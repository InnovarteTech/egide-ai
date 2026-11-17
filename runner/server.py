import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import lab
from session_extras import canary, read_halt, redact, safety_options, traffic

RUNNER_TOKEN = os.environ["EGIDE_RUNNER_TOKEN"]
if len(RUNNER_TOKEN) < 32:
    raise RuntimeError("EGIDE_RUNNER_TOKEN precisa de pelo menos 32 caracteres")

WORK = Path(tempfile.mkdtemp(prefix="egide-"))
WORK.chmod(0o755)
CA = WORK / "ca"
ADDON_ID = "observador@egide.test"
DISPLAY = {**os.environ, "DISPLAY": ":99"}
FIREFOX_ENV = {**DISPLAY, "MOZ_ENABLE_WAYLAND": "0", "HOME": "/home/browser"}
LOCK = threading.Lock()
BRIDGE_LOCK = threading.Lock()
SESSION = None
BRIDGE = {"secret": "", "snapshot": {}, "pending": None, "result": None}
LAB_HOST = "lab.egide.test"
LOCAL_SUFFIX = ".local.egide.test"
LOCAL_ENABLED = os.environ.get("EGIDE_RUNNER_LOCAL") == "1"
RESERVED_PORTS = {22, 25, 53, 3306, 5432, 6379, 6387, 8791, 8792, 8899, 9200, 11211, 27017}


def run(*cmd, **kwargs):
    return subprocess.run(cmd, check=True, env=DISPLAY, **kwargs)


def desktop(*cmd):
    run("xdotool", *map(str, cmd), timeout=8, stdout=subprocess.DEVNULL)


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def close():
    global SESSION
    if not SESSION:
        return
    stop(SESSION.get("firefox"))
    stop(SESSION.get("proxy"))
    shutil.rmtree(SESSION["dir"], ignore_errors=True)
    with BRIDGE_LOCK:
        BRIDGE.update(secret="", snapshot={}, pending=None, result=None)
    SESSION = None


def base_url(actor=None):
    return SESSION["bases"].get(actor or SESSION["actor"], SESSION["url"])


def actor_origin(actor=None):
    url = urllib.parse.urlsplit(base_url(actor))
    return f"{url.scheme}://{url.netloc}"


def firefox(actor):
    (SESSION["dir"] / "actor").write_text("-")
    stop(SESSION.get("firefox"))
    time.sleep(.4)
    (SESSION["dir"] / "actor").write_text(actor)
    profile = SESSION["dir"] / actor
    secret = SESSION.setdefault("secrets", {}).setdefault(actor, secrets.token_urlsafe(32))
    with BRIDGE_LOCK:
        BRIDGE.update(secret=secret, snapshot={}, pending=None, result=None)
    if not profile.exists():
        (profile / "extensions").mkdir(parents=True)
        settings = {
            "xpinstall.signatures.required": False,
            "extensions.autoDisableScopes": 0,
            "browser.shell.checkDefaultBrowser": False,
            "browser.aboutwelcome.enabled": False,
            "browser.startup.homepage_override.mstone": "ignore",
            "browser.startup.couldRestoreSession.count": -1,
            "browser.sessionstore.resume_from_crash": False,
            "browser.cache.disk.enable": False,
            "signon.rememberSignons": False,
            "network.proxy.type": 1,
            "network.proxy.http": "127.0.0.1",
            "network.proxy.http_port": 8899,
            "network.proxy.ssl": "127.0.0.1",
            "network.proxy.ssl_port": 8899,
            "network.proxy.no_proxies_on": "127.0.0.2",
            "network.proxy.allow_hijacking_localhost": True,
            "network.trr.mode": 5,
            "network.http.http3.enable": False,
            "media.peerconnection.enabled": False,
            "datareporting.healthreport.uploadEnabled": False,
            "toolkit.telemetry.enabled": False,
            "browser.safebrowsing.downloads.remote.enabled": False,
        }
        (profile / "user.js").write_text("\n".join(
            f"user_pref({json.dumps(key)}, {json.dumps(value)});" for key, value in settings.items()
        ))
        run("certutil", "-N", "-d", f"sql:{profile}", "--empty-password", timeout=8)
        run("certutil", "-A", "-d", f"sql:{profile}", "-n", "Egide AI test CA",
            "-t", "C,,", "-i", str(CA / "mitmproxy-ca-cert.pem"), timeout=8)

    manifest = {
        "manifest_version": 2, "name": "Égide AI · Observador", "version": "1.0",
        "browser_specific_settings": {"gecko": {"id": ADDON_ID}},
        "permissions": ["tabs", "<all_urls>"],
        "background": {"scripts": ["addon.js"]},
    }
    with zipfile.ZipFile(profile / "extensions" / (ADDON_ID + ".xpi"), "w") as addon:
        addon.writestr("manifest.json", json.dumps(manifest))
        addon.writestr("addon.js", Path("/runner/addon.js").read_text().replace("__TOKEN__", secret))
    run("chown", "-R", "browser:browser", str(profile), timeout=8)
    SESSION["actor"] = actor
    SESSION["firefox"] = subprocess.Popen(
        ["runuser", "-u", "browser", "--", "firefox-esr", "--no-remote",
         "--profile", str(profile), "--kiosk", SESSION["urls"].get(actor, SESSION["url"])],
        env=FIREFOX_ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    wait_for_page(45)


def wait_for_page(seconds=4):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with BRIDGE_LOCK:
            if BRIDGE["snapshot"].get("viewport"):
                return
        time.sleep(.18)
    raise ValueError("Firefox não disponibilizou a observação da página")


def start(data):
    global SESSION
    if SESSION:
        if time.monotonic() - SESSION["last"] < 180:
            raise ValueError("O executor está ocupado com outra sessão")
        close()
    url = urllib.parse.urlsplit(data["url"])
    is_lab = data["lab"] is True
    if (is_lab and (url.hostname != LAB_HOST or url.port != 8788 or url.scheme != "http")) or (
        not is_lab and (url.scheme != "https" or url.port not in (443, None) or
                        not re.fullmatch(r"[a-z0-9.-]+", url.hostname or ""))):
        raise ValueError("Origem inválida")
    bases = {}
    for actor, value in (data.get("urls") or {}).items():
        account = urllib.parse.urlsplit(value)
        if (is_lab or actor not in ("a", "b") or account.scheme != "https" or account.port not in (443, None)
                or not re.fullmatch(r"[a-z0-9.-]+", account.hostname or "")):
            raise ValueError("Origem de conta inválida")
        bases[actor] = value
    api = None
    if data.get("api") is not None:
        api = urllib.parse.urlsplit(data["api"])
        if (is_lab or data.get("local_port") is not None or api.scheme != "https" or api.port not in (443, None)
                or api.path not in ("", "/") or api.query or api.fragment
                or not re.fullmatch(r"[a-z0-9.-]+", api.hostname or "") or api.hostname.endswith(LOCAL_SUFFIX)):
            raise ValueError("Domínio da API inválido")
    hosts = sorted({url.hostname, *(urllib.parse.urlsplit(value).hostname for value in bases.values()), *([api.hostname] if api else [])})
    local_port = data.get("local_port")
    if local_port is not None:
        if (not LOCAL_ENABLED or is_lab or type(local_port) is not int or not 0 < local_port < 65536
                or local_port in RESERVED_PORTS
                or not all(host.endswith(LOCAL_SUFFIX) for host in hosts)):
            raise ValueError("Modo local indisponível para esta origem")
    elif any(host.endswith(LOCAL_SUFFIX) for host in hosts):
        raise ValueError("Origem local exige a porta do app")
    options = safety_options(data, is_lab)
    folder = Path(tempfile.mkdtemp(dir=WORK))
    folder.chmod(0o755)
    event_path = folder / "events.ndjson"
    policy_path = folder / "scope.json"
    write = data.get("write")
    if write is not None:
        if (not isinstance(write, dict) or write.get("method") not in ("PATCH", "PUT")
                or (write.get("host") or "").lower() not in hosts
                or not isinstance(write.get("path"), str) or not write["path"].startswith("/")
                or "//" in write["path"] or ".." in write["path"]
                or not isinstance(write.get("max"), int) or not 0 < write["max"] <= 8):
            raise ValueError("Rota de escrita inválida")
        port = url.port or (80 if url.scheme == "http" else 443)
        suffix = "" if port in (80, 443) else f":{port}"
        write = {"method": write["method"], "host": write["host"].lower(), "path": write["path"],
                 "prefix": bool(write.get("prefix")), "max": int(write["max"]),
                 "base": f"{url.scheme}://{write['host'].lower()}{suffix}"}
    policy_path.write_text(json.dumps({
        "host": url.hostname, "hosts": hosts, "scheme": url.scheme, "port": url.port or 443, "lab": is_lab,
        "rules": data["rules"], "denied": data["denied"], "budget": int(data["budget"]),
        "local_port": local_port, "write": write, **options,
    }))
    SESSION = {
        "id": data["id"], "dir": folder, "url": data["url"], "urls": dict(bases), "bases": bases, "actor": "a",
        "api": api.hostname if api else None, "write": write,
        "origin": f"{url.scheme}://{url.netloc}",
        "offset": 0, "lab": is_lab, "last": time.monotonic(), "events": event_path,
    }
    if is_lab:
        lab.reset()
    try:
        SESSION["proxy"] = subprocess.Popen(
            ["mitmdump", "-q", "--listen-host", "127.0.0.1", "--listen-port", "8899",
             "--set", f"confdir={CA}", "--set", "connection_strategy=lazy",
             "--set", "http2=false",
             "--set", "upstream_cert=false", "--set", "body_size_limit=30m", "--set", "stream_large_bodies=2m", "-s", "/runner/policy.py"],
            env={**os.environ, "EGIDE_POLICY": str(policy_path), "EGIDE_EVENTS": str(event_path)},
            stdout=subprocess.DEVNULL,
        )
        for _ in range(80):
            if (CA / "mitmproxy-ca-cert.pem").exists():
                break
            time.sleep(.15)
        time.sleep(.35)
        firefox("a")
    except Exception:
        close()
        raise
    return {"ready": True}


def settled_snapshot(seconds=6):
    deadline = time.monotonic() + seconds
    previous, stable_since = None, time.monotonic()
    while True:
        with BRIDGE_LOCK:
            snapshot = dict(BRIDGE["snapshot"])
        signature = (snapshot.get("path"), tuple((c.get("type"), c.get("label")) for c in snapshot.get("controls", [])))
        now = time.monotonic()
        if signature != previous:
            previous, stable_since = signature, now
        elif snapshot.get("controls") and now - stable_since >= .9:
            return snapshot
        if now >= deadline:
            return snapshot
        time.sleep(.18)


def observation(with_frame=True):
    snapshot = settled_snapshot()
    path = snapshot.get("path", "/")
    if not path.startswith("/") or path.startswith("//"):
        path = "/"
    SESSION["urls"][SESSION["actor"]] = urllib.parse.urljoin(base_url(), path)
    lines = []
    if SESSION["events"].exists():
        with SESSION["events"].open() as source:
            source.seek(SESSION["offset"])
            for line in source:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if isinstance(event, dict):
                    lines.append(redact(event))
            SESSION["offset"] = source.tell()
    frame = None
    if with_frame:
        windows = run("xdotool", "search", "--onlyvisible", "--class", "firefox",
                      capture_output=True, timeout=4).stdout.decode().splitlines()
        image = run("import", "-window", windows[-1], "-resize", "960x600", "-quality", "78",
                    "jpeg:-", capture_output=True, timeout=6).stdout
        frame = base64.b64encode(image).decode()
    return {"page": snapshot, "network": lines[-80:], "frame": frame, "actor": SESSION["actor"], "halt": read_halt(SESSION["dir"])}


def act(data):
    kind = data["kind"]
    if kind == "switch":
        actor = data["actor"]
        if actor not in ("a", "b"):
            raise ValueError("Identidade inválida")
        if actor != SESSION["actor"]:
            observation(False)
            firefox(actor)
        return {"ok": True}
    if kind == "goto":
        path = data["path"]
        if not path.startswith("/") or path.startswith("//") or any(ord(c) < 32 for c in path):
            raise ValueError("Rota inválida")
        bridge_call({"kind": "goto", "url": urllib.parse.urljoin(base_url(), path)})
    elif kind in ("click", "fill"):
        with BRIDGE_LOCK:
            page = BRIDGE["snapshot"]
            control = next((item for item in page.get("controls", []) if item["id"] == data["control"]), None)
        if page.get("origin") != actor_origin() or not control or not (0 <= control["x"] < 1280 and 0 <= control["y"] < 800):
            raise ValueError("Controle não está visível na tela")
        if kind == "click":
            desktop("key", "Escape")
        desktop("mousemove", "--sync", control["x"], control["y"], "click", "1")
        if kind == "fill":
            value = data["value"]
            if control["type"] not in ("email", "password", "text", "tel", "search", "textarea") or len(value) > 300:
                raise ValueError("Campo incompatível")
            desktop("key", "ctrl+a")
            desktop("type", "--clearmodifiers", "--", value)
    else:
        raise ValueError("Ação inválida")
    time.sleep(.72)
    return {"ok": True}


def write_target(path):
    rule = SESSION.get("write")
    if not rule:
        raise ValueError("Escrita de teste não habilitada")
    if path.startswith("https://") or path.startswith("http://"):
        path = urllib.parse.urlsplit(path).path
    if (not path.startswith("/") or "//" in path or len(path) > 450
            or not re.fullmatch(r"/(?:[a-zA-Z0-9._@-]+/)*[a-zA-Z0-9._@-]*", path)
            or any(part in (".", "..") for part in path.split("/"))):
        raise ValueError("Rota fora da escrita autorizada")
    if not (path == rule["path"] or (rule.get("prefix") and path.startswith(rule["path"] + "/"))):
        raise ValueError("Rota fora da escrita autorizada")
    return rule["base"] + path


def resolve_target(path):
    url = None
    if path.startswith("https://"):
        target = urllib.parse.urlsplit(path)
        if (not SESSION.get("api") or target.hostname != SESSION["api"] or target.port not in (443, None)
                or target.query or target.fragment or target.username or target.password):
            raise ValueError("Rota fora do domínio da API")
        path = target.path
        url = f"https://{SESSION['api']}{path}"
    if (not re.fullmatch(r"/(?:[a-zA-Z0-9._@-]+/)*[a-zA-Z0-9._@-]*", path)
            or any(part in (".", "..") for part in path.split("/")) or len(path) > 450):
        raise ValueError("Rota inválida")
    return url, path


def build_query(query):
    if not isinstance(query, dict) or not query:
        return ""
    pairs = []
    for key, value in list(query.items())[:12]:
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.\-]{1,40}", key):
            raise ValueError("Parâmetro de consulta inválido")
        pairs.append((key, str(value)[:300]))
    return "?" + urllib.parse.urlencode(pairs)


def fields(data):
    url, path = resolve_target(data["path"])
    return bridge_call({"kind": "fields", "url": url or (actor_origin() + path), "origin": actor_origin()})


def write(data):
    if not SESSION.get("write"):
        raise ValueError("Escrita de teste não habilitada")
    field = data.get("field")
    if not isinstance(field, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,60}", field):
        raise ValueError("Campo de escrita inválido")
    value = data.get("value")
    if not isinstance(value, str) or len(value) > 200:
        raise ValueError("Valor de escrita inválido")
    return bridge_call({"kind": "write", "url": write_target(data["path"]),
                        "method": SESSION["write"]["method"], "field": field, "value": value,
                        "origin": actor_origin()})


def probe(data):
    url, path = resolve_target(data["path"])
    query = data.get("query")
    inject = data.get("inject")
    method = "GET"
    body = None
    raw = data.get("raw_body")
    raw_str = data.get("raw")
    content_type = data.get("content_type")
    verb = data.get("method")
    if isinstance(raw_str, str):
        method = verb if verb in ("POST", "PUT", "PATCH") else "POST"
    elif isinstance(raw, dict):
        body = raw
        method = verb if verb in ("POST", "PUT", "PATCH") else "POST"
    elif verb in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
        method = verb
    if isinstance(inject, dict):
        point = inject.get("point")
        value = str(inject.get("value", ""))[:300]
        key = inject.get("key")
        if point == "path":
            segments = path.rstrip("/").split("/")
            if len(segments) > 1:
                segments[-1] = urllib.parse.quote(value, safe="")
                path = "/".join(segments)
                if url:
                    url = f"https://{SESSION['api']}{path}"
        elif point == "query":
            name = key if isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_.\-]{1,40}", key) else "q"
            query = {**(query or {}), name: value}
        elif point == "body":
            if not (isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_.\-]{1,40}", key)):
                raise ValueError("Campo de corpo inválido")
            method = "POST"
            body = {key: value}
    if url is None and data.get("direct"):
        url = actor_origin().rstrip("/") + path
    qs = build_query(query)
    command = {"kind": "probe", "path": path + qs, "origin": actor_origin(), "markers": data.get("markers", []), "anon": bool(data.get("anon"))}
    if url:
        command["url"] = url + qs
    if method != "GET":
        command["method"] = method
    if isinstance(raw_str, str):
        command["raw"] = raw_str[:4000]
        if isinstance(content_type, str):
            command["contentType"] = content_type[:80]
    elif body is not None:
        command["body"] = body
    result = bridge_call(command)
    return {**result, "halt": read_halt(SESSION["dir"])} if isinstance(result, dict) else result


def race(data):
    url, path = resolve_target(data["path"])
    body = data.get("body")
    command = {"kind": "race", "path": path, "origin": actor_origin(),
               "method": data.get("method", "POST"), "count": int(data.get("count", 5)),
               "body": body if isinstance(body, dict) else {}}
    if url:
        command["url"] = url
    return bridge_call(command)


def dom_probe(data):
    url, path = resolve_target(data["path"])
    base = url or (actor_origin() + path)
    value = str(data.get("value", ""))[:400]
    token = data.get("token", "")
    if not re.fullmatch(r"[A-Za-z0-9]{6,40}", str(token)):
        raise ValueError("Token de DOM inválido")
    if data.get("point") == "query":
        key = data.get("key")
        name = key if isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_.\-]{1,40}", key) else "q"
        full = base + "?" + urllib.parse.urlencode({name: value})
    else:
        full = base + "#" + urllib.parse.quote(value, safe="")
    return bridge_call({"kind": "dom_probe", "url": full, "token": token})


def bridge_call(command):
    command["id"] = secrets.token_hex(8)
    with BRIDGE_LOCK:
        BRIDGE.update(pending=command, result=None)
    try:
        for _ in range(180):
            time.sleep(.18)
            with BRIDGE_LOCK:
                if BRIDGE["result"] is not None:
                    return BRIDGE["result"]
        raise ValueError("A chamada de verificação não respondeu")
    finally:
        with BRIDGE_LOCK:
            BRIDGE.update(pending=None, result=None)


def mailbox(email):
    if not SESSION["lab"] or not re.fullmatch(r"[ab]-[0-9a-f-]{8,40}@egide\.test", email):
        raise ValueError("Caixa postal fora do laboratório")
    params = urllib.parse.urlencode({"query": "to:" + email})
    deadline = time.monotonic() + 55
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen("http://mailpit:8025/api/v1/search?" + params, timeout=4) as response:
                messages = json.load(response).get("messages", [])
            if messages:
                with urllib.request.urlopen(
                    "http://mailpit:8025/api/v1/message/" + urllib.parse.quote(messages[0]["ID"], safe=""),
                    timeout=4,
                ) as response:
                    content = json.load(response).get("Text", "")
                match = re.search(r"/(?:vulneravel|corrigido)/confirmar/[a-f0-9]{32}", content)
                if match:
                    return {"path": match.group()}
        except (OSError, ValueError):
            pass
        time.sleep(.4)
    raise ValueError("A confirmação por e-mail não chegou")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send_json(self, status, data):
        encoded = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def payload(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length < 120_000:
            raise ValueError("Corpo inválido")
        return json.loads(self.rfile.read(length))

    def do_GET(self):
        self.send_json(200 if self.path == "/health" else 404, {"ready": True})

    def do_POST(self):
        try:
            if self.server.server_port == 8792:
                with BRIDGE_LOCK:
                    secret = BRIDGE["secret"]
                    if self.path != "/bridge" or not secret or not secrets.compare_digest(
                        self.headers.get("Authorization", ""), "Bearer " + secret
                    ):
                        self.send_json(403, {"error": "Acesso negado"})
                        return
                    data = self.payload()
                    if data.get("id") and data.get("id") == (BRIDGE["pending"] or {}).get("id"):
                        BRIDGE["result"] = data["data"].get("result", {"status": 0, "marker": None})
                        BRIDGE["pending"] = None
                    elif data.get("data", {}).get("viewport"):
                        BRIDGE["snapshot"] = data["data"]
                    self.send_json(200, BRIDGE["pending"])
                return
            if not secrets.compare_digest(self.headers.get("Authorization", ""), "Bearer " + RUNNER_TOKEN):
                self.send_json(403, {"error": "Acesso negado"})
                return
            data = self.payload()
            with LOCK:
                if self.path == "/start":
                    result = start(data)
                elif not SESSION or data.get("id") != SESSION["id"]:
                    raise ValueError("Sessão do executor indisponível")
                else:
                    SESSION["last"] = time.monotonic()
                    if self.path == "/observe":
                        result = observation(data.get("frame", True))
                    elif self.path == "/action":
                        result = act(data)
                    elif self.path == "/probe":
                        result = probe(data)
                    elif self.path == "/dom_probe":
                        result = dom_probe(data)
                    elif self.path == "/race":
                        result = race(data)
                    elif self.path == "/fields":
                        result = fields(data)
                    elif self.path == "/write":
                        result = write(data)
                    elif self.path == "/mail":
                        result = mailbox(data["email"])
                    elif self.path == "/canary":
                        result = canary(SESSION["dir"], data)
                    elif self.path == "/traffic":
                        result = traffic(SESSION, data)
                    elif self.path == "/stop":
                        close()
                        result = {"ok": True}
                    else:
                        self.send_json(404, {"error": "Operação indisponível"})
                        return
                self.send_json(200, result)
        except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
            message = str(error) if type(error) is ValueError else "Não foi possível executar a operação"
            self.send_json(422, {"error": message})


def launch(host, port, handler):
    server = ThreadingHTTPServer((host, port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


if __name__ == "__main__":
    run("iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", "12001",
        "-d", "127.0.0.1", "-p", "tcp", "--dport", "8899", "-j", "ACCEPT")
    run("iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", "12001",
        "-d", "127.0.0.2", "-p", "tcp", "--dport", "8792", "-j", "ACCEPT")
    run("iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", "12001", "-j", "REJECT")
    run("ip6tables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", "12001", "-j", "REJECT")
    if "lab.egide.test" not in Path("/etc/hosts").read_text():
        Path("/etc/hosts").open("a").write("\n127.0.0.1 lab.egide.test\n")
    Path("/tmp/.X99-lock").unlink(missing_ok=True)
    Path("/tmp/.X11-unix/X99").unlink(missing_ok=True)
    xvfb = subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1280x800x24", "-nolisten", "tcp", "-ac"], env=DISPLAY)
    time.sleep(.5)
    launch("127.0.0.1", 8788, lab.Lab)
    launch("127.0.0.2", 8792, Handler)
    try:
        ThreadingHTTPServer(("0.0.0.0", 8791), Handler).serve_forever()
    finally:
        close()
        stop(xvfb)
