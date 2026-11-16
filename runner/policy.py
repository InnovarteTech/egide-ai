import asyncio
import ipaddress
import json
import os
import socket
import sys
import time
from urllib.parse import unquote, urlsplit

from mitmproxy import http

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import guard

with open(os.environ["EGIDE_POLICY"]) as source:
    scope = json.load(source)

limit = 0
preflights = 0
writes = 0
write = scope.get("write")
events = os.environ["EGIDE_EVENTS"]
hosts = set(scope.get("hosts") or [scope["host"]])
local_port = scope.get("local_port")
LOCAL_UPSTREAM = "host.docker.internal"
folder = os.path.dirname(os.environ["EGIDE_POLICY"])
actor_file = os.path.join(folder, "actor")
sessions = {}
safety, approved_writes, session_tag, max_rps, test_markers = guard.settings(scope)
canaries = guard.CanaryFile(os.path.join(folder, "canaries.json"))
stop = guard.Halt(os.path.join(folder, "halt.json"))
brakes = guard.Brakes(max_rps)


def current_actor():
    try:
        with open(actor_file) as source:
            value = source.read().strip()
            return value if value in ("a", "b") else None
    except OSError:
        return None


def classify(method, path, host=None):
    rule = write_match(method, host if host is not None else (write or {}).get("host"), path)
    return guard.classify(method, path, rule, canaries() if method in guard.UPDATES else ())


def gate(method, path, host=None):
    action = classify(method, path, host)
    return action, guard.refusal(safety, action, method, guard.approved(approved_writes, method, path))


def actor_of(flow):
    if "egide_actor" in flow.metadata:
        return flow.metadata["egide_actor"]
    return "anon" if guard.header(flow.request.headers, "x-egide-anon") == "1" else current_actor()


def record(flow, status, allowed, reason="", issues=None, location=None, details=None):
    event = {"method": "", "host": "", "path": "", "status": status, "allowed": allowed, "reason": reason, "issues": [],
             "actor": None, "acao": "negado", "markers": [], "sent_markers": [], "ctype": "", "shape": "", "size": 0, "ms": 0}
    try:
        request = flow.request
        path = urlsplit(request.path).path
        action = flow.metadata.get("egide_action") or classify(request.method, unquote(path), request.pretty_host)
        event.update({
            "method": request.method, "host": request.pretty_host, "path": path[:280], "issues": issues or [],
            "actor": actor_of(flow), "acao": action, "sent_markers": guard.sent_markers(request, test_markers),
        })
        event.update(details or {})
        if location:
            event["location"] = location[:300]
    except Exception:
        pass
    try:
        with open(events, "a") as output:
            output.write(json.dumps(event) + "\n")
    except (OSError, TypeError, ValueError):
        pass


def reject(flow, reason):
    flow.metadata["egide_blocked"] = True
    flow.response = http.Response.make(403, "Fora do escopo autorizado pela Égide AI".encode(), {
        "Content-Type": "text/plain", "X-Egide-Blocked": "1",
    })
    record(flow, 403, False, reason)


def correct_host(host, port):
    return host.lower() in hosts and port == scope["port"]


def allowed(method, path):
    return any(
        (method == rule["method"] or rule["method"] == "*") and
        (path == rule["path"] or (
            rule["prefix"] and (
                rule["path"] == "/" or path.startswith(rule["path"] + "/")
            )
        ))
        for rule in scope["rules"]
    )


def write_match(method, host, path):
    if not write or method != write["method"] or (host or "").lower() != (write["host"] or "").lower():
        return False
    return path == write["path"] or (write.get("prefix") and path.startswith(write["path"] + "/"))


def http_connect(flow):
    if stop.active():
        reject(flow, guard.HALTED)
    elif not correct_host(flow.request.host, flow.request.port):
        reject(flow, "Destino fora da autorização")


def request(flow):
    try:
        check(flow)
    except Exception:
        reject(flow, "Formato de requisição vedado")
    flow.metadata["egide_started"] = time.monotonic()
    if flow.response is not None or safety == "lab":
        return None
    delay = brakes.pace((flow.request.pretty_host or "").lower())
    return hold(flow, delay) if delay > 0 else None


async def hold(flow, delay):
    await asyncio.sleep(delay)
    if stop.active():
        reject(flow, guard.HALTED)
    flow.metadata["egide_started"] = time.monotonic()


def check(flow):
    global limit, preflights, writes
    req = flow.request
    flow.metadata["scheme"] = req.scheme
    if stop.active():
        reject(flow, guard.HALTED)
        return
    if req.stream:
        reject(flow, "Requisição grande demais")
        return
    if not correct_host(req.host, req.port) or req.scheme != scope["scheme"]:
        reject(flow, "Destino fora da autorização")
        return

    raw = urlsplit(req.path).path
    decoded = unquote(raw)
    if (
        not req.path.startswith("/") or req.path.startswith("//") or
        "%" in decoded or "\\" in decoded or "//" in decoded or
        any(part in (".", "..") for part in decoded.split("/")) or
        any(ord(char) < 32 for char in decoded) or
        req.headers.get("upgrade") or
        any(key in req.headers for key in (
            "x-http-method-override", "x-method-override", "x-http-method",
            "x-original-url", "x-rewrite-url", "x-forwarded-host",
        )) or "_method" in req.query or "_method" in req.urlencoded_form
    ):
        reject(flow, "Formato de requisição vedado")
        return
    if any(decoded == path or decoded.startswith(path + "/") for path in scope["denied"]):
        reject(flow, "Rota bloqueada no escopo")
        return
    action, refusal = gate(req.method, decoded, req.pretty_host)
    flow.metadata["egide_action"] = action
    if refusal:
        reject(flow, refusal)
        return

    preflight = req.method == "OPTIONS" and bool(req.headers.get("access-control-request-method"))
    if preflight:
        if preflights >= scope["budget"]:
            reject(flow, "Limite de requisições atingido")
            return
        requested = req.headers["access-control-request-method"].strip().upper()
        if not allowed(requested, decoded) and not write_match(requested, req.pretty_host, decoded):
            reject(flow, "Método ou rota sem permissão")
            return
        preflights += 1
    else:
        is_write = write_match(req.method, req.pretty_host, decoded)
        if is_write:
            if writes >= write["max"]:
                reject(flow, "Limite de escritas de teste atingido")
                return
            writes += 1
        else:
            if limit >= scope["budget"]:
                reject(flow, "Limite de requisições atingido")
                return
            if not allowed(req.method, decoded):
                reject(flow, "Método ou rota sem permissão")
                return
            limit += 1
    req.headers['connection'] = 'close'
    actor = current_actor()
    anon = req.headers.pop("x-egide-anon", None) == "1"
    probe = req.headers.pop("x-egide-probe", None) == "1"
    flow.metadata["egide_actor"] = "anon" if anon else actor
    flow.metadata["egide_probe"] = anon or probe
    if anon:
        req.headers.pop("authorization", None)
        req.headers.pop("cookie", None)
    elif not preflight and actor and probe and "authorization" not in req.headers:
        stored = sessions.get((actor, req.host.lower()))
        if stored:
            req.headers["authorization"] = stored
    elif not preflight and actor and not probe and req.headers.get("authorization"):
        sessions[(actor, req.host.lower())] = req.headers["authorization"]
    if session_tag:
        req.headers["X-Egide-Session"] = session_tag
    if local_port:
        original = req.host
        req.scheme = "http"
        req.host = LOCAL_UPSTREAM
        req.port = local_port
        req.headers["host"] = original
        req.headers["x-forwarded-proto"] = "https"


def server_connect(data):
    address = data.server.address
    if local_port:
        if not address or address != (LOCAL_UPSTREAM, local_port):
            data.server.error = "Servidor fora do escopo"
            return
        try:
            data.server.address = (socket.getaddrinfo(LOCAL_UPSTREAM, local_port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0], local_port)
        except OSError:
            data.server.error = "App local indisponível"
        return
    if not address or not correct_host(*address):
        data.server.error = "Servidor fora do escopo"
        return
    if scope["lab"]:
        return

    try:
        addresses = {
            entry[4][0] for entry in socket.getaddrinfo(
                address[0], address[1], socket.AF_INET, socket.SOCK_STREAM,
            )
        }
        if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
            raise ValueError("Destino não público")
        data.server.address = (sorted(addresses)[0], address[1])
    except (OSError, ValueError):
        data.server.error = "Resolução pública inválida"


def response(flow):
    if flow.metadata.get("egide_blocked"):
        return
    status = flow.response.status_code
    headers = flow.response.headers
    location = guard.destination(headers.get("location", "")) if 300 <= status < 400 else None
    started = flow.metadata.get("egide_started")
    ms = int((time.monotonic() - started) * 1000) if started else 0
    details = guard.describe(guard.content_of(flow.response), headers, ms, test_markers)
    record(flow, status, True, issues=guard.inspect(flow, local_port), location=location, details=details)
    if safety != "lab" and not stop.active():
        path = unquote(urlsplit(flow.request.path).path)
        reason = brakes.feed((flow.request.pretty_host or "").lower(), status, headers, ms, path,
                             flow.request.method, bool(flow.metadata.get("egide_probe")))
        if reason:
            stop.trigger(reason)
