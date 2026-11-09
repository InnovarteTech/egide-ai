import ipaddress
import json
import os
import re
import socket
import time
from email.utils import parsedate_to_datetime
from urllib.parse import unquote, urlsplit

from mitmproxy import http

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
actor_file = os.path.join(os.path.dirname(os.environ["EGIDE_POLICY"]), "actor")
sessions = {}


def current_actor():
    try:
        with open(actor_file) as source:
            value = source.read().strip()
            return value if value in ("a", "b") else None
    except OSError:
        return None


def record(request, status, allowed, reason="", issues=None):
    with open(events, "a") as output:
        output.write(json.dumps({
            "method": request.method, "host": request.pretty_host,
            "path": urlsplit(request.path).path[:280], "status": status,
            "allowed": allowed, "reason": reason, "issues": issues or [],
        }) + "\n")


def expired(parts):
    for part in parts:
        if part.startswith("max-age="):
            return part[8:].strip().lstrip("-").isdigit() and int(part[8:].strip()) <= 0
        if part.startswith("expires="):
            try:
                return parsedate_to_datetime(part[8:].strip()).timestamp() < time.time()
            except (TypeError, ValueError, IndexError):
                return False
    return False


def inspect(flow):
    headers = flow.response.headers
    kind = headers.get("content-type", "").lower()
    html = "text/html" in kind
    found = []
    scheme = flow.metadata.get("scheme", flow.request.scheme)
    if scheme == "https" and not local_port and not headers.get("strict-transport-security"):
        found.append("hsts")
    policy = headers.get("content-security-policy", "").lower()
    if html and not policy:
        found.append("csp")
    if html and not headers.get("x-frame-options") and "frame-ancestors" not in policy:
        found.append("clickjacking")
    if (html or "json" in kind or "javascript" in kind) and headers.get("x-content-type-options", "").lower() != "nosniff":
        found.append("nosniff")
    for name in ("server", "x-powered-by"):
        value = headers.get(name, "")
        if re.search(r"[A-Za-z][\w.-]*/\d", value) or (name == "x-powered-by" and value):
            found.append("version:" + re.sub(r"[^\w ./()-]", "", value)[:80])
    for cookie in headers.get_all("set-cookie"):
        parts = [part.strip().lower() for part in cookie.split(";")]
        name = re.sub(r"[^\w.-]", "", cookie.split("=", 1)[0])[:60]
        if expired(parts):
            continue
        missing = [flag for flag, present in (
            ("secure", scheme != "https" or "secure" in parts),
            ("httponly", "httponly" in parts or name.lower() in ("xsrf-token", "csrftoken", "csrf_token", "_csrf")),
            ("samesite", any(part.startswith("samesite=") for part in parts)),
        ) if not present]
        if name and missing:
            found.append("cookie:" + name + ":" + ",".join(missing))
    return found


def reject(flow, reason):
    record(flow.request, 403, False, reason)
    flow.response = http.Response.make(403, "Fora do escopo autorizado pela Égide AI".encode(), {
        "Content-Type": "text/plain", "X-Egide-Blocked": "1",
    })


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
    if not correct_host(flow.request.host, flow.request.port):
        reject(flow, "Destino fora da autorização")


def request(flow):
    try:
        check(flow)
    except Exception:
        reject(flow, "Formato de requisição vedado")


def check(flow):
    global limit, preflights, writes
    req = flow.request
    flow.metadata["scheme"] = req.scheme
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
    if anon:
        req.headers.pop("authorization", None)
        req.headers.pop("cookie", None)
    elif not preflight and actor and probe and "authorization" not in req.headers:
        stored = sessions.get((actor, req.host.lower()))
        if stored:
            req.headers["authorization"] = stored
    elif not preflight and actor and not probe and req.headers.get("authorization"):
        sessions[(actor, req.host.lower())] = req.headers["authorization"]
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
    if not flow.response.headers.get("X-Egide-Blocked"):
        record(flow.request, flow.response.status_code, True, issues=inspect(flow))
