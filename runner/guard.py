import json
import os
import re
import statistics
import time
import unicodedata
from collections import deque
from email.utils import parsedate_to_datetime
from urllib.parse import unquote_plus, urlsplit

READS = ("GET", "HEAD", "OPTIONS")
WRITES = ("POST", "PUT", "PATCH", "DELETE")
UPDATES = ("PUT", "PATCH", "DELETE")
MODES = ("lab", "canario", "livre", "mapeamento")
SCAN_LIMIT = 512 * 1024
CANARY = re.compile(r"EGIDE-C[AB]-[0-9A-F]{12}(?![0-9A-F])")
REQUEST_SCAN_LIMIT = 64 * 1024
SEND_WORDS = {
    "send", "enviar", "envio", "sms", "whatsapp", "invite", "invites", "pay", "payment", "payments", "checkout",
    "billing", "charge", "charges", "pix", "message", "messages",
}
SEND_STEMS = ("convit", "invit", "notif", "webhook", "pagament", "cobranc", "transfer", "subscri", "assinatur", "mensag")
MAIL_WORDS = {"email", "emails", "mail", "mails"}
AUTH_WORDS = {"login", "signin", "logon", "entrar", "session", "sessions", "token", "oauth", "auth", "callback"}
LOGIN_WORDS = AUTH_WORDS - {"callback"}
RESET_WORDS = {"reset", "forgot", "recover", "recuperar"}
ACCOUNT_WORDS = AUTH_WORDS | {"password", "senha", "conta", "account"}
HALTED = "Sessão pausada por sinal de dano"
MAPPING = "Modo de mapeamento não altera nem exclui dados"
BLOCKS = {
    "efeito_externo": "Ação com efeito externo bloqueada (e-mail, mensagem, pagamento ou webhook)",
    "escrita_irreversivel": "Escrita irreversível fora dos registros de teste bloqueada",
    "negado": "Método HTTP não permitido",
}


def settings(scope):
    safety = scope.get("safety") or ("lab" if scope.get("lab") else "livre")
    if safety not in MODES or (safety == "lab" and not scope.get("lab")):
        safety = "mapeamento"
    tag = scope.get("session_tag")
    rps = scope.get("max_rps")
    return (
        safety,
        [rule for rule in scope.get("approved_writes") or [] if isinstance(rule, dict)],
        tag if isinstance(tag, str) and re.fullmatch(r"[A-Za-z0-9-]{1,40}", tag) else None,
        float(rps) if type(rps) in (int, float) and 0 < rps <= 1000 else None,
        [marker for marker in scope.get("markers") or [] if isinstance(marker, str) and 6 <= len(marker) <= 80][:10],
    )


def header(headers, name):
    try:
        value = headers.get(name)
    except AttributeError:
        return ""
    return "" if value is None else str(value)


def content_of(message):
    if getattr(message, "stream", None):
        return None
    try:
        return message.content
    except Exception:
        return None


def textual(ctype):
    return not ctype or ctype.startswith("text/") or any(kind in ctype for kind in ("json", "xml", "javascript", "html"))


def find_markers(text, extra=()):
    if not text:
        return []
    found = set(CANARY.findall(text))
    found.update(marker for marker in extra if marker and marker in text)
    return sorted(found)[:20]


def keys_of(data):
    return ",".join(sorted(str(key)[:40] for key in data)[:40])


def shape_of(ctype, text):
    if not text or not text.strip():
        return ""
    if "json" in ctype or (not ctype and text.lstrip()[:1] in ("{", "[")):
        try:
            data = json.loads(text)
        except (ValueError, RecursionError):
            pass
        else:
            if isinstance(data, dict):
                return "json:" + keys_of(data)
            if isinstance(data, list):
                return "json:list:" + (keys_of(data[0]) if data and isinstance(data[0], dict) else "")
            return "json:scalar"
    if "html" in ctype:
        return "html"
    return "text" if textual(ctype) else ""


def sent_markers(request, extra=()):
    body = content_of(request)
    text = unquote_plus(urlsplit(request.path).query)
    if body:
        text += "\n" + body[:REQUEST_SCAN_LIMIT].decode("utf-8", "replace")
    return find_markers(text, extra)


def describe(body, headers, ms, extra=()):
    ctype = header(headers, "content-type").split(";")[0].strip().lower()
    length = header(headers, "content-length").strip()
    details = {"ctype": ctype, "ms": ms,
               "size": len(body) if body is not None else int(length) if length.isdigit() else 0}
    if body and textual(ctype):
        head = body[:SCAN_LIMIT].decode("utf-8", "replace")
        details["markers"] = find_markers(head, extra)
        jsonish = "json" in ctype or (not ctype and head.lstrip()[:1] in ("{", "["))
        details["shape"] = "json" if jsonish and len(body) > SCAN_LIMIT else shape_of(ctype, head)
    return details


def under(path, base):
    root = base.rstrip("/")
    return bool(root) and (path == base or path.startswith(root + "/"))


def approved(rules, method, path):
    return method in WRITES and any(
        rule.get("method") == method and isinstance(rule.get("path"), str) and rule["path"].startswith("/")
        and (path == rule["path"] or (rule.get("prefix") is True and under(path, rule["path"])))
        for rule in rules
    )


def tokens_of(path):
    plain = "".join(char for char in unicodedata.normalize("NFKD", path or "") if not unicodedata.combining(char))
    return set(re.findall(r"[a-z]+|[0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", plain).lower()))


def external(path):
    tokens = tokens_of(path)
    if tokens & SEND_WORDS or any(token.startswith(SEND_STEMS) for token in tokens):
        return True
    if tokens & RESET_WORDS and tokens & ACCOUNT_WORDS:
        return True
    return bool(tokens & MAIL_WORDS) and not tokens & AUTH_WORDS


def classify(method, path, rule=False, canary_paths=()):
    if method in READS:
        return "leitura"
    if method not in WRITES:
        return "negado"
    if rule:
        return "escrita_propria"
    if external(path):
        return "efeito_externo"
    if method == "POST" or any(under(path, base) for base in canary_paths):
        return "escrita_propria"
    return "escrita_irreversivel"


def refusal(mode, action, method, released):
    if mode == "lab":
        return None
    if mode == "mapeamento" and method in UPDATES:
        return MAPPING
    blocked = ("efeito_externo", "negado") if mode == "livre" else ("efeito_externo", "negado", "escrita_irreversivel")
    return BLOCKS[action] if action in blocked and not released else None


class CanaryFile:
    def __init__(self, path):
        self.path = path
        self.key = None
        self.paths = ()

    def __call__(self):
        try:
            info = os.stat(self.path)
        except OSError:
            return ()
        key = (info.st_ino, info.st_mtime_ns, info.st_size)
        if key != self.key:
            try:
                with open(self.path) as source:
                    items = json.load(source)
            except (OSError, ValueError):
                return self.paths
            self.key, self.paths = key, tuple(
                item["path"] for item in (items if isinstance(items, list) else [])
                if isinstance(item, dict) and isinstance(item.get("path"), str) and item["path"].startswith("/")
            )
        return self.paths


class Halt:
    def __init__(self, path):
        self.path = path
        self.state = {}

    def active(self):
        return bool(self.state) or os.path.exists(self.path)

    def trigger(self, reason):
        if self.state:
            return
        self.state.update(reason=reason, at=int(time.time()))
        try:
            with open(self.path + ".tmp", "w") as output:
                json.dump(self.state, output)
            os.replace(self.path + ".tmp", self.path)
        except OSError:
            pass


class Signals:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.window = deque(maxlen=40)
        self.latency = deque(maxlen=15)
        self.logins = 0
        self.strikes = 0
        self.until = 0.0

    def feed(self, status, headers, ms, path, method="GET", probe=False):
        waf = status in (403, 406, 429) and (
            any(header(headers, name) for name in ("cf-mitigated", "x-sucuri-id", "x-amzn-waf-action"))
            or "akamaighost" in header(headers, "server").lower())
        self.window.append((status, waf, probe))
        self.latency.append(ms or 0)
        if status == 429:
            self.strikes += 1
            self.until = self.clock() + min(2 ** self.strikes, 16)
        else:
            self.strikes = 0
        if not probe and method == "POST" and tokens_of(path) & LOGIN_WORDS:
            self.logins = self.logins + 1 if status in (401, 403) else 0
        return self.reason()

    def reason(self):
        browsing = [status for status, _, probe in self.window if not probe]
        if sum(waf for _, waf, _ in self.window) >= 5:
            return "Bloqueio de WAF detectado"
        if sum(status == 429 for status, _, _ in self.window) >= 10:
            return "Limite de taxa do alvo atingido repetidamente"
        if self.logins >= 8:
            return "Falhas de login em série (risco de bloquear a conta de teste)"
        if len(browsing) >= 15 and sum(500 <= status < 600 for status in browsing) / len(browsing) >= 0.35:
            return "Taxa de erros 5xx alta no alvo"
        if len(self.latency) == 15 and statistics.median(self.latency) > 15000:
            return "Latência alta no alvo"
        return None

    def wait(self, now=None):
        return max(0.0, self.until - (self.clock() if now is None else now))


class Brakes:
    def __init__(self, max_rps=None):
        self.max_rps = max_rps
        self.signals = {}
        self.next = 0.0

    def pace(self, host, now=None):
        now = time.monotonic() if now is None else now
        signal = self.signals.get(host)
        start = now + signal.wait(now) if signal else now
        if self.max_rps:
            start = max(start, self.next)
            self.next = start + 1 / self.max_rps
        return start - now

    def feed(self, host, status, headers, ms, path, method="GET", probe=False):
        if host not in self.signals:
            self.signals[host] = Signals()
        return self.signals[host].feed(status, headers, ms, path, method, probe)


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


def inspect(flow, local_port):
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


def destination(location):
    value = re.sub(r"[\t\r\n]", "", location.strip()).replace("\\", "/")
    value = re.sub(r"^(?:https?:)?/{2,}", "https://", value, flags=re.I)
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError:
        return ""
    return "https://" + host.rstrip(".") + "/" if host else parts.path[:280]
