import json
import math
import os
import re
import time

SAFETY_MODES = ("lab", "canario", "livre", "mapeamento")
ROUTE = re.compile(r"/(?:[a-zA-Z0-9._@-]+/)*[a-zA-Z0-9._@-]*")
CANARY = re.compile(r"EGIDE-C([AB])-[0-9A-F]{12}")
TEST_MARKER = re.compile(r"(?:EGIDE|ESCOPO)-[A-F0-9]{12,16}")


def valid_route(path):
    return (isinstance(path, str) and len(path) <= 450 and bool(ROUTE.fullmatch(path))
            and not any(part in (".", "..") for part in path.split("/")))


def approved_writes(value):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 50:
        raise ValueError("Escritas aprovadas inválidas")
    rules = []
    for rule in value:
        if (not isinstance(rule, dict) or rule.get("method") not in ("POST", "PUT", "PATCH", "DELETE")
                or not valid_route(rule.get("path")) or rule.get("prefix", False) not in (True, False)
                or (rule.get("prefix") and not rule["path"].rstrip("/"))):
            raise ValueError("Escritas aprovadas inválidas")
        rules.append({"method": rule["method"], "path": rule["path"], "prefix": bool(rule.get("prefix"))})
    return rules


def safety_options(data, is_lab):
    safety = data.get("safety")
    if safety is None:
        safety = "lab" if is_lab else "livre"
    if safety not in SAFETY_MODES or (safety == "lab" and not is_lab):
        raise ValueError("Modo de segurança inválido")
    tag = data.get("session_tag")
    if tag is not None and (not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,40}", tag)):
        raise ValueError("Identificador da sessão inválido")
    rps = data.get("max_rps")
    if rps is not None and (type(rps) not in (int, float) or not math.isfinite(rps) or not 0 < rps <= 999.99):
        raise ValueError("Limite de requisições por segundo inválido")
    accounts = data.get("accounts")
    markers = sorted({
        account["marker"] for account in (accounts.values() if isinstance(accounts, dict) else [])
        if isinstance(account, dict) and isinstance(account.get("marker"), str) and TEST_MARKER.fullmatch(account["marker"])
    })
    return {"safety": safety, "approved_writes": approved_writes(data.get("approved_writes")), "session_tag": tag,
            "max_rps": None if rps is None else float(rps), "markers": markers}


def redact(event):
    for key in ("path", "location"):
        if isinstance(event.get(key), str):
            event[key] = re.sub(r"/confirmar/[a-f0-9]{32}", "/confirmar/[token]", event[key])
    return event


def read_halt(folder):
    file = folder / "halt.json"
    if not file.exists():
        return None
    try:
        data = json.loads(file.read_text())
        return {"reason": str(data["reason"])[:200], "at": int(data["at"])}
    except (OSError, ValueError, KeyError, TypeError):
        return {"reason": "Sessão pausada por sinal de dano", "at": int(time.time())}


def canary(folder, data):
    actor = data.get("actor")
    if actor not in ("a", "b"):
        raise ValueError("Identidade inválida")
    path = data.get("path")
    if not valid_route(path) or not path.rstrip("/"):
        raise ValueError("Rota do canário inválida")
    marker = data.get("marker")
    match = CANARY.fullmatch(marker) if isinstance(marker, str) else None
    if not match or match.group(1) != actor.upper():
        raise ValueError("Marcador de canário inválido")
    method = data.get("method", "POST")
    if method not in ("POST", "PUT", "PATCH"):
        raise ValueError("Método do canário inválido")
    object_id = data.get("object_id")
    if type(object_id) is int:
        object_id = str(object_id)
    if object_id is not None and (not isinstance(object_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,80}", object_id)):
        raise ValueError("Identificador do canário inválido")
    file = folder / "canaries.json"
    items = json.loads(file.read_text()) if file.exists() else []
    if not isinstance(items, list):
        raise ValueError("Registro de canários corrompido")
    entry = {"actor": actor, "path": path, "marker": marker, "method": method, "object_id": object_id}
    if entry not in items:
        if len(items) >= 200:
            raise ValueError("Limite de 200 canários atingido")
        items.append(entry)
        temporary = file.with_name("canaries.json.tmp")
        temporary.write_text(json.dumps(items))
        os.replace(temporary, file)
    return {"ok": True, "count": len(items)}


def traffic(session, data):
    since = data.get("since", 0)
    if type(since) is not int or since < 0:
        raise ValueError("Índice de tráfego inválido")
    offsets = session.setdefault("traffic", [0])
    if not session["events"].exists():
        return {"events": [], "next": 0}
    found = []
    with session["events"].open("rb") as source:
        source.seek(offsets[-1])
        for line in source:
            if not line.endswith(b"\n"):
                break
            offsets.append(offsets[-1] + len(line))
        first = min(since, len(offsets) - 1)
        count = min(2000, len(offsets) - 1 - first)
        source.seek(offsets[first])
        for _ in range(count):
            try:
                event = json.loads(source.readline())
            except ValueError:
                continue
            if isinstance(event, dict):
                found.append(redact(event))
    return {"events": found, "next": first + count}
