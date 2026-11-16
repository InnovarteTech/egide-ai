import html
import ipaddress
import json
import posixpath
import re
import socket
import sqlite3
import threading
import time
import urllib.request
from urllib.parse import parse_qs, quote, urlsplit

PRINTABLE = "".join(chr(code) for code in range(0x21, 0x7F))
DOCUMENTS_DIR = "/srv/prisma/documentos"
DOCUMENTS = {"manual.pdf": "Manual do portal (documento fictício do laboratório)",
             "contrato.pdf": "Contrato de serviço (documento fictício do laboratório)"}
SYSTEM_FILES = {"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nprisma:x:1000:1000:Prisma Faturas:/srv/prisma:/bin/bash\n",
                "/windows/win.ini": "; for 16-bit app support\n[fonts]\n[extensions]\n"}
CUSTOMERS = [{"id": 1, "nome": "Clínica Aurora", "status": "ativos"}, {"id": 2, "nome": "Salão Ébano", "status": "inativos"}]
SCHEMA = {"queryType": {"name": "Query"}, "types": [{"name": "Query"}, {"name": "Fatura"}, {"name": "Empresa"}, {"name": "Usuario"}]}
BUNDLE = """(() => {{
  const alvo = document.getElementById('aviso');
  const recado = decodeURIComponent(location.hash.slice(1));
  if (alvo && recado) alvo.{sink} = recado;
}})();
"""


TEMPLATE_EXPRESSION = re.compile(r"(?:\{\{|\$\{|<%=)\s*(\d{1,6})\s*\*\s*(\d{1,6})\s*(?:\}\}|\}|%>)")

STACK_TRACE = (
    "TypeError: App\\Http\\Controllers\\RelatorioController::mes(): Argument #1 ($mes) must be of type int, "
    "string given, called in /var/www/html/vendor/laravel/framework/src/Illuminate/Routing/ControllerDispatcher.php on line 46\n"
    "Stack trace:\n"
    "#0 /var/www/html/vendor/laravel/framework/src/Illuminate/Routing/ControllerDispatcher.php(46): App\\Http\\Controllers\\RelatorioController->mes()\n"
    "#1 /var/www/html/vendor/laravel/framework/src/Illuminate/Routing/Route.php(260): Illuminate\\Routing\\ControllerDispatcher->dispatch()\n"
    "#2 /var/www/html/vendor/laravel/framework/src/Illuminate/Routing/Router.php(799): Illuminate\\Routing\\Route->run()\n"
    "#3 {main}"
)

POLLUTED = {}
REDEEMED = set()
_STATE_LOCK = threading.Lock()
NOTES = {"vulneravel": {}, "corrigido": {}}
SEQUENCE = {"vulneravel": 0, "corrigido": 0}
NOTICES = [{"id": 1, "titulo": "Manutenção programada", "mensagem": "O portal ficará indisponível no domingo, das 2h às 4h."}, {"id": 2, "titulo": "Novo modelo de exportação", "mensagem": "As faturas seguem o modelo padrão."}]
NOTES_PAGE = """<small>EMPRESA {actor}</small><h1>Anotações</h1><ul>{items}</ul><h2>Nova anotação</h2>
<form method="post" action="/{variant}/notas" aria-label="Nova anotação"><label>Texto da anotação<input name="texto" type="text" required maxlength="300" autocomplete="off"></label>
<button type="submit">Criar anotação</button></form><h2>Avisos do sistema</h2><ul id="avisos" aria-live="polite"></ul><nav><a href="/{variant}/painel">Voltar ao painel</a></nav>
<script>fetch("/servicos/{variant}/avisos").then(r => r.json()).then(d => (d.avisos || []).forEach(a => {{ const item = document.createElement("li"); item.textContent = a.titulo + ": " + a.mensagem; document.getElementById("avisos").append(item); }}));</script>"""
NOTE_PAGE = """<small>EMPRESA {actor}</small><h1>Anotação #{ident}</h1><pre id="nota" aria-live="polite">{texto}</pre><nav><a href="/{variant}/notas">Voltar às anotações</a><a href="/{variant}/painel">Voltar ao painel</a></nav>
<script>fetch("/servicos/{variant}/notas/{ident}").then(r => r.json()).then(n => {{ if (typeof n.texto === "string") document.getElementById("nota").textContent = n.texto; }});</script>"""


def reset_state():
    POLLUTED.clear()
    with _STATE_LOCK:
        REDEEMED.clear()
        NOTES.update({variant: {} for variant in NOTES})
        SEQUENCE.update(dict.fromkeys(SEQUENCE, 0))


def notes(lab, verb, path, page=None):
    screen = re.fullmatch(r"/(vulneravel|corrigido)/notas(?:/(\d{1,9}))?/?", path)
    if screen and (verb == "GET" or (verb == "POST" and not screen.group(2))):
        return note_screen(lab, verb, screen.group(1), screen.group(2), page)
    api = re.fullmatch(r"/servicos/(vulneravel|corrigido)/(?:notas(?:/(\d{1,9}))?|(avisos))", path)
    if not api or verb not in ("GET", "PUT", "PATCH", "DELETE") or (verb != "GET" and not api.group(2)):
        return False
    variant, ident, notices = api.groups()
    try:
        data = json.loads(lab.rfile.read(min(int(lab.headers.get("Content-Length") or 0), 4096)) if verb in ("PUT", "PATCH") else b"{}")
    except ValueError:
        data = None
    with _STATE_LOCK:
        payload, status = note_api(verb, NOTES[variant], None if ident is None else int(ident), variant == "corrigido", lab.actor(), notices, data)
    lab.reply(json.dumps(payload), status, "application/json")
    return True


def note_api(verb, store, ident, owned_only, actor, notices, data):
    note = store.get(ident) if ident is not None else None
    if not actor:
        return {"erro": "Autenticação necessária"}, 401
    if notices:
        return {"avisos": NOTICES}, 200
    if ident is None:
        return {"notas": [{"id": key, "texto": item["texto"]} for key, item in sorted(store.items()) if item["dono"] == actor]}, 200
    if not note or (owned_only and note["dono"] != actor):
        return {"erro": "Anotação não encontrada"}, 404
    if verb == "DELETE":
        store.pop(ident, None)
        return {"ok": True, "removida": ident}, 200
    if verb != "GET":
        texto = data.get("texto", note["texto"] if verb == "PATCH" else None) if isinstance(data, dict) else None
        if not isinstance(texto, str) or not texto.strip():
            return ({"erro": "Envie o campo texto"}, 422) if isinstance(data, dict) else ({"erro": "JSON inválido"}, 400)
        note["texto"] = texto.strip()[:300]
    return {"id": ident, "texto": note["texto"]}, 200


def note_screen(lab, verb, variant, ident, page):
    actor = lab.actor()
    texto = parse_qs(lab.rfile.read(min(int(lab.headers.get("Content-Length") or 0), 2048)).decode(errors="replace")).get("texto", [""])[0].strip()[:300] if verb == "POST" else ""
    with _STATE_LOCK:
        note = dict(NOTES[variant].get(int(ident), {})) if ident else {}
        mine = [key for key, item in sorted(NOTES[variant].items()) if item["dono"] == actor]
        if actor and verb == "POST" and texto:
            SEQUENCE[variant] += 1
            ident = SEQUENCE[variant]
            NOTES[variant][ident] = {"dono": actor, "texto": texto}
    if not actor and verb == "GET":
        lab.redirect(f"/{variant}/entrar")
    elif not actor or (verb == "POST" and not texto):
        lab.reply(page("<h1>Entre novamente para criar anotações</h1>" if not actor else "<h1>Escreva o texto da anotação</h1>"), 401 if not actor else 422)
    elif verb == "POST":
        lab.redirect(f"/{variant}/notas/{ident}")
    elif not ident:
        items = "".join(f'<li><a href="/{variant}/notas/{key}">Anotação #{key}</a></li>' for key in mine)
        lab.reply(page(NOTES_PAGE.format(actor=actor.upper(), variant=variant, items=items or "<li>Nenhuma anotação ainda.</li>")))
    elif note.get("dono") != actor:
        lab.reply(page("<h1>Anotação não encontrada</h1>"), 404)
    else:
        lab.reply(page(NOTE_PAGE.format(actor=actor.upper(), variant=variant, ident=int(ident), texto=html.escape(note["texto"]))))
    return True


def public_host(url):
    host = urlsplit(url).hostname
    if not host:
        return False
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                return False
    except Exception:
        return False
    return True


def get(lab, path, page):
    if notes(lab, "GET", path, page):
        return True
    busca = re.fullmatch(r"/servicos/(vulneravel|corrigido)/busca", path)
    if busca:
        variant = busca.group(1)
        term = parse_qs(urlsplit(lab.path).query).get("q", [""])[0]
        shown = term if variant == "vulneravel" else html.escape(term)
        lab.reply(page(f"<small>BUSCA</small><h1>Resultados</h1><p>Resultados para {shown}</p>"))
        return True
    consulta = re.fullmatch(r"/servicos/(vulneravel|corrigido)/consulta", path)
    if consulta:
        variant = consulta.group(1)
        value = parse_qs(urlsplit(lab.path).query).get("id", [""])[0]
        if variant == "vulneravel" and re.search(r"sleep|benchmark|waitfor|pg_sleep|'", value, re.I):
            time.sleep(6)
        lab.reply(json.dumps({"consulta": value[:40], "itens": []}), kind="application/json")
        return True
    integrador = re.fullmatch(r"/servicos/(vulneravel|corrigido)/integrador", path)
    if integrador:
        variant = integrador.group(1)
        destino = parse_qs(urlsplit(lab.path).query).get("url", [""])[0]
        if variant == "vulneravel" and destino.startswith(("http://", "https://")) and public_host(destino):
            try:
                urllib.request.urlopen(destino, timeout=4).read(64)
            except Exception:
                pass
            lab.reply(json.dumps({"ok": True, "destino": destino[:120]}), kind="application/json")
        else:
            lab.reply(json.dumps({"error": "destino nao permitido"}), 400, "application/json")
        return True
    pedido = re.fullmatch(r"/servicos/(vulneravel|corrigido)/pedido", path)
    if pedido:
        variant = pedido.group(1)
        value = parse_qs(urlsplit(lab.path).query).get("id", [""])[0][:80]
        database = sqlite3.connect(":memory:")
        try:
            database.execute("CREATE TABLE pedidos (id TEXT, item TEXT)")
            database.executemany("INSERT INTO pedidos VALUES (?, ?)", [("1", "Assinatura anual"), ("2", "Suporte premium")])
            if variant == "vulneravel":
                rows = database.execute(f"SELECT id, item FROM pedidos WHERE id = '{value}'").fetchall()
            else:
                rows = database.execute("SELECT id, item FROM pedidos WHERE id = ?", (value,)).fetchall()
        except sqlite3.Error:
            rows = []
        finally:
            database.close()
        lab.reply(json.dumps({"pedidos": [{"id": row[0], "item": row[1]} for row in rows]}), kind="application/json")
        return True
    retorno = re.fullmatch(r"/servicos/(vulneravel|corrigido)/retorno", path)
    if retorno:
        variant = retorno.group(1)
        destino = parse_qs(urlsplit(lab.path).query).get("destino", [""])[0][:300]
        if variant == "corrigido" and not re.fullmatch(r"/(?![/\\])[!-\[\]-~]*", destino):
            destino = ""
        lab.reply("", 302, Location=quote(destino, safe=PRINTABLE) or f"/{variant}/painel")
        return True
    arquivo = re.fullmatch(r"/servicos/(vulneravel|corrigido)/arquivo", path)
    if arquivo:
        variant = arquivo.group(1)
        name = parse_qs(urlsplit(lab.path).query).get("file", [""])[0][:200]
        if variant == "corrigido" and (".." in name or "\\" in name or name.startswith("/")):
            lab.reply(json.dumps({"error": "Nome de arquivo inválido"}), 400, "application/json")
            return True
        resolved = posixpath.normpath(posixpath.join(DOCUMENTS_DIR, name.replace("\\", "/")))
        if variant == "vulneravel" and resolved in SYSTEM_FILES:
            lab.reply(SYSTEM_FILES[resolved], kind="text/plain; charset=utf-8")
            return True
        document = DOCUMENTS.get(posixpath.basename(resolved)) if posixpath.dirname(resolved) == DOCUMENTS_DIR else None
        if document:
            lab.reply(document, kind="text/plain; charset=utf-8")
        else:
            lab.reply(json.dumps({"error": "Arquivo não encontrado"}), 404, "application/json")
        return True
    clientes = re.fullmatch(r"/servicos/(vulneravel|corrigido)/clientes", path)
    if clientes:
        variant = clientes.group(1)
        filtro = parse_qs(urlsplit(lab.path).query).get("filtro", [""])[0][:200]
        operador = re.search(r"\$(ne|gt|gte|lt|lte|in|nin|regex|where|exists)\b|;\s*return\b", filtro)
        if variant == "vulneravel" and operador:
            lab.reply(json.dumps({"error": "MongoServerError: unknown top level operator: $" + (operador.group(1) or "where")}), 500, "application/json")
            return True
        lab.reply(json.dumps({"clientes": [item for item in CUSTOMERS if item["status"] == filtro]}), kind="application/json")
        return True
    bundle = re.fullmatch(r"/(vulneravel|corrigido)/app\.js", path)
    if bundle:
        sink = "innerHTML" if bundle.group(1) == "vulneravel" else "textContent"
        lab.reply(BUNDLE.format(sink=sink), kind="application/javascript; charset=utf-8")
        return True
    perfil = re.fullmatch(r"/servicos/(vulneravel|corrigido)/perfil", path)
    if perfil:
        apelido = parse_qs(urlsplit(lab.path).query).get("apelido", [""])[0][:200]
        shown = apelido.replace("<", "").replace(">", "") if perfil.group(1) == "vulneravel" else html.escape(apelido, quote=True)
        lab.reply(page(f'<small>PERFIL</small><h1>Seu apelido</h1><form><label>Apelido<input name="apelido" value="{shown}"></label></form>'))
        return True
    mensagem = re.fullmatch(r"/servicos/(vulneravel|corrigido)/mensagem", path)
    if mensagem:
        nome = parse_qs(urlsplit(lab.path).query).get("nome", [""])[0][:200]
        if mensagem.group(1) == "vulneravel":
            nome = TEMPLATE_EXPRESSION.sub(lambda found: str(int(found.group(1)) * int(found.group(2))), nome)
        lab.reply(page(f"<small>MENSAGEM</small><h1>Olá, {html.escape(nome)}</h1><p>Seu boleto vence amanhã.</p>"))
        return True
    preferencias = re.fullmatch(r"/servicos/(vulneravel|corrigido)/preferencias", path)
    if preferencias:
        base = {"tema": "claro", "idioma": "pt-BR"}
        if preferencias.group(1) == "vulneravel":
            base.update({k: v for k, v in POLLUTED.items() if isinstance(v, str)})
        lab.reply(json.dumps(base), kind="application/json")
        return True
    relatorio = re.fullmatch(r"/servicos/(vulneravel|corrigido)/relatorio", path)
    if relatorio:
        mes = parse_qs(urlsplit(lab.path).query).get("mes", [""])[0][:200]
        if re.fullmatch(r"\d{1,6}", mes):
            lab.reply(json.dumps({"relatorio": f"mês {int(mes)}", "faturas": 0}), kind="application/json")
        elif relatorio.group(1) == "vulneravel":
            lab.reply(STACK_TRACE, 500, "text/html; charset=utf-8")
        else:
            lab.reply(json.dumps({"erro": "parâmetro mes inválido"}), 422, "application/json")
        return True
    diagnostico = re.fullmatch(r"/servicos/(vulneravel|corrigido)/diagnostico", path)
    if diagnostico:
        host = parse_qs(urlsplit(lab.path).query).get("host", [""])[0][:200]
        if diagnostico.group(1) == "corrigido" and not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
            lab.reply(json.dumps({"erro": "host inválido"}), 422, "application/json")
            return True
        parts = re.split(r"[;|&`]|\$\(", host, maxsplit=1)
        output = f"PING {parts[0].strip() or 'localhost'}: 4 pacotes, 0% de perda"
        if diagnostico.group(1) == "vulneravel" and len(parts) == 2:
            echo = re.search(r"echo\s+\$\(\(\s*(\d{1,6})\s*\*\s*(\d{1,6})\s*\)\)", parts[1])
            pause = re.search(r"(?:sleep\s+|ping\s+-c\s+)(\d{1,2})", parts[1])
            if echo:
                output += "\n" + str(int(echo.group(1)) * int(echo.group(2)))
            if pause:
                time.sleep(min(int(pause.group(1)), 6))
        lab.reply(json.dumps({"saida": output}), kind="application/json")
        return True
    return False


def post(lab, path, page=None):
    if notes(lab, "POST", path, page):
        return True
    graphql = re.fullmatch(r"/servicos/(vulneravel|corrigido)/graphql", urlsplit(lab.path).path)
    if graphql:
        try:
            body = json.loads(lab.rfile.read(min(int(lab.headers.get("Content-Length", 0)), 4096)) or b"{}")
        except ValueError:
            lab.reply(json.dumps({"errors": [{"message": "JSON inválido"}]}), 400, "application/json")
            return True
        query = str(body.get("query", "")) if isinstance(body, dict) else ""
        aliases = re.findall(r"(egideAlias\d+)\s*:", query)
        if aliases:
            if graphql.group(1) == "vulneravel":
                lab.reply(json.dumps({"data": {alias: [] for alias in aliases}}), kind="application/json")
            else:
                lab.reply(json.dumps({"data": {aliases[0]: []}}), kind="application/json")
            return True
        if "__schema" in query or "__type" in query:
            answer = {"data": {"__schema": SCHEMA}} if graphql.group(1) == "vulneravel" else {"errors": [{"message": "Introspecção desativada neste ambiente"}]}
            lab.reply(json.dumps(answer), kind="application/json")
            return True
        lab.reply(json.dumps({"data": {"faturas": []}}), kind="application/json")
        return True
    preferencias = re.fullmatch(r"/servicos/(vulneravel|corrigido)/preferencias", urlsplit(lab.path).path)
    if preferencias:
        try:
            body = json.loads(lab.rfile.read(min(int(lab.headers.get("Content-Length", 0)), 4096)) or b"{}")
        except ValueError:
            lab.reply(json.dumps({"erro": "JSON inválido"}), 400, "application/json")
            return True
        proto = body.get("__proto__") if isinstance(body, dict) else None
        if preferencias.group(1) == "vulneravel" and isinstance(proto, dict):
            POLLUTED.update({k: v for k, v in proto.items() if isinstance(v, str)})
        lab.reply(json.dumps({"ok": True}), kind="application/json")
        return True
    resgatar = re.fullmatch(r"/servicos/(vulneravel|corrigido)/resgatar", urlsplit(lab.path).path)
    if resgatar:
        try:
            body = json.loads(lab.rfile.read(min(int(lab.headers.get("Content-Length", 0)), 1024)) or b"{}")
        except ValueError:
            lab.reply(json.dumps({"erro": "JSON inválido"}), 400, "application/json")
            return True
        token = str(body.get("token", "")) if isinstance(body, dict) else ""
        if resgatar.group(1) == "corrigido":
            with _STATE_LOCK:
                if token in REDEEMED:
                    lab.reply(json.dumps({"erro": "Cupom já resgatado"}), 409, "application/json")
                    return True
                REDEEMED.add(token)
            time.sleep(0.05)
            lab.reply(json.dumps({"ok": True, "resgatado": token[:12]}), kind="application/json")
            return True
        time.sleep(0.05)
        lab.reply(json.dumps({"ok": True, "resgatado": token[:12]}), kind="application/json")
        return True
    return False
