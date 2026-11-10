import html
import ipaddress
import json
import posixpath
import re
import socket
import sqlite3
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
    return False


def post(lab, path):
    graphql = re.fullmatch(r"/servicos/(vulneravel|corrigido)/graphql", urlsplit(lab.path).path)
    if graphql:
        try:
            body = json.loads(lab.rfile.read(min(int(lab.headers.get("Content-Length", 0)), 4096)) or b"{}")
        except ValueError:
            lab.reply(json.dumps({"errors": [{"message": "JSON inválido"}]}), 400, "application/json")
            return True
        query = str(body.get("query", "")) if isinstance(body, dict) else ""
        if "__schema" in query or "__type" in query:
            answer = {"data": {"__schema": SCHEMA}} if graphql.group(1) == "vulneravel" else {"errors": [{"message": "Introspecção desativada neste ambiente"}]}
            lab.reply(json.dumps(answer), kind="application/json")
            return True
        lab.reply(json.dumps({"data": {"faturas": []}}), kind="application/json")
        return True
    return False
