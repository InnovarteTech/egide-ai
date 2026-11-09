import csv
import html
import io
import json
import re
import secrets
import smtplib
from email.message import EmailMessage
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlsplit

ORIGIN = "http://lab.egide.test:8788"
accounts = {}
sessions = {}
confirmations = {}
invoices = {}


def reset():
    accounts.clear()
    sessions.clear()
    confirmations.clear()
    invoices.clear()
    for actor in ("a", "b"):
        invoices[actor] = {"id": secrets.token_hex(4), "marcador": "EGIDE-" + secrets.token_hex(6).upper(), "nota": "Sem observacoes"}


def page(content):
    return """<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Prisma Faturas · Laboratório</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f5f5fa;color:#211b35;font:18px system-ui,sans-serif}
header{padding:28px 7%;background:#23183d;color:white;font-size:22px;font-weight:700}
main{max-width:840px;margin:60px auto;padding:38px;background:white;border:1px solid #e5e1ee;border-radius:18px}
small{color:#685d80;font-weight:600}h1{letter-spacing:-.05em;font-size:42px;margin:12px 0}
p{color:#605673;line-height:1.5}label{display:block;margin:18px 0;font-size:14px;font-weight:700}
input{display:block;width:100%;padding:13px;margin-top:6px;border:1px solid #d8d0e5;border-radius:7px;font:inherit}
button,a.button{display:inline-block;padding:12px 18px;background:#5a37cc;color:white;border:0;border-radius:8px;font:600 15px system-ui;text-decoration:none;cursor:pointer}
a{color:#4b2eb3}nav{display:flex;gap:15px;margin-top:24px}pre{padding:15px;background:#f2effb;white-space:pre-wrap}
</style><header>◈ &nbsp; Prisma Faturas</header><main>""" + content + "</main></html>"


class Lab(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def hardened(self):
        return urlsplit(self.path).path.startswith(("/corrigido", "/servicos/corrigido", "/favicon.ico"))

    def version_string(self):
        return "Prisma" if self.hardened() else super().version_string()

    def reply(self, content, status=200, kind="text/html; charset=utf-8", **headers):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Cache-Control", "no-store")
        if self.hardened():
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "same-origin")
        for key, value in headers.items():
            self.send_header(key.replace("_", "-"), value)
        self.end_headers()
        self.wfile.write(content.encode())

    def redirect(self, path, session=None):
        headers = {"Location": path}
        if session:
            headers["Set_Cookie"] = f"lab_session={session}; HttpOnly; Path=/; SameSite=Strict; Max-Age=1800"
        self.reply("", 303, **headers)

    def actor(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        return sessions.get(cookie["lab_session"].value) if "lab_session" in cookie else None

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/favicon.ico":
            self.reply("", 204)
            return
        if path == "/vulneravel/.env":
            self.reply("APP_ENV=production\nAPP_KEY=base64:ZmljdGljaW8tbGFib3JhdG9yaW8=\nDB_PASSWORD=senha-ficticia-do-laboratorio\n", kind="text/plain; charset=utf-8")
            return
        verify = re.fullmatch(r"/(vulneravel|corrigido)/confirmar/([a-f0-9]{32})", path)
        if verify:
            variant, token = verify.groups()
            email = confirmations.pop(token, None)
            if email:
                accounts[email]["confirmed"] = True
                self.redirect(f"/{variant}/entrar")
            else:
                self.reply(page("<h1>Confirmação expirada</h1>"), 404)
            return
        export = re.fullmatch(r"/servicos/(vulneravel|corrigido)/extratos/([a-f0-9]{8})", path)
        if export:
            variant, invoice = export.groups()
            owner = next((actor for actor, item in invoices.items() if item["id"] == invoice), None)
            if not self.actor() or not owner or (variant == "corrigido" and self.actor() != owner):
                self.reply(json.dumps({"error": "Acesso negado"}), 403, "application/json")
                return
            record = invoices[owner]
            if "application/json" in self.headers.get("Accept", ""):
                self.reply(json.dumps({"fatura": invoice, "empresa": owner.upper(), "marcador": record["marcador"], "nota": record["nota"]}), kind="application/json")
                return
            result = io.StringIO()
            writer = csv.writer(result)
            writer.writerow(("fatura", "empresa", "marcador", "nota"))
            writer.writerow((invoice, owner.upper(), record["marcador"], record["nota"]))
            self.reply(result.getvalue(), kind="text/csv; charset=utf-8")
            return
        match = re.fullmatch(r"/(vulneravel|corrigido)(?:/(entrar|cadastro|painel|faturas|ajuda))?/?", path)
        if not match:
            self.reply(page("<h1>Rota indisponível</h1>"), 404)
            return
        variant, screen = match.groups()
        if screen in (None, "entrar", "cadastro"):
            register = screen == "cadastro"
            title = "Criar conta de teste" if register else "Acesse sua empresa"
            action = "cadastro" if register else "entrar"
            button = "Criar conta" if register else "Entrar"
            self.reply(page(f"""
<small>AMBIENTE CONTROLADO · {variant.upper()}</small><h1>{title}</h1>
<p>Portal de faturamento com registros fictícios para avaliação de acesso.</p>
<form method="post" action="/{variant}/{action}">
<label>E-mail<input name="email" type="email" required autocomplete="off"></label>
<label>Senha<input name="password" type="password" required autocomplete="off"></label>
<button type="submit">{button}</button></form>
<nav><a href="/{variant}/cadastro">Cadastrar nova conta</a><a href="/{variant}/entrar">Ir para login</a></nav>
"""))
            return
        actor = self.actor()
        if not actor:
            self.redirect(f"/{variant}/entrar")
            return
        if screen == "painel":
            self.reply(page(f"""
<small>EMPRESA {actor.upper()}</small><h1>Painel financeiro</h1>
<p>Consulte os registros e exportações da sua empresa de teste.</p>
<nav><a class="button" href="/{variant}/faturas">Ver faturas</a><a href="/{variant}/ajuda">Ajuda do portal</a></nav>
"""))
            return
        if screen == "ajuda":
            self.reply(page(f"""
<small>EMPRESA {actor.upper()}</small><h1>Ajuda do portal</h1>
<p>Encontre seus documentos na página de faturas.</p>
<nav><a href="/{variant}/painel">Voltar ao painel</a><a href="/{variant}/faturas">Ver faturas</a></nav>
"""))
            return
        invoice, marker = invoices[actor]["id"], invoices[actor]["marcador"]
        self.reply(page(f"""
<small>EMPRESA {actor.upper()}</small><h1>Faturas</h1>
<p>Fatura {invoice} · Referência {marker}</p>
<button id="exportar" type="button">Exportar fatura</button>
<pre id="resultado" aria-live="polite"></pre>
<nav><a href="/{variant}/painel">Voltar ao painel</a><a href="/{variant}/ajuda">Ajuda do portal</a></nav>
<script>
document.getElementById("exportar").onclick = async () => {{
  const resposta = await fetch("/servicos/{variant}/extratos/{invoice}");
  document.getElementById("resultado").textContent = await resposta.text();
}};
</script>
"""))

    def do_PATCH(self):
        match = re.fullmatch(r"/(vulneravel|corrigido)/servicos-indisponivel", self.path)
        export = re.fullmatch(r"/servicos/(vulneravel|corrigido)/extratos/([a-f0-9]{8})", urlsplit(self.path).path)
        if not export:
            self.reply(json.dumps({"error": "Rota indisponivel"}), 404, "application/json")
            return
        variant, invoice = export.groups()
        actor = self.actor()
        owner = next((a for a, item in invoices.items() if item["id"] == invoice), None)
        if not actor or not owner or (variant == "corrigido" and actor != owner):
            self.reply(json.dumps({"error": "Acesso negado"}), 403, "application/json")
            return
        try:
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 2048)) or b"{}")
        except ValueError:
            self.reply(json.dumps({"error": "JSON invalido"}), 400, "application/json")
            return
        if "nota" in body and isinstance(body["nota"], str):
            invoices[owner]["nota"] = body["nota"][:200]
        self.reply(json.dumps({"fatura": invoice, "empresa": owner.upper(), "nota": invoices[owner]["nota"]}), kind="application/json")

    def do_POST(self):
        match = re.fullmatch(r"/(vulneravel|corrigido)/(cadastro|entrar)", self.path)
        if not match:
            self.reply(page("<h1>Rota indisponível</h1>"), 404)
            return
        variant, action = match.groups()
        values = parse_qs(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 2048)).decode())
        email = values.get("email", [""])[0]
        password = values.get("password", [""])[0]
        if not re.fullmatch(r"[ab]-[0-9a-f-]{8,40}@egide\.test", email) or len(password) < 12:
            self.reply(page("<h1>Use as credenciais de teste</h1>"), 422)
            return
        if action == "cadastro":
            accounts[email] = {"password": password, "confirmed": False, "actor": email[0]}
            token = secrets.token_hex(16)
            confirmations[token] = email
            message = EmailMessage()
            message["From"] = "laboratorio@egide.test"
            message["To"] = email
            message["Subject"] = "Confirme sua conta no laboratório"
            message.set_content(f"{ORIGIN}/{variant}/confirmar/{token}")
            with smtplib.SMTP("mailpit", 1025, timeout=5) as mail:
                mail.send_message(message)
            self.reply(page(f"<h1>Confirme seu e-mail</h1><p>Mensagem de teste enviada para {html.escape(email)}.</p>"))
            return
        account = accounts.get(email)
        if not account or not account["confirmed"] or account["password"] != password:
            self.reply(page("<h1>Credenciais inválidas</h1>"), 401)
            return
        token = secrets.token_hex(24)
        sessions[token] = account["actor"]
        self.redirect(f"/{variant}/painel", token)
