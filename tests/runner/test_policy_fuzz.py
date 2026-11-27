import ipaddress
import json
import socket
import unittest
from urllib.parse import quote

import types
from urllib.parse import parse_qsl, urlsplit

from hypothesis import given, settings, strategies as st

from test_policy import Headers, OPEN_RULES, PolicyCase


def outgoing_raw(method, path, headers=None, body=b"", host="app.example.com"):
    try:
        query = dict(parse_qsl(urlsplit(path).query))
    except ValueError:
        query = {}
    request = types.SimpleNamespace(
        method=method, host=host, port=443, scheme="https", path=path, pretty_host=host,
        headers=Headers(headers), query=query, urlencoded_form={},
        stream=False, content=body,
    )
    return types.SimpleNamespace(request=request, response=None, metadata={})


class OutOfScopeTest(PolicyCase):
    def test_other_host_port_and_scheme_are_rejected(self):
        self.load(rules=OPEN_RULES)
        for kwargs in ({"host": "outro.example.com"},):
            self.assertEqual(self.send("GET", "/api", **kwargs).response.status_code, 403)
        current = self.send("GET", "/api")
        current.request.port = 8443
        self.policy.request(current)
        self.assertEqual(current.response.status_code, 403)
        current = self.send("GET", "/api")
        current.request.scheme = "http"
        self.policy.request(current)
        self.assertEqual(current.response.status_code, 403)

    def test_denied_routes_win_even_inside_allowed_prefix(self):
        self.load(rules=OPEN_RULES, denied=["/admin", "/api/interno/reset"])
        for path in ("/admin", "/admin/painel", "/api/interno/reset", "/api/interno/reset/x"):
            self.assertEqual(self.send("GET", path).response.status_code, 403, path)
            self.assertEqual(self.last_event()["reason"], "Rota bloqueada no escopo")
        self.assertIsNone(self.send("GET", "/api/interno/outros").response)


class TraversalTest(PolicyCase):
    EVIL_PATHS = (
        "/%2e%2e/segredo", "/a/%2E%2E/b", "/%2f%2fexterno", "//evasao", "/a//b",
        "/a/../b", "/./x", "/../x", "/a/./b", "/a\\b", "/a%5cb", "/a%00b",
        "/a%0d%0ab", "/a%2fb/..", quote("/x/..") + "/y", "/%252e%252e/x",
    )

    def test_encoded_or_literal_traversal_is_rejected(self):
        self.load(rules=OPEN_RULES)
        for path in self.EVIL_PATHS:
            self.assertEqual(self.send("GET", path).response.status_code, 403, path)
            self.assertIn(self.last_event()["reason"], ("Formato de requisição vedado", "Rota bloqueada no escopo"), path)


class MethodOverrideTest(PolicyCase):
    def test_override_headers_query_and_form_are_rejected(self):
        self.load(rules=[{"method": "GET", "path": "/", "prefix": True}])
        for header in ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method",
                       "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Host"):
            self.assertEqual(self.send("GET", "/a", headers={header: "DELETE"}).response.status_code, 403, header)
        self.assertEqual(self.send("GET", "/a?_method=DELETE").response.status_code, 403)
        current = self.send("POST", "/a", headers={"Content-Type": "application/x-www-form-urlencoded"}, body=b"_method=DELETE")
        current.request.urlencoded_form = {"_method": "DELETE"}
        self.policy.request(current)
        self.assertEqual(current.response.status_code, 403)

    def test_dangerous_and_lowercase_verbs_are_denied(self):
        self.load(rules=OPEN_RULES)
        for method in ("TRACE", "CONNECT", "PROPFIND", "get", "delete", "PUTX"):
            self.assertEqual(self.send(method, "/api").response.status_code, 403, method)


class BudgetFuzzTest(PolicyCase):
    def test_reads_writes_and_preflights_have_independent_caps(self):
        self.load(rules=[{"method": "GET", "path": "/", "prefix": True}], budget=2,
                  write={"method": "PATCH", "host": "app.example.com", "path": "/api/me", "prefix": False, "max": 1})

        self.assertIsNone(self.send("GET", "/a").response)
        self.assertIsNone(self.send("GET", "/b").response)
        self.assertEqual(self.send("GET", "/c").response.status_code, 403)
        self.assertEqual(self.last_event()["reason"], "Limite de requisições atingido")

        self.assertIsNone(self.send("PATCH", "/api/me").response)
        self.assertEqual(self.send("PATCH", "/api/me").response.status_code, 403)
        self.assertEqual(self.last_event()["reason"], "Limite de escritas de teste atingido")

        self.assertEqual(self.send("OPTIONS", "/a", headers={"Access-Control-Request-Method": "DELETE"}).response.status_code, 403)
        self.assertEqual(self.last_event()["reason"], "Método ou rota sem permissão")

        for _ in range(2):
            self.assertIsNone(self.send("OPTIONS", "/a", headers={"Access-Control-Request-Method": "GET"}).response)
        self.assertEqual(self.send("OPTIONS", "/a", headers={"Access-Control-Request-Method": "GET"}).response.status_code, 403)
        self.assertEqual(self.last_event()["reason"], "Limite de requisições atingido")

    def test_halt_stops_everything_regardless_of_budget(self):
        self.load(rules=OPEN_RULES, budget=100)
        self.assertIsNone(self.send("GET", "/a").response)
        self.policy.stop.trigger("teste")

        self.assertEqual(self.send("GET", "/a").response.status_code, 403)
        self.assertEqual(self.send("POST", "/api/notas").response.status_code, 403)


class RebindingTest(PolicyCase):
    def test_server_addresses_must_resolve_to_global_ips(self):
        for addresses in (["10.0.0.9"], ["169.254.169.254"], ["127.0.0.1"], ["1.1.1.1", "10.0.0.9"], ["::1"]):
            fake = lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in addresses]
            original = socket.getaddrinfo
            socket.getaddrinfo = fake
            try:
                data = type("Conn", (), {"server": type("Srv", (), {"address": ("app.example.com", 443), "error": None})()})()
                self.policy.server_connect(data)
                self.assertIsNotNone(data.server.error, addresses)
            finally:
                socket.getaddrinfo = original

        public = lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        original = socket.getaddrinfo
        socket.getaddrinfo = public
        try:
            data = type("Conn", (), {"server": type("Srv", (), {"address": ("app.example.com", 443), "error": None})()})()
            self.policy.server_connect(data)
            self.assertIsNone(data.server.error)
            self.assertEqual(data.server.address[0], "93.184.216.34")
        finally:
            socket.getaddrinfo = original

    def test_dns_failure_fails_closed(self):
        original = socket.getaddrinfo
        socket.getaddrinfo = lambda *a, **k: (_ for _ in ()).throw(OSError("falha DNS"))
        try:
            data = type("Conn", (), {"server": type("Srv", (), {"address": ("app.example.com", 443), "error": None})()})()
            self.policy.server_connect(data)
            self.assertIsNotNone(data.server.error)
        finally:
            socket.getaddrinfo = original


class RawSend:
    def send(self, method, path, **kwargs):
        current = outgoing_raw(method, path, **kwargs)
        self.policy.request(current)
        return current


class AllowedMatrixFuzzTest(RawSend, PolicyCase):
    """Invariante: nenhum caminho negado ou fora das regras é liberado, seja qual for o caminho."""

    PATHS = st.text(alphabet="/._-~%abcXYZ0192\\", min_size=1, max_size=60).map(lambda text: "/" + text.lstrip("/"))
    METHODS = st.sampled_from(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "get", "X-TEST"])

    @settings(max_examples=200, deadline=None)
    @given(path=PATHS, method=METHODS)
    def test_denied_and_unlisted_paths_never_pass(self, path, method):
        self.load(rules=[{"method": "GET", "path": "/api", "prefix": True},
                         {"method": "POST", "path": "/api/notas", "prefix": False}],
                  denied=["/api/segredo"])
        import urllib.parse
        current = self.send(method, path)
        decoded = urllib.parse.unquote(path)
        rejected = current.response is not None and current.response.status_code == 403
        malformed = (
            not path.startswith("/") or path.startswith("//") or
            "%" in decoded or "\\" in decoded or "//" in decoded or
            any(part in (".", "..") for part in decoded.split("/")) or
            any(ord(char) < 32 for char in decoded)
        )
        denied = decoded == "/api/segredo" or decoded.startswith("/api/segredo/")
        if malformed or denied:
            self.assertTrue(rejected, (method, path))
        if not rejected:
            self.assertTrue(decoded == "/api/notas" and method == "POST"
                            or method == "GET" and (decoded == "/api" or decoded.startswith("/api/")), (method, path))


class MalformedFuzzTest(RawSend, PolicyCase):
    @settings(max_examples=150, deadline=None)
    @given(st.binary(min_size=0, max_size=80))
    def test_arbitrary_bytes_in_path_never_crash_the_gate(self, blob):
        path = "/" + "".join(chr(33 + byte % 94) for byte in blob)
        current = self.send("GET", path)
        self.assertIn(current.response is None or current.response.status_code == 403, (True,))


if __name__ == "__main__":
    unittest.main()
