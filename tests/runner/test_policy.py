import importlib.util
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

RUNNER = Path(__file__).resolve().parents[2] / "runner"


class Headers:
    def __init__(self, values=None):
        self.values = {key.lower(): value for key, value in (values or {}).items()}

    def get(self, name, default=None):
        return self.values.get(name.lower(), default)

    def get_all(self, name):
        value = self.values.get(name.lower())
        return [value] if value else []

    def pop(self, name, default=None):
        return self.values.pop(name.lower(), default)

    def __contains__(self, name):
        return name.lower() in self.values

    def __getitem__(self, name):
        return self.values[name.lower()]

    def __setitem__(self, name, value):
        self.values[name.lower()] = value


def flow(status, headers, body=None, path="/retorno?destino=x"):
    return types.SimpleNamespace(
        request=types.SimpleNamespace(method="GET", pretty_host="app.example.com", path=path, scheme="https",
                                      headers=Headers(), content=b""),
        response=types.SimpleNamespace(status_code=status, headers=Headers(headers), content=body),
        metadata={"scheme": "https"},
    )


def outgoing(method, path, headers=None, body=b"", host="app.example.com"):
    request = types.SimpleNamespace(
        method=method, host=host, port=443, scheme="https", path=path, pretty_host=host,
        headers=Headers(headers), query=dict(parse_qsl(urlsplit(path).query)), urlencoded_form={},
        stream=False, content=body,
    )
    return types.SimpleNamespace(request=request, response=None, metadata={})


OPEN_RULES = [{"method": "*", "path": "/", "prefix": True}]


class PolicyCase(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.load()

    def load(self, **overrides):
        scope = {
            "host": "app.example.com", "hosts": ["app.example.com"], "port": 443, "scheme": "https",
            "rules": [], "denied": [], "budget": 80, "lab": False,
        }
        scope.update(overrides)
        (self.folder / "policy.json").write_text(json.dumps(scope))
        os.environ["EGIDE_POLICY"] = str(self.folder / "policy.json")
        os.environ["EGIDE_EVENTS"] = str(self.folder / "events.ndjson")
        mitmproxy = types.ModuleType("mitmproxy")
        mitmproxy.http = types.ModuleType("mitmproxy.http")
        mitmproxy.http.Response = types.SimpleNamespace(make=lambda status, content, headers: types.SimpleNamespace(
            status_code=status, content=content, headers=Headers(headers)))
        sys.modules["mitmproxy"] = mitmproxy
        sys.modules["mitmproxy.http"] = mitmproxy.http
        spec = importlib.util.spec_from_file_location("egide_policy_under_test", RUNNER / "policy.py")
        self.policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.policy)
        return self.policy

    def tearDown(self):
        sys.modules.pop("mitmproxy", None)
        sys.modules.pop("mitmproxy.http", None)
        shutil.rmtree(self.folder, ignore_errors=True)

    def last_event(self):
        return json.loads((self.folder / "events.ndjson").read_text().splitlines()[-1])

    def send(self, method, path, **kwargs):
        current = outgoing(method, path, **kwargs)
        self.policy.request(current)
        return current

    def answered(self, current, status, headers, body):
        current.response = types.SimpleNamespace(status_code=status, headers=Headers(headers), content=body)
        self.policy.response(current)
        return self.last_event()

    def canaries(self, *paths):
        (self.folder / "canaries.json").write_text(json.dumps([
            {"actor": "a", "path": path, "marker": "EGIDE-CA-0123456789AB", "method": "POST", "object_id": None}
            for path in paths
        ]))


class PolicyRedirectTest(PolicyCase):
    def test_redirect_response_records_its_location(self):
        self.policy.response(flow(302, {"Location": "https://egide-ab12cd34.invalid/"}))

        event = self.last_event()
        self.assertEqual(event["status"], 302)
        self.assertEqual(event["location"], "https://egide-ab12cd34.invalid/")

    def test_non_redirect_response_records_no_location(self):
        self.policy.response(flow(200, {"Location": "https://egide-ab12cd34.invalid/", "Content-Type": "text/html"}))

        self.assertNotIn("location", self.last_event())

    def test_location_keeps_only_the_destination_host_never_query_or_path(self):
        cases = (
            ("https://egide-ab12cd34.invalid/cb?code=segredo-oauth#frag", "https://egide-ab12cd34.invalid/"),
            ("https://app.example.com@egide-ab12cd34.invalid/x?t=segredo", "https://egide-ab12cd34.invalid/"),
            ("/\\egide-ab12cd34.invalid/reset/segredo", "https://egide-ab12cd34.invalid/"),
            ("/\t/egide-ab12cd34.invalid/?k=segredo", "https://egide-ab12cd34.invalid/"),
            ("/redefinir?token=segredo", "/redefinir"),
        )
        for location, expected in cases:
            self.policy.response(flow(302, {"Location": location}))

            recorded = self.last_event()["location"]
            self.assertEqual(recorded, expected, location)
            self.assertNotIn("segredo", recorded, location)

    def test_recorded_location_is_bounded(self):
        self.policy.response(flow(301, {"Location": "https://egide-ab12cd34.invalid/" + "a" * 5000}))

        self.assertLessEqual(len(self.last_event()["location"]), 300)


class ClassifierTest(PolicyCase):
    def test_actions_follow_the_contract(self):
        cases = (
            ("GET", "/api/convites", "leitura"), ("HEAD", "/", "leitura"), ("OPTIONS", "/api/x", "leitura"),
            ("POST", "/api/notas", "escrita_propria"), ("POST", "/api/convites", "efeito_externo"),
            ("POST", "/api/Users/Invite", "efeito_externo"), ("PATCH", "/api/perfil/e-mail", "efeito_externo"),
            ("POST", "/checkout/sessao", "efeito_externo"), ("DELETE", "/hooks/webhook/9", "efeito_externo"),
            ("POST", "/financeiro/cobranca", "efeito_externo"), ("POST", "/whatsapp/enviar", "efeito_externo"),
            ("PUT", "/api/notas/1", "escrita_irreversivel"), ("PATCH", "/api/notas/1", "escrita_irreversivel"),
            ("DELETE", "/api/notas/1", "escrita_irreversivel"), ("TRACE", "/", "negado"),
            ("PROPFIND", "/api", "negado"), ("patch", "/api/notas/1", "negado"),
        )
        for method, path, expected in cases:
            self.assertEqual(self.policy.classify(method, path), expected, (method, path))

    def test_canary_path_and_write_rule_make_updates_own_writes(self):
        self.load(write={"method": "PATCH", "host": "app.example.com", "path": "/api/perfil", "prefix": False, "max": 4})
        self.canaries("/api/notas/7")

        for method, path, host, expected in (
            ("PATCH", "/api/notas/7", None, "escrita_propria"), ("DELETE", "/api/notas/7/anexos/1", None, "escrita_propria"),
            ("DELETE", "/api/notas/70", None, "escrita_irreversivel"), ("PATCH", "/api/perfil", None, "escrita_propria"),
            ("PATCH", "/api/perfil", "outro.example.com", "escrita_irreversivel"), ("PUT", "/api/perfil", None, "escrita_irreversivel"),
        ):
            self.assertEqual(self.policy.classify(method, path, host), expected, (method, path, host))

    def test_canary_file_is_cached_reloaded_on_change_and_never_shrinks_on_corruption(self):
        self.canaries("/", "/api/notas/7")
        self.assertEqual(self.policy.classify("PATCH", "/api/notas/8"), "escrita_irreversivel")

        self.canaries("/api/notas/7", "/api/notas/8")
        self.assertEqual(self.policy.classify("PATCH", "/api/notas/8"), "escrita_propria")

        (self.folder / "canaries.json").write_text("[{\"path\": ")
        self.assertEqual(self.policy.classify("PATCH", "/api/notas/8"), "escrita_propria")
        self.assertEqual(self.policy.classify("PATCH", "/api/notas/9"), "escrita_irreversivel")


class SafetyModeTest(PolicyCase):
    def test_mode_defaults_and_conservative_fallback(self):
        self.assertEqual(self.policy.safety, "livre")
        self.assertEqual(self.load(lab=True).safety, "lab")
        self.assertEqual(self.load(lab=True, safety="canario").safety, "canario")
        self.assertEqual(self.load(safety="turbo").safety, "mapeamento")
        self.assertEqual(self.load(safety="lab", lab=False).safety, "mapeamento")

    def test_livre_blocks_external_effects_and_denied_methods_only(self):
        self.load(rules=OPEN_RULES)

        self.assertIsNone(self.send("POST", "/api/notas").response)
        self.assertIsNone(self.send("DELETE", "/api/notas/1").response)
        blocked = self.send("POST", "/api/convites")
        self.assertEqual(blocked.response.status_code, 403)
        event = self.last_event()
        self.assertFalse(event["allowed"])
        self.assertEqual(event["acao"], "efeito_externo")
        self.assertIn("efeito externo", event["reason"])
        self.assertEqual(self.send("TRACE", "/api").response.status_code, 403)
        self.assertEqual(self.last_event()["acao"], "negado")

    def test_canario_releases_patch_and_delete_only_on_the_canary_path(self):
        self.load(rules=OPEN_RULES, safety="canario")
        self.canaries("/api/notas/7")

        self.assertIsNone(self.send("PATCH", "/api/notas/7").response)
        self.assertIsNone(self.send("DELETE", "/api/notas/7").response)
        self.assertIsNone(self.send("POST", "/api/notas").response)
        for method, path in (("PATCH", "/api/notas/8"), ("DELETE", "/api/notas/70"), ("PUT", "/api/usuarios/1")):
            self.assertEqual(self.send(method, path).response.status_code, 403, (method, path))
            self.assertEqual(self.last_event()["acao"], "escrita_irreversivel")
        self.assertEqual(self.send("POST", "/api/notas/7/enviar").response.status_code, 403)
        self.load(rules=[{"method": "GET", "path": "/", "prefix": True}], safety="canario")
        self.send("PATCH", "/api/notas/7")
        self.assertEqual(self.last_event()["reason"], "Método ou rota sem permissão")

    def test_configured_write_test_keeps_working_even_with_external_words(self):
        write = {"method": "PATCH", "host": "app.example.com", "path": "/api/me/notificacoes", "prefix": False, "max": 4}
        self.load(write=write)
        self.assertIsNone(self.send("PATCH", "/api/me/notificacoes").response)

        self.load(write=write, safety="mapeamento")
        self.assertEqual(self.policy.classify("PATCH", "/api/me/notificacoes"), "escrita_propria")
        self.assertEqual(self.send("PATCH", "/api/me/notificacoes").response.status_code, 403)

    def test_mapping_blocks_updates_even_on_canary_write_rule_and_approved(self):
        self.load(rules=OPEN_RULES, safety="mapeamento",
                  write={"method": "PATCH", "host": "app.example.com", "path": "/api/perfil", "prefix": False, "max": 4},
                  approved_writes=[{"method": "DELETE", "path": "/api/notas", "prefix": True}])
        self.canaries("/api/notas/7")

        for method, path in (("PATCH", "/api/notas/7"), ("DELETE", "/api/notas/7"), ("PATCH", "/api/perfil"), ("PUT", "/api/x")):
            self.assertEqual(self.send(method, path).response.status_code, 403, (method, path))
        self.assertIsNone(self.send("POST", "/api/notas").response)
        self.assertIsNone(self.send("GET", "/api/notas").response)
        self.assertEqual(self.send("POST", "/api/convites").response.status_code, 403)

    def test_approved_writes_release_the_exact_method_and_route(self):
        self.load(rules=OPEN_RULES, safety="canario", approved_writes=[
            {"method": "POST", "path": "/api/convites", "prefix": False},
            {"method": "DELETE", "path": "/api/rascunhos", "prefix": True},
            {"method": "POST", "path": "/", "prefix": True},
        ])

        self.assertIsNone(self.send("POST", "/api/convites").response)
        self.assertIsNone(self.send("DELETE", "/api/rascunhos/3").response)
        self.assertEqual(self.send("PATCH", "/api/convites").response.status_code, 403)
        self.assertEqual(self.send("POST", "/api/convites/5/reenviar").response.status_code, 403)
        self.assertEqual(self.send("DELETE", "/api/rascunhos-antigos/3").response.status_code, 403)
        self.assertEqual(self.send("POST", "/api/pagamentos").response.status_code, 403)

    def test_lab_only_records_the_action(self):
        self.load(rules=OPEN_RULES, lab=True)
        current = self.send("POST", "/api/convites")

        self.assertIsNone(current.response)
        self.assertEqual(self.answered(current, 201, {}, b"")["acao"], "efeito_externo")

    def test_existing_rejections_still_record_events(self):
        self.load(rules=OPEN_RULES, budget=1)
        broken = outgoing("GET", "/a")
        broken.request.path = "//[x/a"
        self.policy.request(broken)
        self.assertEqual((broken.response.status_code, self.last_event()["reason"]), (403, "Formato de requisição vedado"))

        self.send("POST", "/api/notas?_method=DELETE")
        self.assertEqual(self.last_event()["reason"], "Formato de requisição vedado")
        self.send("GET", "/a", headers={"X-HTTP-Method-Override": "DELETE"})
        self.assertEqual(self.last_event()["reason"], "Formato de requisição vedado")
        self.assertIsNone(self.send("GET", "/a").response)
        self.send("GET", "/b")
        self.assertEqual(self.last_event()["reason"], "Limite de requisições atingido")


class IdentificationTest(PolicyCase):
    def test_session_tag_header_is_forced_only_when_the_tag_is_valid(self):
        for tag, expected in (("scan-42ab", "scan-42ab"), (None, None), ("tag com espaço\r\nX: y", None), (42, None)):
            self.load(rules=OPEN_RULES, session_tag=tag)

            sent = self.send("GET", "/api/notas", headers={"X-Egide-Session": "forjado"} if expected else None)

            self.assertEqual(sent.request.headers.get("x-egide-session"), expected, tag)


class EventEnrichmentTest(PolicyCase):
    def test_response_event_carries_markers_shape_size_latency_and_actor(self):
        self.load(rules=OPEN_RULES, markers=["EGIDE-00112233445566AA"])
        (self.folder / "actor").write_text("b")
        current = self.send("GET", "/api/notas/7")
        current.metadata["egide_started"] -= 0.25
        body = json.dumps({"nota": "EGIDE-CA-0123456789AB e EGIDE-00112233445566AA", "id": 7}).encode()

        event = self.answered(current, 200, {"Content-Type": "application/json; charset=utf-8"}, body)

        expected = {"actor": "b", "acao": "leitura", "markers": ["EGIDE-00112233445566AA", "EGIDE-CA-0123456789AB"],
                    "sent_markers": [], "ctype": "application/json", "shape": "json:id,nota", "size": len(body)}
        self.assertEqual({key: event[key] for key in expected}, expected)
        self.assertGreaterEqual(event["ms"], 250)

    def test_markers_in_request_query_and_body_are_sent_markers(self):
        self.load(rules=OPEN_RULES)
        current = self.send("POST", "/api/notas?ref=EGIDE-CB-AAAAAAAAAAAA",
                            body=b'{"nota": "EGIDE-CA-0123456789AB"}')

        event = self.answered(current, 201, {"Content-Type": "text/plain"}, b"ok")

        self.assertEqual(event["sent_markers"], ["EGIDE-CA-0123456789AB", "EGIDE-CB-AAAAAAAAAAAA"])
        self.assertEqual(event["markers"], [])
        self.assertEqual(event["shape"], "text")

    def test_anonymous_requests_are_attributed_to_anon(self):
        self.load(rules=OPEN_RULES)
        (self.folder / "actor").write_text("a")
        self.assertEqual(self.answered(self.send("GET", "/api/notas", headers={"X-Egide-Anon": "1"}), 401, {}, b"")["actor"], "anon")

    def test_rejected_event_is_enriched_too(self):
        self.load(rules=OPEN_RULES)
        (self.folder / "actor").write_text("a")

        self.send("POST", "/api/convites?c=EGIDE-CA-0123456789AB", headers={"X-Egide-Anon": "1"})
        event = self.last_event()

        self.assertEqual(event["actor"], "anon")
        self.assertEqual(event["acao"], "efeito_externo")
        self.assertEqual(event["sent_markers"], ["EGIDE-CA-0123456789AB"])
        self.assertEqual((event["markers"], event["ctype"], event["shape"], event["size"], event["ms"]), ([], "", "", 0, 0))

    def test_only_the_first_512_kb_of_textual_bodies_are_scanned(self):
        self.load(rules=OPEN_RULES)
        late = b"x" * (512 * 1024) + b"EGIDE-CA-0123456789AB"

        html = self.answered(self.send("GET", "/a"), 200, {"Content-Type": "text/html"}, late)
        image = self.answered(self.send("GET", "/a.png"), 200, {"Content-Type": "image/png"}, b"EGIDE-CA-0123456789AB")

        self.assertEqual((html["markers"], html["shape"]), ([], "html"))
        self.assertEqual((image["markers"], image["shape"], image["ctype"]), ([], "", "image/png"))

    def test_upstream_cannot_hide_its_response_with_the_blocked_header(self):
        self.load(rules=OPEN_RULES)

        event = self.answered(self.send("GET", "/a"), 200, {"X-Egide-Blocked": "1"}, b"")

        self.assertEqual((event["allowed"], event["status"]), (True, 200))


if __name__ == "__main__":
    unittest.main()
