import http.client
import importlib.util
import json
import re
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlencode

RUNNER = Path(__file__).resolve().parents[2] / "runner"


class LabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(RUNNER))
        spec = importlib.util.spec_from_file_location("egide_lab_under_test", RUNNER / "lab.py")
        cls.lab = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.lab)
        cls.lab.reset()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), cls.lab.Lab)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.lab.sessions.update({"sessao-a": "a", "sessao-b": "b"})

    def call(self, verb, path, actor=None, payload=None, form=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        body = urlencode(form) if form else payload if payload is None or isinstance(payload, str) else json.dumps(payload)
        headers = {"Cookie": f"lab_session=sessao-{actor}" if actor else "", "Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
        try:
            connection.request(verb, path, body=None if body is None else body.encode(), headers=headers)
            response = connection.getresponse()
            return response.status, response.read().decode(), response.getheader("Location")
        finally:
            connection.close()

    def get(self, path):
        return self.call("GET", path)

    def post_json(self, path, payload):
        return self.call("POST", path, payload=payload)[:2]

    def notes(self, verb, variant, ident="", actor=None, payload=None):
        status, body, _ = self.call(verb, f"/servicos/{variant}/notas" + (f"/{ident}" if ident else ""), actor, payload)
        return status, json.loads(body)

    def create_note(self, variant, actor, texto):
        status, _, location = self.call("POST", f"/{variant}/notas", actor, form={"texto": texto})
        self.assertEqual(status, 303)
        return int(re.fullmatch(rf"/{variant}/notas/(\d+)", location).group(1))

    def test_vulnerable_report_leaks_a_framework_stack_trace_on_bad_input(self):
        status, body, _ = self.get("/servicos/vulneravel/relatorio?mes=" + quote("1'><svg"))
        self.assertEqual(status, 500)
        self.assertIn("Stack trace:", body)
        self.assertIn("vendor/laravel/framework", body)

    def test_vulnerable_report_stays_clean_for_a_valid_month(self):
        status, body, _ = self.get("/servicos/vulneravel/relatorio?mes=3")
        self.assertEqual(status, 200)
        self.assertNotIn("Stack trace", body)
        self.assertEqual(json.loads(body)["faturas"], 0)

    def test_fixed_report_rejects_bad_input_without_a_stack_trace(self):
        status, body, _ = self.get("/servicos/corrigido/relatorio?mes=" + quote("1'><svg"))
        self.assertEqual(status, 422)
        self.assertNotIn("Stack trace", body)
        self.assertNotIn("vendor/laravel", body)

    def test_vulnerable_exposes_an_openapi_spec(self):
        for name in ("swagger.json", "openapi.json", "v2/api-docs"):
            status, body, _ = self.get("/vulneravel/" + name)
            self.assertEqual(status, 200, name)
            data = json.loads(body)
            self.assertIn("openapi", data)
            self.assertIn("paths", data)

    def test_fixed_hides_the_openapi_spec(self):
        status, body, _ = self.get("/corrigido/swagger.json")
        self.assertEqual(status, 404)
        self.assertNotIn("paths", body)

    def test_vulnerable_redeem_has_no_dedup_so_the_same_token_wins_twice(self):
        first = self.post_json("/servicos/vulneravel/resgatar", {"token": "egideRCtest"})
        second = self.post_json("/servicos/vulneravel/resgatar", {"token": "egideRCtest"})
        self.assertEqual(first[0], 200)
        self.assertEqual(second[0], 200)

    def test_fixed_redeem_dedups_the_same_token(self):
        first = self.post_json("/servicos/corrigido/resgatar", {"token": "egideRCtest"})
        second = self.post_json("/servicos/corrigido/resgatar", {"token": "egideRCtest"})
        self.assertEqual(first[0], 200)
        self.assertEqual(second[0], 409)

    def test_vulnerable_accepts_anonymous_delete_write(self):
        status, body = self.call("DELETE", "/servicos/vulneravel/reservas/ab12cd34")[:2]
        self.assertEqual(status, 200)
        self.assertIn("removido", body)

    def test_fixed_rejects_anonymous_delete_write(self):
        status, _ = self.call("DELETE", "/servicos/corrigido/reservas/ab12cd34")[:2]
        self.assertEqual(status, 401)

    def test_vulnerable_preferences_pollutes_the_prototype_and_contaminates_a_fresh_response(self):
        self.post_json("/servicos/vulneravel/preferencias", {"__proto__": {"egidePoluido": "egidePPcafe"}})
        status, body, _ = self.get("/servicos/vulneravel/preferencias")
        self.assertEqual(status, 200)
        self.assertIn("egidePPcafe", body)

    def test_fixed_preferences_ignores_proto_injection(self):
        self.post_json("/servicos/corrigido/preferencias", {"__proto__": {"egidePoluido": "egidePPcafe"}})
        status, body, _ = self.get("/servicos/corrigido/preferencias")
        self.assertEqual(status, 200)
        self.assertNotIn("egidePPcafe", body)

    def test_vulnerable_graphql_runs_a_whole_alias_batch_in_one_request(self):
        query = "{" + " ".join(f"egideAlias{i}: faturas" for i in range(30)) + "}"
        status, body = self.post_json("/servicos/vulneravel/graphql", {"query": query})
        self.assertEqual(status, 200)
        data = json.loads(body)["data"]
        self.assertEqual(len([k for k in data if k.startswith("egideAlias")]), 30)

    def test_fixed_graphql_caps_the_alias_batch(self):
        query = "{" + " ".join(f"egideAlias{i}: faturas" for i in range(30)) + "}"
        status, body = self.post_json("/servicos/corrigido/graphql", {"query": query})
        self.assertEqual(status, 200)
        data = json.loads(body)["data"]
        self.assertEqual(len([k for k in data if k.startswith("egideAlias")]), 1)

    def test_vulnerable_file_download_follows_traversal_with_a_synthetic_passwd(self):
        status, body, _ = self.get("/servicos/vulneravel/arquivo?file=" + quote("../../../../../../etc/passwd", safe=""))

        self.assertEqual(status, 200)
        self.assertIn("root:x:0:0:", body)

    def test_file_download_never_reads_the_real_filesystem(self):
        for target in ("../../../../../../etc/hostname", "../../../../../../proc/self/environ", "/proc/self/environ"):
            status, body, _ = self.get("/servicos/vulneravel/arquivo?file=" + quote(target, safe=""))

            self.assertIn(status, (400, 404), target)
            self.assertNotIn("EGIDE_RUNNER_TOKEN", body, target)

    def test_fixed_file_download_rejects_traversal_and_serves_known_files(self):
        status, body, _ = self.get("/servicos/corrigido/arquivo?file=" + quote("../../../../../../etc/passwd", safe=""))
        self.assertEqual(status, 400)
        self.assertNotIn("root:", body)

        status, _, _ = self.get("/servicos/corrigido/arquivo?file=manual.pdf")
        self.assertEqual(status, 200)

    def test_vulnerable_customer_filter_leaks_a_document_database_error(self):
        status, body, _ = self.get("/servicos/vulneravel/clientes?filtro=" + quote('{"$ne":null}', safe=""))

        self.assertEqual(status, 500)
        self.assertIn("MongoServerError", body)

    def test_fixed_customer_filter_treats_operators_as_plain_text(self):
        status, body, _ = self.get("/servicos/corrigido/clientes?filtro=" + quote('{"$ne":null}', safe=""))

        self.assertEqual(status, 200)
        self.assertNotIn("Mongo", body)
        self.assertEqual(json.loads(body)["clientes"], [])

    def test_vulnerable_graphql_answers_introspection(self):
        status, body = self.post_json("/servicos/vulneravel/graphql", {"query": "{__schema{queryType{name} types{name}}}"})

        self.assertEqual(status, 200)
        self.assertIn("__schema", json.loads(body)["data"])

    def test_fixed_graphql_refuses_introspection(self):
        status, body = self.post_json("/servicos/corrigido/graphql", {"query": "{__schema{queryType{name} types{name}}}"})
        data = json.loads(body)

        self.assertEqual(status, 200)
        self.assertNotIn("data", data)
        self.assertIn("errors", data)

    def test_login_page_loads_a_bundle_that_writes_the_hash_into_the_page(self):
        _, page, _ = self.get("/vulneravel/entrar")
        self.assertIn('src="/vulneravel/app.js"', page)
        self.assertIn('id="aviso"', page)

        _, vulnerable, _ = self.get("/vulneravel/app.js")
        self.assertIn("location.hash", vulnerable)
        self.assertIn(".innerHTML", vulnerable)

        _, fixed, _ = self.get("/corrigido/app.js")
        self.assertIn("location.hash", fixed)
        self.assertNotIn(".innerHTML", fixed)

    def test_profile_strips_brackets_but_leaves_the_attribute_open_in_the_vulnerable_variant(self):
        payload = '" autofocus onfocus="egideXSSabc'
        _, vulnerable, _ = self.get("/servicos/vulneravel/perfil?apelido=" + quote('"><b>' + payload, safe=""))
        self.assertIn('value=""b' + payload, vulnerable)
        self.assertNotIn("<b>", vulnerable)

        _, fixed, _ = self.get("/servicos/corrigido/perfil?apelido=" + quote(payload, safe=""))
        self.assertNotIn(payload, fixed)
        self.assertIn("&quot;", fixed)

    def test_message_template_evaluates_arithmetic_only_in_the_vulnerable_variant(self):
        for expression in ("{{7919*8191}}", "${7919*8191}", "<%= 7919*8191 %>"):
            _, vulnerable, _ = self.get("/servicos/vulneravel/mensagem?nome=" + quote(expression, safe=""))
            self.assertIn("64864529", vulnerable, expression)

            _, fixed, _ = self.get("/servicos/corrigido/mensagem?nome=" + quote(expression, safe=""))
            self.assertNotIn("64864529", fixed, expression)

    def test_diagnostic_simulates_command_injection_without_a_real_shell(self):
        _, echoed, _ = self.get("/servicos/vulneravel/diagnostico?host=" + quote("127.0.0.1;echo $((7919*8191))", safe=""))
        self.assertIn("64864529", echoed)

        status, fixed, _ = self.get("/servicos/corrigido/diagnostico?host=" + quote("127.0.0.1;echo $((7919*8191))", safe=""))
        self.assertEqual(status, 422)
        self.assertNotIn("64864529", fixed)

        _, plain, _ = self.get("/servicos/vulneravel/diagnostico?host=127.0.0.1")
        self.assertIn("0% de perda", plain)

    def test_diagnostic_never_runs_other_commands(self):
        _, body, _ = self.get("/servicos/vulneravel/diagnostico?host=" + quote("127.0.0.1;id;cat /etc/passwd", safe=""))
        self.assertNotIn("uid=", body)
        self.assertNotIn("root:", body)

    def orders(self, variant, value):
        status, body, _ = self.get(f"/servicos/{variant}/pedido?id={quote(value, safe='')}")
        self.assertEqual(status, 200, value)
        return json.loads(body)["pedidos"]

    def test_vulnerable_order_lookup_evaluates_injected_boolean_conditions(self):
        self.assertEqual(len(self.orders("vulneravel", "1")), 1)
        self.assertEqual(len(self.orders("vulneravel", "1' AND '1'='1'-- -")), 1)
        self.assertEqual(self.orders("vulneravel", "1' AND '1'='2'-- -"), [])

    def test_fixed_order_lookup_treats_the_condition_as_plain_data(self):
        self.assertEqual(len(self.orders("corrigido", "1")), 1)
        self.assertEqual(self.orders("corrigido", "1' AND '1'='1'-- -"), [])
        self.assertEqual(self.orders("corrigido", "1' AND '1'='2'-- -"), [])

    def test_injected_extra_statement_never_runs(self):
        self.assertEqual(self.orders("vulneravel", "1'; DELETE FROM pedidos;-- -"), [])
        self.assertEqual(len(self.orders("vulneravel", "1")), 1)

    def test_vulnerable_return_redirects_to_any_destination(self):
        status, _, location = self.get("/servicos/vulneravel/retorno?destino=" + quote("https://egide-ab12cd34.invalid/", safe=""))

        self.assertEqual(status, 302)
        self.assertEqual(location, "https://egide-ab12cd34.invalid/")

    def test_return_survives_a_non_latin1_destination(self):
        for variant in ("vulneravel", "corrigido"):
            status, _, location = self.get(f"/servicos/{variant}/retorno?destino=" + quote("/painel/…", safe=""))

            self.assertEqual(status, 302, variant)
            self.assertTrue(location.isascii(), location)

    def test_fixed_return_only_redirects_inside_the_site(self):
        for destination, expected in (
            ("/corrigido/faturas", "/corrigido/faturas"),
            ("https://egide-ab12cd34.invalid/", "/corrigido/painel"),
            ("//egide-ab12cd34.invalid/", "/corrigido/painel"),
            ("/\\egide-ab12cd34.invalid/", "/corrigido/painel"),
            ("/\t/egide-ab12cd34.invalid/", "/corrigido/painel"),
            ("", "/corrigido/painel"),
        ):
            status, _, location = self.get("/servicos/corrigido/retorno?destino=" + quote(destination, safe=""))

            self.assertEqual(status, 302, destination)
            self.assertEqual(location, expected, destination)

    def test_panel_links_to_the_notes_page_with_the_creation_form(self):
        for variant in ("vulneravel", "corrigido"):
            self.assertIn(f'<a href="/{variant}/notas">Anotações</a>', self.call("GET", f"/{variant}/painel", "a")[1])
            body = self.call("GET", f"/{variant}/notas", "a")[1]
            for fragment in ("Nova anotação", f'action="/{variant}/notas"', 'name="texto"', ">Criar anotação</button>", f"/servicos/{variant}/avisos"):
                self.assertIn(fragment, body)

    def test_owner_creates_reads_and_edits_own_notes_with_sequential_ids(self):
        for variant in ("vulneravel", "corrigido"):
            first, second = self.create_note(variant, "a", "EGIDE-CA-0123456789AB"), self.create_note(variant, "a", "<b>nota</b>")
            self.assertEqual(second, first + 1)
            self.assertRegex(self.call("GET", f"/{variant}/notas/{first}", "a")[1], rf"(?s)EGIDE-CA-0123456789AB.*/servicos/{variant}/notas/{first}\b")
            self.assertIn("&lt;b&gt;nota", self.call("GET", f"/{variant}/notas/{second}", "a")[1])
            self.assertIn(f'href="/{variant}/notas/{first}"', self.call("GET", f"/{variant}/notas", "a")[1])
            self.assertEqual([item["id"] for item in self.notes("GET", variant, actor="a")[1]["notas"]][-2:], [first, second])
            self.assertEqual(self.call("POST", f"/{variant}/notas", "a", form={"texto": " "})[0], 422)
            for verb, payload, expected in (
                ("GET", None, (200, {"id": first, "texto": "EGIDE-CA-0123456789AB"})), ("PUT", {"texto": "nova"}, (200, {"id": first, "texto": "nova"})),
                ("PATCH", {"texto": "outra"}, (200, {"id": first, "texto": "outra"})), ("PATCH", {}, (200, {"id": first, "texto": "outra"})),
                ("PUT", {}, (422, {"erro": "Envie o campo texto"})), ("PATCH", "{x", (400, {"erro": "JSON inválido"})),
                ("DELETE", None, (200, {"ok": True, "removida": first})), ("GET", None, (404, {"erro": "Anotação não encontrada"})),
            ):
                self.assertEqual(self.notes(verb, variant, first, "a", payload), expected, verb)

    def test_vulnerable_api_lets_another_account_read_change_and_delete_a_note(self):
        ident = self.create_note("vulneravel", "a", "EGIDE-CA-0123456789AB")
        self.assertEqual(self.notes("GET", "vulneravel", ident, "b"), (200, {"id": ident, "texto": "EGIDE-CA-0123456789AB"}))
        self.assertNotIn(ident, [item["id"] for item in self.notes("GET", "vulneravel", actor="b")[1]["notas"]])
        self.assertEqual(self.notes("PUT", "vulneravel", ident, "b", {"texto": "EGIDE-CB-0123456789AB"})[0], 200)
        self.assertEqual(self.notes("GET", "vulneravel", ident, "a")[1]["texto"], "EGIDE-CB-0123456789AB")
        self.assertEqual(self.notes("PATCH", "vulneravel", ident, "b", {"texto": "por B"})[1]["texto"], "por B")
        self.assertEqual(self.notes("DELETE", "vulneravel", ident, "b")[0], 200)
        self.assertEqual(self.notes("GET", "vulneravel", ident, "a")[0], 404)

    def test_fixed_api_and_both_note_pages_hide_another_accounts_note(self):
        ident, other = self.create_note("corrigido", "a", "EGIDE-CA-0123456789AB"), self.create_note("vulneravel", "a", "EGIDE-CA-FFFFFFFFFFFF")
        for verb, payload in (("GET", None), ("PUT", {"texto": "x"}), ("PATCH", {"texto": "y"}), ("DELETE", None)):
            self.assertEqual(self.notes(verb, "corrigido", ident, "b", payload), (404, {"erro": "Anotação não encontrada"}), verb)
        self.assertEqual(self.notes("GET", "corrigido", ident, "a"), (200, {"id": ident, "texto": "EGIDE-CA-0123456789AB"}))
        self.assertNotIn("FFFFFFFFFFFF", self.call("GET", f"/servicos/corrigido/notas/{other}", "a")[1])
        pages = [self.call("GET", f"/{variant}/notas/{owned}", "b") for variant, owned in (("vulneravel", other), ("corrigido", ident))]
        self.assertEqual([(page[0], "EGIDE-CA" in page[1]) for page in pages], [(404, False)] * 2)

    def test_notes_and_notices_require_a_session(self):
        for variant in ("vulneravel", "corrigido"):
            ident = self.create_note(variant, "a", "EGIDE-CA-0123456789AB")
            for verb, path in (("GET", f"notas/{ident}"), ("PUT", f"notas/{ident}"), ("PATCH", f"notas/{ident}"), ("DELETE", f"notas/{ident}"), ("GET", "notas"), ("GET", "avisos")):
                status, body, _ = self.call(verb, f"/servicos/{variant}/{path}", payload={"texto": "x"} if verb in ("PUT", "PATCH") else None)
                self.assertEqual((status, "EGIDE-CA" in body), (401, False), verb + path)
            self.assertEqual(self.call("POST", f"/{variant}/notas", form={"texto": "anonima"})[0], 401)
            self.assertEqual(self.call("GET", f"/{variant}/notas/{ident}")[::2], (303, f"/{variant}/entrar"))
            self.assertEqual(self.notes("GET", variant, ident, "a")[1]["texto"], "EGIDE-CA-0123456789AB")

    def test_notices_are_the_same_shared_list_for_both_accounts(self):
        for variant in ("vulneravel", "corrigido"):
            first, second = self.call("GET", f"/servicos/{variant}/avisos", "a"), self.call("GET", f"/servicos/{variant}/avisos", "b")
            self.assertEqual((first, first[0], bool(json.loads(first[1])["avisos"])), (second, 200, True))
            self.assertNotRegex(first[1], r"EGIDE-|egide\.test|EMPRESA")
            self.assertEqual(self.call("DELETE", f"/servicos/{variant}/avisos", "a")[0], 404)

    def test_reset_clears_notes_and_restarts_the_sequence(self):
        ident = self.create_note("vulneravel", "a", "EGIDE-CA-0123456789AB")
        self.lab.reset()
        self.setUp()
        self.assertEqual(self.notes("GET", "vulneravel", ident, "a")[0], 404)
        self.assertEqual(self.notes("GET", "vulneravel", actor="a")[1]["notas"], [])
        self.assertEqual(self.create_note("vulneravel", "b", "nova"), 1)


if __name__ == "__main__":
    unittest.main()
