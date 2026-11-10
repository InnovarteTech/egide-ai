import http.client
import importlib.util
import json
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

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

    def get(self, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, response.read().decode(), response.getheader("Location")
        finally:
            connection.close()

    def post_json(self, path, payload):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        try:
            body = json.dumps(payload)
            connection.request("POST", path, body=body, headers={"Content-Type": "application/json", "Content-Length": str(len(body))})
            response = connection.getresponse()
            return response.status, response.read().decode()
        finally:
            connection.close()

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


if __name__ == "__main__":
    unittest.main()
