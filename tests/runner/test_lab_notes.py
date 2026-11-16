import http.client
import importlib.util
import json
import re
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

RUNNER = Path(__file__).resolve().parents[2] / "runner"


class LabNotesLockTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(RUNNER))
        spec = importlib.util.spec_from_file_location("egide_lab_notes_under_test", RUNNER / "lab.py")
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

    def call(self, verb, path, actor="a", payload=None, form=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        body = urlencode(form) if form else None if payload is None else json.dumps(payload)
        headers = {"Cookie": f"lab_session=sessao-{actor}", "Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
        try:
            connection.request(verb, path, body=None if body is None else body.encode(), headers=headers)
            response = connection.getresponse()
            return response.status, response.read().decode(), response.getheader("Location")
        finally:
            connection.close()

    def create_note(self, variant, texto):
        status, _, location = self.call("POST", f"/{variant}/notas", form={"texto": texto})
        self.assertEqual(status, 303)
        return int(re.fullmatch(rf"/{variant}/notas/(\d+)", location).group(1))

    def blocked_while_locked(self, verb, path, actor="a", payload=None):
        results = []
        with self.lab.lab_services._STATE_LOCK:
            worker = threading.Thread(target=lambda: results.append(self.call(verb, path, actor, payload)))
            worker.start()
            worker.join(0.3)
            blocked = worker.is_alive()
        worker.join(5)
        return blocked, results[0]

    def test_note_api_reads_and_writes_wait_for_the_state_lock(self):
        for variant in ("vulneravel", "corrigido"):
            ident = self.create_note(variant, "EGIDE-CA-0123456789AB")
            for verb, payload, expected in (("GET", None, "EGIDE-CA-0123456789AB"), ("PUT", {"texto": "nova"}, "nova"),
                                            ("PATCH", {"texto": "outra"}, "outra"), ("DELETE", None, "removida")):
                blocked, (status, body, _) = self.blocked_while_locked(verb, f"/servicos/{variant}/notas/{ident}", payload=payload)
                self.assertEqual((blocked, status), (True, 200), f"{variant} {verb}")
                self.assertIn(expected, body, f"{variant} {verb}")
            blocked, (status, body, _) = self.blocked_while_locked("GET", f"/servicos/{variant}/notas")
            self.assertEqual((blocked, status, ident in [item["id"] for item in json.loads(body)["notas"]]), (True, 200, False), variant)

    def test_note_pages_read_under_the_state_lock(self):
        ident = self.create_note("corrigido", "EGIDE-CA-0123456789AB")
        for path, expected in (("/corrigido/notas", f'href="/corrigido/notas/{ident}"'), (f"/corrigido/notas/{ident}", "EGIDE-CA-0123456789AB")):
            blocked, (status, body, _) = self.blocked_while_locked("GET", path)
            self.assertEqual((blocked, status), (True, 200), path)
            self.assertIn(expected, body, path)

    def test_concurrent_writes_keep_ids_unique_and_answers_consistent(self):
        ident = self.create_note("vulneravel", "EGIDE-CA-0123456789AB")
        results, workers = [], []
        for number in range(12):
            verb, payload = ("PATCH", {"texto": f"versao {number}"}) if number % 3 else ("DELETE", None)
            workers.append(threading.Thread(target=lambda v=verb, p=payload: results.append(self.call(v, f"/servicos/vulneravel/notas/{ident}", "b", p))))
            workers.append(threading.Thread(target=lambda n=number: results.append(self.call("POST", "/vulneravel/notas", form={"texto": f"nota {n}"}))))
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)
        created = [int(location.rsplit("/", 1)[1]) for status, _, location in results if status == 303]
        self.assertEqual(sorted(created), list(range(ident + 1, ident + 13)))
        deleted = [body for status, body, _ in results if status == 200 and "removida" in body]
        self.assertEqual(len(deleted), 1)
        for status, body, _ in results:
            self.assertIn(status, (200, 303, 404))
            if status == 200 and "texto" in body:
                self.assertRegex(json.loads(body)["texto"], r"^versao \d+$")


if __name__ == "__main__":
    unittest.main()
