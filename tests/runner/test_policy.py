import importlib.util
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path

RUNNER = Path(__file__).resolve().parents[2] / "runner"


class Headers:
    def __init__(self, values):
        self.values = {key.lower(): value for key, value in values.items()}

    def get(self, name, default=None):
        return self.values.get(name.lower(), default)

    def get_all(self, name):
        value = self.values.get(name.lower())
        return [value] if value else []


def flow(status, headers):
    return types.SimpleNamespace(
        request=types.SimpleNamespace(method="GET", pretty_host="app.example.com", path="/retorno?destino=x", scheme="https"),
        response=types.SimpleNamespace(status_code=status, headers=Headers(headers)),
        metadata={"scheme": "https"},
    )


class PolicyRedirectTest(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        (self.folder / "policy.json").write_text(json.dumps({
            "host": "app.example.com", "hosts": ["app.example.com"], "port": 443, "scheme": "https",
            "rules": [], "denied": [], "budget": 80, "lab": False,
        }))
        os.environ["EGIDE_POLICY"] = str(self.folder / "policy.json")
        os.environ["EGIDE_EVENTS"] = str(self.folder / "events.ndjson")
        mitmproxy = types.ModuleType("mitmproxy")
        mitmproxy.http = types.ModuleType("mitmproxy.http")
        sys.modules["mitmproxy"] = mitmproxy
        sys.modules["mitmproxy.http"] = mitmproxy.http
        spec = importlib.util.spec_from_file_location("egide_policy_under_test", RUNNER / "policy.py")
        self.policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.policy)

    def tearDown(self):
        sys.modules.pop("mitmproxy", None)
        sys.modules.pop("mitmproxy.http", None)
        shutil.rmtree(self.folder, ignore_errors=True)

    def last_event(self):
        return json.loads((self.folder / "events.ndjson").read_text().splitlines()[-1])

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


if __name__ == "__main__":
    unittest.main()
