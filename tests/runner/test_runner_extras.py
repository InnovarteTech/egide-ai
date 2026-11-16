import asyncio
import http.client
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_policy import OPEN_RULES, RUNNER, PolicyCase, outgoing

sys.path.insert(0, str(RUNNER))

import guard

MARKER = "EGIDE-CA-0123456789AB"


class AutomaticHaltTest(PolicyCase):
    def signals(self):
        self.now = [100.0]
        return guard.Signals(clock=lambda: self.now[0])

    def feed(self, signals, times, status, headers=None, ms=50, path="/api/notas", method="POST", probe=False):
        return [signals.feed(status, headers or {}, ms, path, method, probe) for _ in range(times)]

    def test_5xx_rate_needs_15_samples_and_35_percent(self):
        signals = self.signals()
        self.assertEqual(set(self.feed(signals, 13, 200) + self.feed(signals, 6, 503)), {None})

        self.assertEqual(signals.feed(500, {}, 50, "/x"), "Taxa de erros 5xx alta no alvo")
        self.assertEqual(set(self.feed(self.signals(), 14, 503)), {None})
        probed = self.signals()
        self.assertEqual(set(self.feed(probed, 40, 500, probe=True) + self.feed(probed, 14, 500)), {None})
        self.assertEqual(self.feed(probed, 1, 500), ["Taxa de erros 5xx alta no alvo"])

    def test_429_backs_off_and_halts_after_ten_in_the_window(self):
        signals = self.signals()
        waits = []
        for _ in range(5):
            signals.feed(429, {}, 50, "/x")
            waits.append(signals.wait(self.now[0]))
        signals.feed(200, {}, 50, "/x")
        self.assertEqual(waits, [2, 4, 8, 16, 16])
        signals.feed(429, {}, 50, "/x")
        self.assertEqual(signals.wait(self.now[0] + 0.5), 1.5)

        self.assertEqual(self.feed(signals, 4, 429)[-1], "Limite de taxa do alvo atingido repetidamente")

    def test_waf_blocks_are_recognised_by_their_headers(self):
        signals = self.signals()
        self.feed(signals, 3, 403)
        self.feed(signals, 2, 200, {"cf-mitigated": "challenge"})
        blocks = [(403, {"cf-mitigated": "challenge"}), (406, {"x-sucuri-id": "1"}),
                  (429, {"x-amzn-waf-action": "block"}), (403, {"server": "AkamaiGHost"})]
        self.assertEqual({signals.feed(status, headers, 50, "/x") for status, headers in blocks}, {None})

        self.assertEqual(signals.feed(403, {"server": "AkamaiGHost/1"}, 50, "/x"), "Bloqueio de WAF detectado")

    def test_login_failures_must_be_consecutive_posts_to_login_routes(self):
        signals = self.signals()
        self.feed(signals, 7, 401, path="/api/login")
        signals.feed(200, {}, 50, "/api/login", "POST")
        noise = (self.feed(signals, 7, 401, path="/auth/entrar") + self.feed(signals, 3, 200)
                 + self.feed(signals, 9, 401, path="/api/login", method="GET") + self.feed(signals, 9, 401, path="/api/login", probe=True)
                 + self.feed(signals, 9, 403, path="/api/authors") + self.feed(signals, 9, 401, path="/api/tokens", method="GET"))
        self.assertEqual(set(noise), {None})

        self.assertEqual(signals.feed(403, {}, 50, "/oauth/token", "POST"),
                         "Falhas de login em série (risco de bloquear a conta de teste)")

    def test_latency_uses_the_median_of_the_last_15(self):
        signals = self.signals()
        self.assertEqual(set(self.feed(signals, 8, 200, ms=100) + self.feed(signals, 7, 200, ms=16000)), {None})

        self.assertEqual(self.feed(signals, 1, 200, ms=16000), ["Latência alta no alvo"])
        self.assertEqual(set(self.feed(self.signals(), 14, 200, ms=90000)), {None})

    def test_halt_file_pauses_every_request_even_in_the_lab(self):
        self.load(rules=OPEN_RULES, lab=True)
        (self.folder / "halt.json").write_text(json.dumps({"reason": "Latência alta no alvo", "at": 1}))

        self.assertEqual(self.send("GET", "/").response.status_code, 403)
        self.assertEqual(self.last_event()["reason"], "Sessão pausada por sinal de dano")
        tunnel = outgoing("CONNECT", "")
        self.policy.http_connect(tunnel)
        self.assertEqual(tunnel.response.status_code, 403)

    def test_server_errors_through_the_proxy_write_halt_and_block(self):
        self.load(rules=OPEN_RULES)
        for _ in range(30):
            self.answered(self.send("GET", "/api/relatorio", headers={"X-Egide-Probe": "1"}), 500, {}, b"")
        self.assertFalse((self.folder / "halt.json").exists())
        for _ in range(15):
            self.answered(self.send("GET", "/api/relatorio"), 503, {}, b"")

        saved = json.loads((self.folder / "halt.json").read_text())
        self.assertEqual(saved["reason"], "Taxa de erros 5xx alta no alvo")
        self.assertIsInstance(saved["at"], int)
        self.assertEqual(self.send("GET", "/").response.status_code, 403)
        self.assertEqual(self.last_event()["reason"], "Sessão pausada por sinal de dano")

    def test_lab_never_halts_or_paces(self):
        self.load(rules=OPEN_RULES, lab=True, max_rps=1)
        for _ in range(40):
            self.answered(self.send("GET", "/api/relatorio"), 500, {}, b"")

        self.assertFalse((self.folder / "halt.json").exists())
        self.assertIsNone(self.policy.request(outgoing("GET", "/")))

    def test_max_rps_and_backoff_set_the_pace(self):
        self.load(rules=OPEN_RULES, max_rps=2)
        brakes = self.policy.brakes
        self.assertEqual([brakes.pace("app.example.com", 100.0) for _ in range(3)], [0, 0.5, 1.0])

        brakes.signals["app.example.com"] = self.signals()
        brakes.signals["app.example.com"].feed(429, {}, 50, "/x")
        self.assertEqual(brakes.pace("app.example.com", 100.0), 2.0)

    def test_paced_request_waits_and_is_refused_if_halted_meanwhile(self):
        self.load(rules=OPEN_RULES, max_rps=1)
        self.assertIsNone(self.policy.request(outgoing("GET", "/a")))
        waiting = outgoing("GET", "/b")
        pending = self.policy.request(waiting)
        slept = []

        async def fake_sleep(seconds):
            slept.append(seconds)
            (self.folder / "halt.json").write_text("{}")

        with mock.patch.object(self.policy.asyncio, "sleep", fake_sleep):
            asyncio.run(pending)

        self.assertEqual(len(slept), 1)
        self.assertGreater(slept[0], 0.5)
        self.assertEqual(waiting.response.status_code, 403)

    def test_find_markers_and_shape_are_pure(self):
        find, shape = guard.find_markers, guard.shape_of

        self.assertEqual(find(f"a EGIDE-CB-ABCDEF012345 b {MARKER} {MARKER}"), [MARKER, "EGIDE-CB-ABCDEF012345"])
        self.assertEqual(find("EGIDE-CA-0123456789ABCD EGIDE-CC-0123456789AB egide-ca-0123456789ab"), [])
        self.assertEqual(find("t ESCOPO-AAAA0000BBBB1111", ["ESCOPO-AAAA0000BBBB1111", "EGIDE-FFFF"]), ["ESCOPO-AAAA0000BBBB1111"])
        cases = (
            ("application/json", '{"b": 1, "a": {"z": 2}}', "json:a,b"),
            ("application/json", '[{"id": 1, "nome": "x"}, {"outro": 1}]', "json:list:id,nome"),
            ("application/json", "[]", "json:list:"), ("application/json", '"texto"', "json:scalar"),
            ("application/json", "null", "json:scalar"), ("", '{"ok": true}', "json:ok"),
            ("application/json", "{quebrado", "text"), ("text/html", "<p>oi</p>", "html"),
            ("text/plain", "oi", "text"), ("image/png", "\x89PNG", ""), ("application/json", "", ""),
        )
        for ctype, text, expected in cases:
            self.assertEqual(shape(ctype, text), expected, (ctype, text))


class ExternalEffectTokensTest(PolicyCase):
    def test_external_effect_uses_tokens_and_auth_only_neutralises_mail(self):
        external = (
            "/api/emails", "/conta/e-mail", "/api/sendEmail", "/v2/sms/enviar", "/api/pay", "/checkout", "/api/notificacoes",
            "/financeiro/cobrança", "/pagamentos/9", "/api/Users/Invites", "/convites", "/mensagens", "/webhooks/1",
            "/subscriptions", "/transferencias", "/assinaturas", "/whatsapp", "/auth/send-sms-code", "/api/token/send",
            "/logon/sms", "/auth/password/reset", "/auth/email/forgot", "/login/recuperar-senha", "/session/reset",
            "/conta/recover", "/account/forgot-password",
        )
        harmless = (
            "/api/payloads", "/pixels", "/display", "/api/mailbox-rules", "/api/repay-plans", "/sender-profile",
            "/api/notas", "/api/recharged", "/payroll", "/discharge", "/auth/email/login", "/api/sessions",
            "/oauth/callback/email", "/entrar", "/users/signin", "/auth/password", "/api/password", "/conta/senha",
            "/esqueci/recuperar", "/api/filtros/reset",
        )
        for path in external:
            self.assertTrue(guard.external(path), path)
        for path in harmless:
            self.assertFalse(guard.external(path), path)

    def test_large_bodies_are_only_scanned_at_the_start(self):
        late = b'{"a": "' + b"x" * (600 * 1024) + b'EGIDE-CA-0123456789AB"}'
        details = guard.describe(late, {"content-type": "application/json"}, 5)
        self.assertEqual((details["shape"], details["markers"], details["size"]), ("json", [], len(late)))
        request = outgoing("POST", "/a", body=b"x" * (64 * 1024) + MARKER.encode()).request
        self.assertEqual(guard.sent_markers(request), [])
        self.assertEqual(guard.sent_markers(outgoing("POST", "/a", body=b"x" * 1000 + MARKER.encode()).request), [MARKER])

    def test_login_works_in_mapping_mode_and_reset_stays_blocked(self):
        self.load(rules=OPEN_RULES, safety="mapeamento")

        self.assertIsNone(self.send("POST", "/auth/email/login").response)
        self.assertIsNone(self.send("POST", "/api/payloads").response)
        self.assertEqual(self.send("POST", "/auth/password/reset").response.status_code, 403)
        self.assertEqual(self.last_event()["acao"], "efeito_externo")
        self.assertEqual(self.send("POST", "/api/emails").response.status_code, 403)
        self.assertEqual(self.send("POST", "/auth/send-sms-code").response.status_code, 403)


class RunnerServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["EGIDE_RUNNER_TOKEN"] = "t" * 40
        sys.path.insert(0, str(RUNNER))
        spec = importlib.util.spec_from_file_location("egide_server_under_test", RUNNER / "server.py")
        cls.server = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.server)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), cls.server.Handler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.server.WORK, ignore_errors=True)

    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(dir=self.server.WORK))
        self.server.SESSION = {"id": "sessao-1", "dir": self.folder, "events": self.folder / "events.ndjson",
                               "last": time.monotonic(), "actor": "a", "url": "https://app.example.com/",
                               "urls": {}, "bases": {}, "api": None, "offset": 0, "lab": False}

    def tearDown(self):
        self.server.SESSION = None

    def call(self, path, payload, token=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=5)
        try:
            connection.request("POST", path, body=json.dumps({"id": "sessao-1", **payload}), headers={
                "Authorization": "Bearer " + (token or self.server.RUNNER_TOKEN), "Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_new_routes_require_the_token_and_the_active_session(self):
        for route in ("/canary", "/traffic"):
            self.assertEqual(self.call(route, {}, token="x" * 40)[0], 403)
            self.assertEqual(self.call(route, {"id": "outra"}), (422, {"error": "Sessão do executor indisponível"}))

    def test_canary_is_persisted_deduplicated_and_counted(self):
        entry = {"actor": "a", "path": "/api/notas/7", "marker": MARKER, "method": "POST", "object_id": "7"}

        self.assertEqual(self.call("/canary", entry), (200, {"ok": True, "count": 1}))
        self.assertEqual(self.call("/canary", entry), (200, {"ok": True, "count": 1}))
        self.assertEqual(self.call("/canary", {**entry, "actor": "b", "marker": "EGIDE-CB-AAAAAAAAAAAA", "object_id": None})[1]["count"], 2)
        saved = json.loads((self.folder / "canaries.json").read_text())
        self.assertEqual(saved[0], entry)

    def test_canary_rejects_invalid_input_and_caps_at_200(self):
        entry = {"actor": "a", "path": "/api/notas/7", "marker": MARKER, "method": "POST", "object_id": None}
        for change in ({"actor": "c"}, {"path": "api/notas"}, {"path": "/"}, {"path": "/a/../b"}, {"path": "/a?x=1"},
                       {"path": "//evil"}, {"marker": "EGIDE-CA-0123"}, {"marker": "EGIDE-CB-0123456789AB"},
                       {"method": "GET"}, {"object_id": "1 OR 1=1"}, {"object_id": True}):
            self.assertEqual(self.call("/canary", {**entry, **change})[0], 422, change)
        self.assertFalse((self.folder / "canaries.json").exists())

        (self.folder / "canaries.json").write_text(json.dumps([{**entry, "path": f"/n/{i}"} for i in range(200)]))
        self.assertEqual(self.call("/canary", entry)[0], 422)

    def test_traffic_pages_complete_lines_from_an_index(self):
        lines = [json.dumps({"path": f"/n/{i}", "status": 200}) for i in range(2500)]
        lines[3] = json.dumps({"path": "/vulneravel/confirmar/" + "a" * 32})
        (self.folder / "events.ndjson").write_text("\n".join(lines) + "\n{\"path\": \"/parci")

        status, first = self.call("/traffic", {"since": 0})
        _, rest = self.call("/traffic", {"since": first["next"]})
        _, beyond = self.call("/traffic", {"since": 99999})

        self.assertEqual((status, len(first["events"]), first["next"]), (200, 2000, 2000))
        self.assertEqual(first["events"][3]["path"], "/vulneravel/confirmar/[token]")
        self.assertEqual((len(rest["events"]), rest["next"], rest["events"][-1]["path"]), (500, 2500, "/n/2499"))
        self.assertEqual(beyond, {"events": [], "next": 2500})
        for since in (-1, "0", True, None):
            self.assertEqual(self.call("/traffic", {"since": since})[0], 422, since)

    def test_traffic_keeps_up_with_appended_events_and_redacts_locations(self):
        events = self.folder / "events.ndjson"
        events.write_text(json.dumps({"path": "/a"}) + "\n" + "{quebrado\n" + "{\"path\": \"/b")
        self.assertEqual(self.call("/traffic", {"since": 0})[1], {"events": [{"path": "/a"}], "next": 2})

        with events.open("a") as output:
            output.write("\"}\n" + json.dumps({"path": "/c", "location": "/conta/confirmar/" + "b" * 32}) + "\n")
        _, page = self.call("/traffic", {"since": 2})

        self.assertEqual(page, {"events": [{"path": "/b"}, {"path": "/c", "location": "/conta/confirmar/[token]"}], "next": 4})
        self.assertEqual(self.call("/traffic", {"since": 1})[1]["next"], 4)

    def test_observe_and_probe_report_the_halt(self):
        with mock.patch.object(self.server, "settled_snapshot", return_value={"path": "/"}), \
                mock.patch.object(self.server, "bridge_call", return_value={"status": 200}):
            self.assertIsNone(self.call("/observe", {"frame": False})[1]["halt"])
            (self.folder / "halt.json").write_text(json.dumps({"reason": "Bloqueio de WAF detectado", "at": 1700000000}))
            expected = {"reason": "Bloqueio de WAF detectado", "at": 1700000000}

            self.assertEqual(self.call("/observe", {"frame": False})[1]["halt"], expected)
            self.assertEqual(self.call("/probe", {"path": "/api/notas"})[1], {"status": 200, "halt": expected})

    def test_safety_options_are_validated(self):
        options = self.server.safety_options
        self.assertEqual(options({}, True)["safety"], "lab")
        self.assertEqual(options({"accounts": []}, False), {
            "safety": "livre", "approved_writes": [], "session_tag": None, "max_rps": None, "markers": []})
        good = {"safety": "canario", "session_tag": "scan-1", "max_rps": 2.5,
                "approved_writes": [{"method": "POST", "path": "/api/convites", "prefix": False}],
                "accounts": {"a": {"marker": "EGIDE-00112233445566AA"}, "b": {"marker": "<script>"}}}
        self.assertEqual(options(good, False), {**{k: v for k, v in good.items() if k != "accounts"}, "markers": ["EGIDE-00112233445566AA"]})
        for change in ({"safety": "lab"}, {"safety": "turbo"}, {"session_tag": "a b"}, {"session_tag": "x" * 41},
                       {"max_rps": 0}, {"max_rps": "2"}, {"max_rps": True}, {"max_rps": 1000},
                       {"approved_writes": {"method": "POST"}}, {"approved_writes": [{"method": "GET", "path": "/a"}]},
                       {"approved_writes": [{"method": "POST", "path": "/", "prefix": True}]},
                       {"approved_writes": [{"method": "POST", "path": "/a/../b"}]}):
            with self.assertRaises(ValueError, msg=change):
                options({**good, **change}, False)

    def test_start_writes_the_safety_options_into_the_policy(self):
        self.server.SESSION = None
        self.server.CA.mkdir(exist_ok=True)
        (self.server.CA / "mitmproxy-ca-cert.pem").write_text("ca")
        data = {"id": "sessao-2", "url": "https://app.example.com/", "lab": False, "rules": OPEN_RULES, "denied": [],
                "budget": 40, "safety": "mapeamento", "session_tag": "egide-7", "max_rps": 3,
                "approved_writes": [{"method": "POST", "path": "/api/convites", "prefix": True}]}
        with mock.patch("subprocess.Popen"), mock.patch.object(self.server, "firefox"):
            self.server.start(data)
        policy = json.loads((self.server.SESSION["dir"] / "scope.json").read_text())
        self.server.close()

        self.assertEqual({key: policy[key] for key in ("safety", "session_tag", "max_rps", "approved_writes", "markers")},
                         {"safety": "mapeamento", "session_tag": "egide-7", "max_rps": 3.0, "markers": [],
                          "approved_writes": [{"method": "POST", "path": "/api/convites", "prefix": True}]})


if __name__ == "__main__":
    unittest.main()
