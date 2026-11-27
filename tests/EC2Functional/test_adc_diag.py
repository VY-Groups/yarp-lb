import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[2] / "control-center/tools/adc_diag.py"
SPEC = importlib.util.spec_from_file_location("adc_diag", PATH)
adc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adc)


class Fake:
    def __init__(self, otp=False, accepted=False):
        self.calls = []
        self.otp = otp
        self.accepted = accepted
        self.cleared = False

    def request(self, name, payload=None, csrf=None):
        self.calls.append((name, payload, csrf))
        if name == "login":
            return {"otpRequired": True, "challengeId": "a"*48} if self.otp else {"authenticated": True}
        if name == "login/verify":
            return {"authenticated": True}
        if name == "session":
            return {"authenticated": True, "csrf": "secret", "privacyAccepted": self.accepted,
                    "privacyText": "Example notice", "privacyVersion": "a"*64}
        if name == "privacy/accept":
            return {"accepted": True, "version": "a"*64}
        if name == "state":
            return {k: {"private-origin": "secret"} for k in
                    ("routes", "clusters", "disabled", "monitorProfiles", "realServers", "serviceGroups")}
        if name == "metrics":
            return {"totalRequests": 10, "success2xx": 8, "clientErrors4xx": 1,
                    "serverErrors5xx": 1, "meanDurationMs": 2.5}
        if name == "virtual-servers":
            return {"services": [{"address": "private"}]}
        if name == "logout":
            return {"loggedOut": True}
        raise AssertionError(name)

    def clear(self):
        self.cleared = True


class DiagnosticsTests(unittest.TestCase):
    def test_origin(self):
        self.assertEqual(adc.origin("https://example.test:8443/"), "https://example.test:8443")
        for invalid in ("http://example.test", "https://user@example.test", "https://example.test/a",
                        "https://example.test/?token=x", "https://example.test/#x", "https://example.test:99999", "https://example.test:0",
                        "https://example.test\n", "https://example.test\\evil"):
            with self.subTest(invalid=invalid), self.assertRaises(adc.DiagnosticError):
                adc.origin(invalid)

    def test_otp_acceptance_and_redaction(self):
        client = Fake(otp=True)
        report = adc.collect(client, "operator", "secret", "directory", prompt=lambda _: "ACCEPT",
                             secret=lambda _: "123456", notice=lambda _: None)
        self.assertEqual([x[0] for x in client.calls], ["login", "login/verify", "session",
                         "privacy/accept", "state", "metrics", "virtual-servers", "logout"])
        self.assertEqual(client.calls[3][2], "secret")
        self.assertEqual(client.calls[-1][2], "secret")
        self.assertEqual(report["inventory"]["virtualServices"], 1)
        self.assertEqual(report["localCounters"]["serverErrors5xx"], 1)
        self.assertNotIn("secret", str(report))
        self.assertNotIn("private", str(report))
        self.assertTrue(client.cleared)

    def test_decline_no_diagnostics(self):
        client = Fake()
        with self.assertRaises(adc.DiagnosticError):
            adc.collect(client, "operator", "secret", "local", prompt=lambda _: "NO", notice=lambda _: None)
        self.assertEqual([x[0] for x in client.calls], ["login", "session", "logout"])
        self.assertTrue(client.cleared)

    def test_existing_acceptance(self):
        client = Fake(accepted=True)
        adc.collect(client, "operator", "secret", "local")
        self.assertNotIn("privacy/accept", [x[0] for x in client.calls])

    def test_redirect_refusal(self):
        with self.assertRaises(adc.DiagnosticError):
            adc.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.test/")

    def test_reject_malformed_metrics(self):
        with self.assertRaises(adc.DiagnosticError):
            adc.number({"totalRequests": True}, "totalRequests")
        with self.assertRaises(adc.DiagnosticError):
            adc.number({"meanDurationMs": float("nan")}, "meanDurationMs", False)


if __name__ == "__main__":
    unittest.main()
