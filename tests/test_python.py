import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

import discord_relay  # noqa: E402
from railwatch_verify import InvalidSignature, SeenDeliveries, parse_verified, verify_signature  # noqa: E402

BODY = (ROOT / "fixtures" / "delivery.body.json").read_bytes()
META = json.loads((ROOT / "fixtures" / "delivery.meta.json").read_text())
SECRET = META["secret"]
SIG = META["headers"]["X-RailWatch-Signature"]
DID = META["headers"]["X-RailWatch-Delivery-Id"]


class VerifyTests(unittest.TestCase):
    def test_fixture_from_production_signer_verifies(self):
        self.assertTrue(verify_signature(SECRET, BODY, SIG))
        env = parse_verified(SECRET, BODY, SIG)
        self.assertEqual(env["delivery_id"], DID)
        self.assertEqual(env["events"][0]["title"], "Café Lofts, 2BR — East Austin")

    def test_reserialised_json_does_not_verify(self):
        # Why the raw body matters: parse + dump changes the bytes.
        reser = json.dumps(json.loads(BODY), ensure_ascii=False).encode("utf-8")
        self.assertNotEqual(reser, BODY)
        self.assertFalse(verify_signature(SECRET, reser, SIG))

    def test_rejects_wrong_secret_tamper_and_missing(self):
        self.assertFalse(verify_signature("other", BODY, SIG))
        self.assertFalse(verify_signature(SECRET, BODY.replace(b"1799.0", b"1.0"), SIG))
        self.assertFalse(verify_signature(SECRET, BODY, None))
        self.assertFalse(verify_signature("", BODY, SIG))
        self.assertFalse(verify_signature(SECRET, BODY, "sha256=" + "0" * 64))
        with self.assertRaises(InvalidSignature):
            parse_verified(SECRET, BODY, "sha256=bad")

    def test_idempotency(self):
        seen = SeenDeliveries(limit=2)
        self.assertTrue(seen.first_time("a"))
        self.assertFalse(seen.first_time("a"))
        seen.first_time("b")
        seen.first_time("c")
        self.assertTrue(seen.first_time("a"))  # evicted, oldest first

    def test_discord_message_has_no_mentions_and_fits(self):
        msg = discord_relay.discord_message(json.loads(BODY))
        self.assertEqual(msg["allowed_mentions"], {"parse": []})
        self.assertLessEqual(len(msg["content"]), 2000)
        self.assertIn("price_drop", msg["content"])
        self.assertIn("https://www.zumper.com/apartment-buildings/p12345", msg["content"])


class RelayE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sent = []
        discord_relay.Handler.secret = SECRET
        discord_relay.Handler.discord_url = "https://discord.invalid/hook"
        discord_relay.Handler.sender = staticmethod(lambda url, payload: cls.sent.append(payload) or 204)
        discord_relay.Handler.log_message = lambda *a, **k: None
        cls.httpd = HTTPServer(("127.0.0.1", 0), discord_relay.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def post(self, body, sig, did):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/railwatch", data=body, method="POST",
            headers={"Content-Type": "application/json", "X-RailWatch-Signature": sig, "X-RailWatch-Delivery-Id": did},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_valid_then_duplicate_then_bad(self):
        self.assertEqual(self.post(BODY, SIG, "dlv_e2e_1"), (200, "ok"))
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.post(BODY, SIG, "dlv_e2e_1"), (200, "duplicate ignored"))
        # a replay with a changed (unsigned) header id is still a duplicate
        self.assertEqual(self.post(BODY, SIG, "dlv_other_header"), (200, "duplicate ignored"))
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.post(BODY, "sha256=" + "0" * 64, "dlv_e2e_2")[0], 401)
        self.assertEqual(len(self.sent), 1)


if __name__ == "__main__":
    unittest.main()
