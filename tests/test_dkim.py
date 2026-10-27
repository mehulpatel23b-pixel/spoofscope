import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from fakes import FakeResolver, txt  # noqa: E402
from spoofscope.dkim import (  # noqa: E402
    DEFAULT_SELECTORS,
    estimate_rsa_bits,
    parse_key_record,
    probe_dkim,
)


def fake_4096_key():
    # 4096/8 = 512 bytes modulus; DER adds ~24 bytes of SPKI overhead.
    return base64.b64encode(b"\x01" * (512 + 24)).decode()


def fake_1024_key():
    return base64.b64encode(b"\x01" * (128 + 24)).decode()


class TestParsing(unittest.TestCase):
    def test_parse_key_record_tags(self):
        tags = parse_key_record("v=DKIM1; k=rsa; p=MIIBIjANBgkq")
        self.assertEqual(tags["v"], "DKIM1")
        self.assertEqual(tags["k"], "rsa")
        self.assertTrue(tags["p"].startswith("MIIB"))

    def test_estimate_bits_needs_length(self):
        big = estimate_rsa_bits(fake_4096_key())
        self.assertGreater(big, 3000)
        self.assertEqual(estimate_rsa_bits(""), None)
        self.assertEqual(estimate_rsa_bits("not base64!"), None)

    def test_estimate_bits_1024(self):
        self.assertLess(estimate_rsa_bits(fake_1024_key()), 1024 + 300)


class TestProbe(unittest.TestCase):
    def test_found_selector_reported(self):
        zone = {("google._domainkey.example.com", "TXT"): txt("v=DKIM1; k=rsa; p=" + fake_4096_key())}
        res = FakeResolver(zone)
        found, findings = probe_dkim("example.com", res, selectors=["google"])
        self.assertEqual(found[0][0], "google")
        self.assertEqual(findings, [])

    def test_none_found_warn(self):
        res = FakeResolver({})
        found, findings = probe_dkim("example.com", res, selectors=["default", "google"])
        self.assertEqual(found, [])
        self.assertEqual(findings[0]["code"], "dkim-not-found")
        self.assertEqual(findings[0]["severity"], "WARN")

    def test_one_revoked_key_single_info(self):
        zone = {("google._domainkey.example.com", "TXT"): txt("v=DKIM1; k=rsa; p=")}
        _, findings = probe_dkim("example.com", FakeResolver(zone), selectors=["google"])
        revoked = [f for f in findings if f["code"] == "dkim-key-revoked"]
        self.assertEqual(len(revoked), 1)
        self.assertIn("google", revoked[0]["message"])
        self.assertEqual(revoked[0]["severity"], "INFO")

    def test_wildcard_revoked_keys_consolidated(self):
        # Reserved domains publish `v=DKIM1; p=` on every selector via a
        # wildcard; 16 identical findings would drown the report.
        zone = {
            ("%s._domainkey.example.com" % s, "TXT"): txt("v=DKIM1; k=rsa; p=")
            for s in DEFAULT_SELECTORS
        }
        _, findings = probe_dkim("example.com", FakeResolver(zone), selectors=None)
        revoked = [f for f in findings if f["code"] == "dkim-key-revoked"]
        self.assertEqual(len(revoked), 1)
        self.assertIn("wildcard", revoked[0]["message"])
        self.assertEqual(revoked[0]["severity"], "INFO")

    def test_weak_key_high(self):
        tiny = fake_1024_key()
        zone = {("default._domainkey.example.com", "TXT"): txt("v=DKIM1; k=rsa; p=" + tiny)}
        _, findings = probe_dkim("example.com", FakeResolver(zone), selectors=["default"])
        self.assertIn("dkim-weak-key", {f["code"] for f in findings})
        f = [x for x in findings if x["code"] == "dkim-weak-key"][0]
        self.assertEqual(f["severity"], "HIGH")
        self.assertIn("default", f["message"])

    def test_trivial_key_consolidated_critical(self):
        tiny_512 = base64.b64encode(b"\x01" * (64 + 24)).decode()
        zone = {
            ("%s._domainkey.example.com" % s, "TXT"): txt("v=DKIM1; k=rsa; p=" + tiny_512)
            for s in ("default", "google", "k1")
        }
        _, findings = probe_dkim("example.com", FakeResolver(zone), selectors=["default", "google", "k1", "mail"])
        trivial = [f for f in findings if f["code"] == "dkim-trivial-key"]
        self.assertEqual(len(trivial), 1)
        self.assertEqual(trivial[0]["severity"], "CRITICAL")

    def test_dns_failure_on_one_selector_does_not_kill_audit(self):
        class Flaky(FakeResolver):
            def query(self, name, rrtype="TXT"):
                if name.startswith(" deported"):
                    raise OSError("boom")
                return []

        found, findings = probe_dkim("example.com", Flaky({}), selectors=["deported", "google"])
        self.assertEqual(found, [])
        self.assertEqual(findings[0]["code"], "dkim-not-found")

    def test_default_selectors_nonempty(self):
        self.assertGreater(len(DEFAULT_SELECTORS), 10)


if __name__ == "__main__":
    unittest.main()
