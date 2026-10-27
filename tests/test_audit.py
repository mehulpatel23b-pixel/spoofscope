import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from fakes import FakeResolver, mx, txt  # noqa: E402
from spoofscope.audit import (  # noqa: E402
    GRADE_ORDER,
    SEVERITY_WEIGHTS,
    audit_domain,
    classify,
    grade_for,
    render_json,
    render_text,
)
from spoofscope.doh import DoHError  # noqa: E402


def zone_for_good_domain():
    return {
        ("locked.example", "TXT"): txt(
            "v=spf1 include:_spf.locked.example -all",
            "MS=ms12345",
        ),
        ("_spf.locked.example", "TXT"): txt("v=spf1 ip4:203.0.113.10 -all"),
        ("_dmarc.locked.example", "TXT"): txt(
            "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc@locked.example"
        ),
        ("google._domainkey.locked.example", "TXT"): txt(
            "v=DKIM1; k=rsa; p=" + "A" * 380
        ),
        ("locked.example", "MX"): [mx(10, "mail.locked.example")],
    }


def zone_for_spoofable_domain():
    return {
        ("open.example", "TXT"): txt("v=spf1 +all"),
        ("_dmarc.open.example", "TXT"): txt("v=DMARC1; p=none; pct=25"),
    }


class TestFullAudit(unittest.TestCase):
    def test_hardened_domain_enforced(self):
        report = audit_domain("locked.example", FakeResolver(zone_for_good_domain()))
        self.assertEqual(report["verdict"], "ENFORCED")
        self.assertEqual(report["dmarc_policy"], "reject")
        self.assertEqual(report["spf_all"], "-all")
        self.assertEqual(report["grade"], "A+" if report["score"] >= 95 else report["grade"])
        self.assertGreaterEqual(report["score"], 95)
        self.assertIn("google", report["dkim_selectors"])

    def test_spoofable_domain_open(self):
        report = audit_domain("open.example", FakeResolver(zone_for_spoofable_domain()))
        self.assertEqual(report["verdict"], "SPOOFABLE")
        self.assertLess(report["score"], 40)
        codes = {f["code"] for f in report["findings"]}
        self.assertIn("spf-open", codes)
        self.assertIn("dmarc-monitor-only", codes)
        self.assertIn("dmarc-pct-partial", codes)

    def test_bare_domain_spoofable(self):
        report = audit_domain("nothing.example", FakeResolver({}))
        self.assertEqual(report["verdict"], "SPOOFABLE")
        self.assertEqual(report["grade"], "F")
        self.assertIn("spf-missing", {f["code"] for f in report["findings"]})
        self.assertIn("dmarc-missing", {f["code"] for f in report["findings"]})
        self.assertIn("dkim-not-found", {f["code"] for f in report["findings"]})
        self.assertIn("mx-none", {f["code"] for f in report["findings"]})

    def test_softfail_with_reject_is_partial(self):
        zone = {
            ("soft.example", "TXT"): txt("v=spf1 ip4:203.0.113.0/24 ~all"),
            ("_dmarc.soft.example", "TXT"): txt("v=DMARC1; p=reject; rua=mailto:a@soft.example"),
        }
        report = audit_domain("soft.example", FakeResolver(zone))
        self.assertEqual(report["verdict"], "PARTIAL")

    def test_quarantine_is_partial(self):
        zone = {
            ("q.example", "TXT"): txt("v=spf1 -all"),
            ("_dmarc.q.example", "TXT"): txt("v=DMARC1; p=quarantine; rua=mailto:q@q.example"),
        }
        report = audit_domain("q.example", FakeResolver(zone))
        self.assertEqual(report["verdict"], "PARTIAL")

    def test_mx_missing_is_info(self):
        zone = {
            ("mxless.example", "TXT"): txt("v=spf1 -all"),
            ("_dmarc.mxless.example", "TXT"): txt("v=DMARC1; p=reject"),
        }
        report = audit_domain("mxless.example", FakeResolver(zone))
        f = [x for x in report["findings"] if x["code"] == "mx-none"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "INFO")

    def test_skips_mx_and_dkim_when_told(self):
        report = audit_domain(
            "locked.example",
            FakeResolver(zone_for_good_domain()),
            probe_dkim_keys=False,
            check_mx=False,
        )
        self.assertEqual(report["queries"], 2)
        self.assertNotIn("mx-none", {f["code"] for f in report["findings"]})

    def test_doh_failure_propagates(self):
        zone = {("down.example", "TXT"): DoHError("DoH endpoint dead")}
        with self.assertRaises(DoHError):
            audit_domain("down.example", FakeResolver(zone))

    def test_overrides_lint_mode(self):
        report = audit_domain(
            "any.example",
            FakeResolver({}),
            spf_override=["v=spf1 +all"],
            dmarc_override=["v=DMARC1; p=none"],
            probe_dkim_keys=False,
            check_mx=False,
        )
        self.assertEqual(report["queries"], 0)
        self.assertEqual(report["verdict"], "SPOOFABLE")


class TestRendering(unittest.TestCase):
    def setUp(self):
        self.good = audit_domain("locked.example", FakeResolver(zone_for_good_domain()))
        self.bad = audit_domain("nothing.example", FakeResolver({}))

    def test_text_render_contains_verdict_and_score(self):
        text = render_text(self.bad, version="0.1.0")
        self.assertIn("verdict: SPOOFABLE", text)
        self.assertIn("score:", text)
        self.assertIn("grade: F", text)
        self.assertIn("fix:", text)

    def test_text_render_findings_all_checks(self):
        text = render_text(self.bad)
        for check in ("SPF", "DMARC", "DKIM", "MX"):
            self.assertIn(check, text)

    def test_json_render_shape(self):
        doc = render_json(self.good)
        for key in ("domain", "verdict", "score", "grade", "findings", "dkim_selectors"):
            self.assertIn(key, doc)
        import json

        json.dumps(doc)

    def test_grade_for_boundaries(self):
        self.assertEqual(grade_for(100), "A+")
        self.assertEqual(grade_for(95), "A+")
        self.assertEqual(grade_for(94), "A")
        self.assertEqual(grade_for(85), "A")
        self.assertEqual(grade_for(70), "B")
        self.assertEqual(grade_for(55), "C")
        self.assertEqual(grade_for(40), "D")
        self.assertEqual(grade_for(39), "F")
        self.assertEqual(grade_for(0), "F")


class TestScoreModel(unittest.TestCase):
    def test_criticals_can_not_be_averaged_away(self):
        self.assertEqual(SEVERITY_WEIGHTS["CRITICAL"], 35)
        self.assertEqual(SEVERITY_WEIGHTS["HIGH"], 20)
        self.assertEqual(SEVERITY_WEIGHTS["WARN"], 8)
        self.assertEqual(SEVERITY_WEIGHTS["INFO"], 0)

    def test_classify_open_flavors(self):
        base = []
        self.assertEqual(classify(base, None, None), "SPOOFABLE")
        self.assertEqual(classify(base, "none", "-all"), "SPOOFABLE")
        self.assertEqual(classify(base, "", ""), "SPOOFABLE")


if __name__ == "__main__":
    unittest.main()
