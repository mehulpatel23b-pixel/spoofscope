import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from fakes import txt  # noqa: E402
from spoofscope.dmarc import (  # noqa: E402
    audit_dmarc,
    find_dmarc_records,
    parse_tags,
)


def codes(findings):
    return {f["code"] for f in findings}


class TestFindRecords(unittest.TestCase):
    def test_extracts_dmarc(self):
        records = find_dmarc_records(txt("v=DMARC1; p=reject; rua=mailto:a@b.com"))
        self.assertEqual(records[0].startswith("v=DMARC1"), True)

    def test_lowercase_variant_found(self):
        self.assertEqual(len(find_dmarc_records(txt("v=dmarc1;p=none"))), 1)

    def test_non_dmarc_txt_ignored(self):
        self.assertEqual(find_dmarc_records(txt("v=spf1 -all", "hosting-verify=x")), [])


class TestParseTags(unittest.TestCase):
    def test_basic_tags(self):
        tags, problems = parse_tags("v=DMARC1; p=reject; pct=50; rua=mailto:a@b.com; sp=quarantine")
        self.assertEqual(tags["p"], "reject")
        self.assertEqual(tags["pct"], "50")
        self.assertEqual(tags["rua"], "mailto:a@b.com")
        self.assertEqual(tags["sp"], "quarantine")
        self.assertEqual(len(problems["unknown"]), 0)

    def test_duplicate_tag_flagged(self):
        _, problems = parse_tags("v=DMARC1; p=none; p=reject")
        self.assertIn("p", problems["duplicate"])

    def test_unknown_tag_flagged(self):
        _, problems = parse_tags("v=DMARC1; p=none; zap=1")
        self.assertIn("zap", problems["unknown"])

    def test_malformed_chunk_flagged(self):
        _, problems = parse_tags("v=DMARC1; ;p=none; broken")
        self.assertTrue(len(problems["malformed"]) >= 1)


class TestAuditDmarc(unittest.TestCase):
    def test_missing_record_critical(self):
        findings = audit_dmarc([])
        self.assertEqual((findings[0]["code"], findings[0]["severity"]),
                         ("dmarc-missing", "CRITICAL"))

    def test_multiple_records_high(self):
        self.assertIn("dmarc-duplicate", codes(audit_dmarc(["v=DMARC1; p=none", "v=DMARC1; p=reject"])))

    def test_monitor_only_high(self):
        self.assertIn("dmarc-monitor-only", codes(audit_dmarc(["v=DMARC1; p=none"])))

    def test_no_policy_tag_critical(self):
        findings = audit_dmarc(["v=DMARC1; rua=mailto:a@b.com"])
        self.assertEqual((findings[0]["code"], findings[0]["severity"]),
                         ("dmarc-no-policy", "CRITICAL"))

    def test_invalid_policy_high(self):
        self.assertIn("dmarc-invalid-policy", codes(audit_dmarc(["v=DMARC1; p=sometimes"])))

    def test_partial_pct_high(self):
        f = [x for x in audit_dmarc(["v=DMARC1; p=reject; pct=5"]) if x["code"] == "dmarc-pct-partial"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "HIGH")

    def test_full_pct_no_partial_finding(self):
        self.assertNotIn("dmarc-pct-partial", codes(audit_dmarc(["v=DMARC1; p=reject; pct=100"])))

    def test_bad_pct_format_warn(self):
        self.assertIn("dmarc-pct-invalid", codes(audit_dmarc(["v=DMARC1; p=reject; pct=lots"])))

    def test_no_rua_warn(self):
        f = [x for x in audit_dmarc(["v=DMARC1; p=reject"]) if x["code"] == "dmarc-no-rua"]
        self.assertEqual(f[0]["severity"], "WARN")

    def test_sp_inherit_info(self):
        self.assertIn("dmarc-sp-inherit", codes(audit_dmarc(["v=DMARC1; p=reject"])))

    def test_relaxed_alignment_info(self):
        self.assertIn("dmarc-relaxed-alignment",
                      codes(audit_dmarc(["v=DMARC1; p=reject; sp=reject"])))

    def test_quarantine_is_info_not_fail(self):
        findings = audit_dmarc(["v=DMARC1; p=quarantine; rua=mailto:a@b.com; sp=quarantine; adkim=s; aspf=s"])
        self.assertIn("dmarc-quarantine", codes(findings))
        self.assertTrue(all(f["severity"] in ("INFO",) for f in findings))


if __name__ == "__main__":
    unittest.main()
