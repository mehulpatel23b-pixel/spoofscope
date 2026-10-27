import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from fakes import FakeResolver, txt  # noqa: E402
from spoofscope.spf import (  # noqa: E402
    audit_spf,
    count_lookups,
    find_spf_records,
    parse_terms,
)


def codes(findings):
    return {f["code"] for f in findings}


class TestFindRecords(unittest.TestCase):
    def test_extracts_spf_case_insensitive(self):
        records = find_spf_records(txt("v=SPF1 include:_spf.a.com -all", "other=txt"))
        self.assertEqual(records, ["v=SPF1 include:_spf.a.com -all"])

    def test_ignores_non_spf(self):
        self.assertEqual(find_spf_records(txt("google-site-verification=abc", "v=spf10 -all")), [])

    def test_split_spf_record_rejoined_from_strings(self):
        answers = [{"type": 16, "data": '"v=spf1 include:_spf." "a.com -all"'}]
        self.assertEqual(find_spf_records(answers), ["v=spf1 include:_spf.a.com -all"])


class TestParseTerms(unittest.TestCase):
    def test_qualifier_default_plus(self):
        term = parse_terms("v=spf1 a -all")[1]
        self.assertEqual((term["qualifier"], term["name"]), ("-", "all"))

    def test_modifier_and_mechanism(self):
        terms = parse_terms("v=spf1 include:spf.a.com redirect=b.com ~all")
        kinds = {t["raw"]: t["kind"] for t in terms}
        self.assertEqual(kinds["include:spf.a.com"], "mechanism")
        self.assertEqual(kinds["redirect=b.com"], "modifier")
        self.assertEqual(len(terms), 3)


class TestAuditSpf(unittest.TestCase):
    def test_no_record_is_critical(self):
        findings = audit_spf([], domain="example.com")
        self.assertIn("spf-missing", codes(findings))
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_duplicate_records_flagged(self):
        findings = audit_spf(["v=spf1 -all", "v=spf1 ~all"])
        self.assertIn("spf-duplicate", codes(findings))

    def test_all_plus_is_critical(self):
        findings = audit_spf(["v=spf1 +all"])
        self.assertIn("spf-open", codes(findings))
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_all_neutral_is_high(self):
        f = audit_spf(["v=spf1 ip4:1.2.3.4 ?all"])[0]
        self.assertEqual((f["code"], f["severity"]), ("spf-neutral", "HIGH"))

    def test_softfail_is_warn(self):
        f = audit_spf(["v=spf1 ip4:1.2.3.4 ~all"])[0]
        self.assertEqual((f["code"], f["severity"]), ("spf-softfail", "WARN"))

    def test_hard_fail_is_clean(self):
        findings = audit_spf(["v=spf1 ip4:1.2.3.4 -all"])
        self.assertTrue(
            all(f["code"] not in
                ("spf-missing", "spf-open", "spf-neutral", "spf-softfail",
                 "spf-implicit-all") for f in findings)
        )

    def test_missing_all_is_high(self):
        f = audit_spf(["v=spf1 ip4:1.2.3.4"])[0]
        self.assertEqual((f["code"], f["severity"]), ("spf-implicit-all", "HIGH"))

    def test_lookup_overflow_detected(self):
        record = "v=spf1 " + " ".join(["include:x%d.com" % i for i in range(11)]) + " -all"
        self.assertIn("spf-lookup-overflow", codes(audit_spf([record])))

    def test_ten_lookups_is_boundary(self):
        record = "v=spf1 " + " ".join(["include:x%d.com" % i for i in range(10)]) + " -all"
        self.assertNotIn("spf-lookup-overflow", codes(audit_spf([record])))

    def test_ip4_wildcard_everywhere_is_critical(self):
        findings = audit_spf(["v=spf1 ip4:0.0.0.0/0 -all"])
        self.assertIn("spf-ip4-anywhere", codes(findings))
        self.assertTrue(all(f["severity"] == "CRITICAL" for f in findings if f["code"] == "spf-ip4-anywhere"))

    def test_ptr_deprecated_info(self):
        self.assertIn("spf-ptr-deprecated", codes(audit_spf(["v=spf1 ptr -all"])))

    def test_unknown_mechanism_permerror(self):
        self.assertIn("spf-invalid-term", codes(audit_spf(["v=spf1 foo:bar -all"])))


class TestLookupCounting(unittest.TestCase):
    def test_modifiers_count(self):
        self.assertEqual(count_lookups(parse_terms("v=spf1 redirect=a.com")), 1)
        self.assertEqual(count_lookups(parse_terms("v=spf1 ip4:1.2.3.4 -all")), 0)

    def test_nested_includes_followed(self):
        zone = {("spf.corp.com", "TXT"): txt("v=spf1 include:spf2.corp.com -all"),
                ("spf2.corp.com", "TXT"): txt("v=spf1 -all")}
        res = FakeResolver(zone)
        total = count_lookups(parse_terms("v=spf1 include:spf.corp.com -all"), resolver=res)
        self.assertEqual(total, 2)

    def test_beyond_ten_stops_early(self):
        zone = {("spf%d.com" % i, "TXT"): txt("v=spf1 -all") for i in range(20)}
        res = FakeResolver(zone)
        record = "v=spf1 " + " ".join(["include:spf%d.com" % i for i in range(20)]) + " -all"
        self.assertEqual(count_lookups(parse_terms(record), resolver=res), 11)


if __name__ == "__main__":
    unittest.main()
