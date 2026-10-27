import contextlib
import io
import json
import os
import sys
import unittest
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from fakes import FakeResolver, mx, txt  # noqa: E402
import spoofscope.cli as cli_mod  # noqa: E402
from spoofscope.cli import lint_report, main  # noqa: E402
from spoofscope.doh import DoHError  # noqa: E402


@contextlib.contextmanager
def capture_stdout():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        yield buf


class TestLintMode(unittest.TestCase):
    def test_lint_bad_spf_fails_grade(self):
        args = ["--lint-spf", "v=spf1 +all", "--lint-dmarc", "v=DMARC1; p=none"]
        with capture_stdout() as out:
            rc = main(args)
        text = out.getvalue()
        self.assertEqual(rc, 1)
        self.assertIn("spf-open", text)
        self.assertIn("dmarc-monitor-only", text)

    def test_lint_good_records_pass(self):
        args = [
            "--lint-spf", "v=spf1 ip4:203.0.113.10 -all",
            "--lint-dmarc", "v=DMARC1; p=reject; sp=reject; rua=mailto:a@b.com; adkim=s; aspf=s",
        ]
        with capture_stdout() as out:
            rc = main(args)
        self.assertEqual(rc, 0)
        self.assertIn("verdict:", out.getvalue())

    def test_lint_report_offline_shapes(self):
        report = lint_report("v=spf1 -all", "v=DMARC1; p=reject; rua=mailto:x@y.z; sp=reject; adkim=s; aspf=s")
        self.assertEqual(report["queries"], 0)
        self.assertGreaterEqual(report["score"], 95)


class TestOnlineMode(unittest.TestCase):
    def _patch_and_run(self, argv):
        real_audit = cli_mod.audit_domain

        def fake_audit(domain, resolver, **kwargs):
            zone = {
                ("locked.example", "TXT"): txt("v=spf1 -all"),
                ("_dmarc.locked.example", "TXT"): txt(
                    "v=DMARC1; p=reject; sp=reject; rua=mailto:a@locked.example; adkim=s; aspf=s"),
            }
            return real_audit(domain, FakeResolver(zone), **kwargs)

        cli_mod.audit_domain = fake_audit
        try:
            with capture_stdout() as out:
                rc = main(argv)
            return rc, out.getvalue()
        finally:
            cli_mod.audit_domain = real_audit

    def test_passing_domain_exit_zero(self):
        rc, text = self._patch_and_run([
            "locked.example",
            "--no-dkim",  # fixture zone has no DKIM records
            "--selectors", "",
        ])
        self.assertEqual(rc, 0)
        self.assertIn("verdict: ENFORCED", text)

    def test_strict_min_grade_can_fail_passing_domain(self):
        # A-grade domain (softfail SPF => WARN deducts points) must fail an A+ gate.
        real_audit = cli_mod.audit_domain
        zone = {
            ("soft.example", "TXT"): txt("v=spf1 ip4:203.0.113.0/24 ~all"),
            ("_dmarc.soft.example", "TXT"): txt(
                "v=DMARC1; p=reject; sp=reject; rua=mailto:a@soft.example; adkim=s; aspf=s"),
        }

        def fake_audit(domain, resolver, **kwargs):
            return real_audit(domain, FakeResolver(zone), **kwargs)

        cli_mod.audit_domain = fake_audit
        try:
            with capture_stdout():
                rc = main(["soft.example", "--min-grade", "A+", "--no-dkim"])
        finally:
            cli_mod.audit_domain = real_audit
        self.assertEqual(rc, 1)
        # ...while the default B gate accepts the same domain.
        cli_mod.audit_domain = fake_audit
        try:
            with capture_stdout():
                rc = main(["soft.example", "--no-dkim"])
        finally:
            cli_mod.audit_domain = real_audit
        self.assertEqual(rc, 0)

    def test_json_output(self):
        rc, text = self._patch_and_run(["locked.example", "--json", "--no-dkim"])
        doc = json.loads(text.strip().splitlines()[0])
        self.assertEqual(doc["verdict"], "ENFORCED")
        self.assertIn("findings", doc)

    def test_no_domains_usage_error(self):
        with capture_stdout():
            rc = main([])
        self.assertEqual(rc, 2)

    def test_doh_unreachable_exit_64(self):
        real_audit = cli_mod.audit_domain
        cli_mod.audit_domain = lambda *a, **k: (_ for _ in ()).throw(DoHError("dead"))
        try:
            with capture_stdout():
                rc = main(["down.example"])
        finally:
            cli_mod.audit_domain = real_audit
        self.assertEqual(rc, 64)

    def test_skips_and_flags(self):
        rc, text = self._patch_and_run(["locked.example", "--no-dkim", "--no-mx", "--min-grade", "B"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
