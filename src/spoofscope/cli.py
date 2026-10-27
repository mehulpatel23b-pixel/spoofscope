"""Command-line interface for spoofscope."""
from __future__ import annotations

import argparse
import json
import sys

from .audit import GRADE_ORDER, audit_domain, render_json, render_text
from .doh import DoHError, DoHResolver
from .dkim import DEFAULT_SELECTORS

EXIT_CODES = {
    0: "all targets at or above --min-grade",
    1: "a target graded below --min-grade",
    2: "usage or runtime error",
    64: "DNS/DoH unavailable",
}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="spoofscope",
        description="Audit how spoofable a domain is: SPF, DMARC, DKIM and MX via DNS-over-HTTPS.",
        epilog="Run only against domains you own or are authorized to assess.",
    )
    parser.add_argument("domains", nargs="*", help="domain(s) to audit, e.g. example.com")
    parser.add_argument("--json", action="store_true", help="machine-readable output (one JSON doc per domain)")
    parser.add_argument("--min-grade", default="B", choices=list(GRADE_ORDER), help="fail (exit 1) if any target grades below this (default: B)")
    parser.add_argument("--selectors", default="", help="comma-separated extra DKIM selectors to probe")
    parser.add_argument("--resolver", default="cloudflare", help="'cloudflare', 'google', or a DoH endpoint URL (default: cloudflare)")
    parser.add_argument("--timeout", type=float, default=10.0, help="DoH timeout in seconds (default: 10)")
    parser.add_argument("--no-dkim", action="store_true", help="skip DKIM selector probing (fewer DNS queries)")
    parser.add_argument("--no-mx", action="store_true", help="skip the MX existence check")
    parser.add_argument("--lint-spf", metavar="RECORD", help="offline: lint an SPF record string instead of resolving it")
    parser.add_argument("--lint-dmarc", metavar="RECORD", help="offline: lint a DMARC record string instead of resolving it")
    parser.add_argument("--version", action="version", version="spoofscope 0.1.0")
    return parser


def lint_report(spf_record, dmarc_record):
    """Build a report dict from raw record strings, without any DNS."""
    from .audit import SEVERITY_WEIGHTS, classify, grade_for
    from .dmarc import audit_dmarc, parse_tags
    from .spf import audit_spf, parse_terms

    findings = []
    spf_records = [spf_record] if spf_record else []
    dmarc_records = [dmarc_record] if dmarc_record else []
    findings += audit_spf(spf_records, resolver=None, domain="(lint)")
    findings += audit_dmarc(dmarc_records)

    dmarc_policy = None
    spf_all = None
    if dmarc_records:
        tags, _ = parse_tags(dmarc_records[0])
        if tags.get("p", "").lower() in ("none", "quarantine", "reject"):
            dmarc_policy = tags["p"].lower()
    if spf_records:
        for term in parse_terms(spf_records[0]):
            if term.get("name") == "all" and term.get("kind") == "mechanism":
                spf_all = term.get("qualifier", "+") + "all"

    score = max(0, 100 - sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings))
    return {
        "domain": "(offline lint)",
        "verdict": classify(findings, dmarc_policy, spf_all),
        "score": score,
        "grade": grade_for(score),
        "findings": findings,
        "spf_all": spf_all,
        "dmarc_policy": dmarc_policy,
        "dkim_selectors": [],
        "queries": 0,
    }


def main(argv=None):
    args = build_parser().parse_args(argv)
    min_rank = GRADE_ORDER[args.min_grade]

    # ---- offline lint mode ---------------------------------------------
    if args.lint_spf or args.lint_dmarc:
        report = lint_report(args.lint_spf, args.lint_dmarc)
        print(render_text(report))
        return 0 if GRADE_ORDER[report["grade"]] >= min_rank else 1

    # ---- online mode ----------------------------------------------------
    domains = [d.strip() for d in args.domains if d.strip()]
    if not domains:
        print("spoofscope: no domain given and no --lint-* record supplied", file=sys.stderr)
        return 2

    resolver = DoHResolver(args.resolver, timeout=args.timeout)
    selectors = None
    if args.selectors:
        extras = tuple(s.strip() for s in args.selectors.split(",") if s.strip())
        selectors = sorted(set(DEFAULT_SELECTORS + extras))

    reports = []
    for domain in domains:
        try:
            report = audit_domain(
                domain,
                resolver,
                selectors=selectors,
                probe_dkim_keys=not args.no_dkim,
                check_mx=not args.no_mx,
            )
        except DoHError as exc:
            print("spoofscope: %s" % exc, file=sys.stderr)
            return 64
        reports.append(report)

    for report in reports:
        if args.json:
            print(json.dumps(render_json(report)))
        else:
            print(render_text(report))
        print()
    rejected = [r for r in reports if GRADE_ORDER[r["grade"]] < min_rank]
    return 1 if rejected else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
