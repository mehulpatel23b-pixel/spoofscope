"""SPF record discovery and auditing (RFC 7208)."""
from __future__ import annotations

from .doh import join_txt_answers

# Mechanisms / modifiers that cost a DNS lookup during SPF evaluation
# (RFC 7208 section 4.6.4 - evaluation MUST abort after 10).
LOOKUP_TERMS = ("include", "a", "mx", "ptr", "exists", "redirect")

QUALIFIERS = "+-~?"
MECHANISMS = ("all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists")
MODIFIERS = ("redirect", "exp")

MAX_LOOKUPS = 10
MAX_RECURSION_DEPTH = 4


def find_spf_records(answers) -> list:
    """Return the SPF records found among TXT answers (case-insensitive)."""
    records = []
    for data in join_txt_answers(answers):
        stripped = data.strip()
        low = stripped.lower()
        if low == "v=spf1" or low.startswith("v=spf1 "):
            records.append(stripped)
    return records


def parse_terms(record: str) -> list:
    """Parse an SPF record into normalized term dicts (never raises)."""
    terms = []
    tokens = record.split()[1:] if record.split() else []
    for tok in tokens:
        term = {"raw": tok}
        if "=" in tok:
            name, value = tok.split("=", 1)
            if name.lower() in MODIFIERS:
                term.update(kind="modifier", name=name.lower(), value=value)
            else:
                term.update(kind="unknown", name=name.lower(), value=value)
            terms.append(term)
            continue
        qual, rest = "+", tok
        if tok and tok[0] in QUALIFIERS:
            qual, rest = tok[0], tok[1:]
        name, _, value = rest.partition(":")
        if name.lower() in MECHANISMS:
            term.update(kind="mechanism", qualifier=qual, name=name.lower(), value=value)
        else:
            term.update(kind="invalid", qualifier=qual, name=name.lower(), value=value)
        terms.append(term)
    return terms


def count_lookups(terms, resolver=None, domain=None, depth: int = 0, gone: int = 0) -> int:
    """Count DNS lookups an evaluation of these terms would trigger.

    With a resolver, ``include:`` targets are fetched and their terms are
    counted recursively (bounded by depth and the RFC budget).  Offline,
    include depth is unknown, so only the top level is counted and callers
    should present the number as an estimate/partial.
    """
    total = 0
    for term in terms:
        if term.get("name") in LOOKUP_TERMS and term.get("kind") in ("mechanism", "modifier"):
            total += 1
            if total > MAX_LOOKUPS:
                return total
            if (
                resolver is not None
                and term["name"] == "include"
                and depth < MAX_RECURSION_DEPTH
            ):
                nested = resolver.query(term["value"], "TXT")
                nested_records = find_spf_records(nested)
                if nested_records:
                    total += count_lookups(
                        parse_terms(nested_records[0]), resolver, domain, depth + 1
                    )
                    if total > MAX_LOOKUPS:
                        return total
    return total


def _finding(code, severity, message, hint=""):
    return {"check": "SPF", "severity": severity, "code": code, "message": message, "hint": hint}


def audit_spf(records, resolver=None, domain="domain") -> list:
    """Audit the SPF records published for *domain*."""
    findings = []
    if not records:
        findings.append(
            _finding(
                "spf-missing",
                "CRITICAL",
                "no SPF record published for %s" % domain,
                "publish `v=spf1 <your senders> -all` as a TXT record on %s (RFC 7208)" % domain,
            )
        )
        return findings
    if len(records) > 1:
        findings.append(
            _finding(
                "spf-duplicate",
                "HIGH",
                "%d SPF records published (%s) - RFC 7208 forbids multiple; check_host() fails with permerror"
                % (len(records), " | ".join(records[:2])),
                "keep exactly one SPF TXT record on %s" % domain,
            )
        )

    record = records[0]
    terms = parse_terms(record)
    all_term = None
    for term in terms:
        if term.get("kind") == "mechanism" and term.get("name") == "all":
            all_term = term
            break

    if all_term is None:
        findings.append(
            _finding(
                "spf-implicit-all",
                "HIGH",
                "no `all` mechanism - evaluation ends with default Neutral: unauthorized senders are NOT excluded",
                "end the record with `-all` (or `~all` during rollout)",
            )
        )
    else:
        qual = all_term.get("qualifier", "+")
        if qual == "+":
            findings.append(
                _finding(
                    "spf-open",
                    "CRITICAL",
                    "`+all` authorizes the entire internet to send mail as %s" % domain,
                    "replace `+all` with a list of your real senders, then `-all`",
                )
            )
        elif qual == "?":
            findings.append(
                _finding(
                    "spf-neutral",
                    "HIGH",
                    "`?all`=Neutral: unauthorized senders are not excluded - domain still spoofable by SPF",
                    "move to `-all` once your sender list has soaked",
                )
            )
        elif qual == "~":
            findings.append(
                _finding(
                    "spf-softfail",
                    "WARN",
                    "`~all`=SoftFail: forged mail is marked (spam) but not rejected",
                    "graduate to `-all` for hard enforcement; DMARC can still force reject",
                )
            )
        # "-all" is the goal - no finding.

    for term in terms:
        name = term.get("name")
        if term.get("kind") == "invalid":
            findings.append(
                _finding(
                    "spf-invalid-term",
                    "HIGH",
                    "unknown or malformed term `%s` - evaluation yields permerror and receivers may ignore the record" % term["raw"],
                    "remove or fix the term `%s`" % term["raw"],
                )
            )
        if name == "ptr":
            findings.append(
                _finding(
                    "spf-ptr-deprecated",
                    "INFO",
                    "`ptr` is deprecated by RFC 7208 (costly, unreliable) and counts against the lookup limit",
                    "remove the `ptr` mechanism",
                )
            )
        if name == "ip4" and term.get("value", "").strip() in ("0.0.0.0", "0.0.0.0/0"):
            findings.append(
                _finding(
                    "spf-ip4-anywhere",
                    "CRITICAL",
                    "`ip4:0.0.0.0/0` authorizes the entire IPv4 internet to send as %s" % domain,
                    "list the actual sending IPs/CIDRs your mail uses",
                )
            )
        if name == "ip6" and term.get("value", "").strip() in ("::", "::/0"):
            findings.append(
                _finding(
                    "spf-ip6-anywhere",
                    "CRITICAL",
                    "`ip6:::/0` authorizes the entire IPv6 internet to send as %s" % domain,
                    "list the actual sending IPv6 CIDRs your mail uses",
                )
            )

    lookups = count_lookups(terms, resolver=resolver, domain=domain)
    if lookups > MAX_LOOKUPS:
        findings.append(
            _finding(
                "spf-lookup-overflow",
                "HIGH",
                "SPF evaluation needs %d DNS lookups (limit %d): receivers abort with PermError and legitimate mail fails SPF"
                % (lookups, MAX_LOOKUPS),
                "flatten includes or drop dead ones; each include/all add up (RFC 7208 4.6.4)",
            )
        )
    return findings
