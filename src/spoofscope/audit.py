"""Domain audit engine: SPF + DMARC + DKIM + MX rollup, scoring and verdicts."""
from __future__ import annotations

from .dmarc import audit_dmarc, find_dmarc_records
from .doh import answer_of_type
from .dkim import probe_dkim
from .spf import audit_spf, find_spf_records

SEVERITY_WEIGHTS = {"CRITICAL": 35, "HIGH": 20, "WARN": 8, "INFO": 0}
GRADES = ((95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F"))
GRADE_ORDER = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4, "A+": 5}

VERDICTS = {
    "ENFORCED": "SPF + DMARC combine to make spoofed mail rejectable by receivers",
    "PARTIAL": "some enforcement exists, but gaps let forged mail through to spam or inboxes",
    "SPOOFABLE": "receivers have no working policy to reject forged mail as this domain",
}


def grade_for(score: int) -> str:
    for threshold, grade in GRADES:
        if score >= threshold:
            return grade
    return "F"


def classify(findings, dmarc_policy, spf_all) -> str:
    """Roll findings into the headline verdict."""
    criticals = [f for f in findings if f["severity"] == "CRITICAL"]
    if dmarc_policy in (None, "", "none") or any(
        f["code"] in ("spf-open", "spf-ip4-anywhere", "spf-ip6-anywhere") for f in criticals
    ):
        return "SPOOFABLE"
    if dmarc_policy == "reject" and spf_all == "-all" and not criticals:
        return "ENFORCED"
    if dmarc_policy in ("quarantine", "reject"):
        return "PARTIAL"
    return "SPOOFABLE"


def audit_domain(
    domain,
    resolver,
    selectors=None,
    probe_dkim_keys=True,
    spf_override=None,
    dmarc_override=None,
    check_mx=True,
):
    """Audit one domain.  Overrides enable offline lint mode (no DNS).

    Returns a report dict: domain, verdict, score, grade, findings,
    spf_policy, dmarc_policy, dkim_selectors, queries.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    findings = []
    queries = 0
    dkim_selectors = []

    def q(name, rrtype):
        nonlocal queries
        queries += 1
        return resolver.query(name, rrtype)

    # --- SPF -----------------------------------------------------------
    if spf_override is not None:
        spf_records = list(spf_override)
    else:
        spf_records = find_spf_records(q(domain, "TXT"))
    findings.extend(audit_spf(spf_records, resolver=resolver, domain=domain))

    # --- DMARC ---------------------------------------------------------
    if dmarc_override is not None:
        dmarc_records = list(dmarc_override)
    else:
        dmarc_records = find_dmarc_records(q("_dmarc." + domain, "TXT"))
    findings.extend(audit_dmarc(dmarc_records))

    # --- policy extraction ----------------------------------------------
    dmarc_policy = None
    spf_all = None
    if dmarc_records:
        from .dmarc import parse_tags

        tags, _ = parse_tags(dmarc_records[0])
        if tags.get("p", "").lower() in ("none", "quarantine", "reject"):
            dmarc_policy = tags["p"].lower()
    if spf_records:
        from .spf import parse_terms

        for term in parse_terms(spf_records[0]):
            if term.get("name") == "all" and term.get("kind") == "mechanism":
                spf_all = term.get("qualifier", "+") + "all"

    # --- DKIM -----------------------------------------------------------
    if probe_dkim_keys and resolver is not None:
        found, dkim_findings = probe_dkim(domain, resolver, selectors)
        dkim_selectors = [s for s, _ in found]
        findings.extend(dkim_findings)

    # --- MX -------------------------------------------------------------
    if check_mx:
        answers = q(domain, "MX")
        if not answer_of_type(answers, "MX"):
            findings.append(
                {
                    "check": "MX",
                    "severity": "INFO",
                    "code": "mx-none",
                    "message": "no MX record - the domain cannot receive mail (bounce-based abuse less relevant)",
                    "hint": "if this domain sends mail, also publish null MX `0 .` to signal non-receiving",
                }
            )

    # --- scoring --------------------------------------------------------
    score = 100 - sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings)
    score = max(0, min(100, score))
    verdict = classify(findings, dmarc_policy, spf_all)
    return {
        "domain": domain,
        "verdict": verdict,
        "score": score,
        "grade": grade_for(score),
        "findings": findings,
        "spf_all": spf_all,
        "dmarc_policy": dmarc_policy,
        "dkim_selectors": sorted(set(dkim_selectors)),
        "queries": queries,
    }


def render_text(report, version="") -> str:
    """Render a human-readable report."""
    lines = []
    head = "spoofscope %s - email spoofing exposure audit" % version if version else "email spoofing exposure audit"
    lines.append(head)
    lines.append("target: %s" % report["domain"])
    lines.append("verdict: %s - %s" % (report["verdict"], VERDICTS[report["verdict"]]))
    lines.append("")
    if not report["findings"]:
        lines.append("  no findings - SPF/DMARC/DKIM look clean")
    for f in report["findings"]:
        lines.append("  %-6s %-9s [%s] %s" % (f["check"], f["severity"] + ":", f["code"], f["message"]))
        if f["hint"]:
            lines.append("         fix: %s" % f["hint"])
    lines.append("")
    lines.append("score: %d/100  grade: %s" % (report["score"], report["grade"]))
    lines.append("spf=%s   dmarc=%s   dkim selectors=%s" % (
        report["spf_all"] or "none",
        ("p=" + report["dmarc_policy"]) if report["dmarc_policy"] else "-",
        ",".join(report["dkim_selectors"]) or "none found",
    ))
    if report["queries"]:
        lines.append("dns queries: %d" % report["queries"])
    return "\n".join(lines)


def render_json(report) -> dict:
    return {
        "domain": report["domain"],
        "verdict": report["verdict"],
        "score": report["score"],
        "grade": report["grade"],
        "spf_all": report["spf_all"],
        "dmarc_policy": report["dmarc_policy"],
        "dkim_selectors": report["dkim_selectors"],
        "findings": report["findings"],
        "queries": report["queries"],
    }
