"""DMARC record discovery and auditing (RFC 7489)."""
from __future__ import annotations

from .doh import join_txt_answers

POLICIES = ("none", "quarantine", "reject")

KNOWN_TAGS = ("v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri")


def find_dmarc_records(answers) -> list:
    """Return DMARC records among TXT answers (must begin with v=DMARC1)."""
    records = []
    for data in join_txt_answers(answers):
        stripped = data.strip()
        low = stripped.lower()
        if low == "v=dmarc1" or low.startswith("v=dmarc1;") or low.startswith("v=dmarc1 "):
            records.append(stripped)
    return records


def parse_tags(record: str) -> tuple:
    """Parse a DMARC record into (tags dict, problems dict-of-lists)."""
    tags, problems = {}, {"duplicate": [], "unknown": [], "malformed": []}
    body = record[record.lower().index("v=dmarc1") + len("v=dmarc1"):]
    for chunk in body.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            problems["malformed"].append(chunk)
            continue
        key, value = chunk.split("=", 1)
        key, value = key.strip().lower(), value.strip()
        if not key or not value:
            problems["malformed"].append(chunk)
            continue
        if key in tags:
            problems["duplicate"].append(key)
            continue
        if key not in KNOWN_TAGS:
            problems["unknown"].append(key)
            continue
        tags[key] = value
    return tags, problems


def _finding(code, severity, message, hint=""):
    return {"check": "DMARC", "severity": severity, "code": code, "message": message, "hint": hint}


def audit_dmarc(records) -> list:
    """Audit DMARC records fetched from _dmarc.<domain>."""
    findings = []
    if not records:
        findings.append(
            _finding(
                "dmarc-missing",
                "CRITICAL",
                "no DMARC record at _dmarc.<domain> - receivers have no policy for forged mail",
                "publish `v=DMARC1; p=quarantine; rua=mailto:you@domain` and graduate to p=reject",
            )
        )
        return findings
    if len(records) > 1:
        findings.append(
            _finding(
                "dmarc-duplicate",
                "HIGH",
                "%d DMARC records published (%s) - RFC 7489 requires exactly one; mail may be treated as unsigned"
                % (len(records), records[0][:40] + "..."),
                "keep a single DMARC TXT record at _dmarc.<domain>",
            )
        )

    tags, problems = parse_tags(records[0])
    for key in problems["duplicate"]:
        findings.append(
            _finding(
                "dmarc-duplicate-tag",
                "WARN",
                "tag `%s` appears more than once" % key,
                "DMARC parsers use the first occurrence; remove the duplicate",
            )
        )
    for key in problems["unknown"]:
        findings.append(
            _finding(
                "dmarc-unknown-tag",
                "WARN",
                "unknown tag `%s` in record" % key,
                "remove the tag; unknown tags are ignored by conforming receivers",
            )
        )
    for chunk in problems["malformed"]:
        findings.append(
            _finding(
                "dmarc-malformed-tag",
                "WARN",
                "unparsable tag `%s`" % chunk,
                "fix the tag syntax: key=value separated by semicolons",
            )
        )

    policy = tags.get("p", "").lower()
    if "p" not in tags:
        findings.append(
            _finding(
                "dmarc-no-policy",
                "CRITICAL",
                "no `p=` tag - RFC 7489 6.3: a record without p is ignored entirely (equivalent to no DMARC)",
                "add `p=quarantine` or `p=reject`",
            )
        )
    elif policy not in POLICIES:
        findings.append(
            _finding(
                "dmarc-invalid-policy",
                "HIGH",
                "policy `p=%s` is not one of none/quarantine/reject" % tags.get("p"),
                "use p=none|quarantine|reject",
            )
        )
    elif policy == "none":
        findings.append(
            _finding(
                "dmarc-monitor-only",
                "HIGH",
                "p=none - monitoring only: receivers will deliver forged mail anyway; 2026 bulk-sender rules treat this as unprotected",
                "once reports look clean, move to p=quarantine, then p=reject",
            )
        )
    elif policy == "quarantine":
        findings.append(
            _finding(
                "dmarc-quarantine",
                "INFO",
                "p=quarantine - forged mail is junked, not rejected",
                "p=reject is the terminal enforcement state - move once reports are stable",
            )
        )
    # p=reject: no finding, that is the goal.

    if "pct" in tags:
        pct = None
        try:
            pct = int(tags["pct"])
        except ValueError:
            pass
        if pct is None or not 0 <= pct <= 100:
            findings.append(
                _finding(
                    "dmarc-pct-invalid",
                    "WARN",
                    "pct=%s is not an integer 0-100" % tags["pct"],
                    "pct must be 0-100; omit it for 100%",
                )
            )
        elif pct < 100:
            findings.append(
                _finding(
                    "dmarc-pct-partial",
                    "HIGH",
                    "pct=%d - policy is applied to only %d%% of mail; the remaining %d%% is unprotected"
                    % (pct, pct, 100 - pct),
                    "raise pct to 100 once reports show legitimate mail passing",
                )
            )

    if "rua" not in tags:
        findings.append(
            _finding(
                "dmarc-no-rua",
                "WARN",
                "no rua= aggregate reporting address - you are blind: DMARC success cannot be verified",
                "add `rua=mailto:dmarc-reports@yourdomain` so receivers tell you what passes",
            )
        )

    if "sp" not in tags and "p" in tags and policy in POLICIES:
        findings.append(
            _finding(
                "dmarc-sp-inherit",
                "INFO",
                "no sp= tag - subdomains inherit p=%s (subdomain spoofing IS covered)" % policy,
                "fine if intentional; add sp=reject to state it explicitly",
            )
        )

    if "adkim" not in tags and "aspf" not in tags:
        findings.append(
            _finding(
                "dmarc-relaxed-alignment",
                "INFO",
                "alignment defaults to relaxed (adkim/aspf) - sibling subdomains can satisfy SPF/DKIM alignment",
                "add adkim=s aspf=s once your legitimate mail can handle strict alignment",
            )
        )
    return findings
