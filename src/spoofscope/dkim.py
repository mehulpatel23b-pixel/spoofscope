"""DKIM selector probing and public-key sanity checks (RFC 6376)."""
from __future__ import annotations

import base64
import binascii

from .doh import join_txt_answers

# The selectors seen most often in real DNS zones.  DKIM has no discovery
# mechanism, so auditors traditionally probe common selector names.
DEFAULT_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "s1",
    "s2",
    "dkim",
    "mail",
    "smtp",
    "zoho",
    "sendgrid",
    "mandrill",
    "mailgun",
    "amazonses",
    "protonmail",
)


def parse_key_record(data: str) -> dict:
    """Parse a DKIM key record into tags (k, h, p, s, t...)."""
    tags = {}
    for chunk in data.split(";"):
        chunk = chunk.strip()
        if "=" in chunk:
            key, value = chunk.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def estimate_rsa_bits(p_value: str):
    """Estimate RSA modulus size from the base64 p= tag (SPKI DER)."""
    compact = "".join(p_value.split())
    if not compact:
        return None
    try:
        der = base64.b64decode(compact, validate=False)
    except (binascii.Error, ValueError):
        return None
    return max(0, (len(der) - 24) * 8) if len(der) > 24 else 0


def _probe_one(resolver, name):
    try:
        answers = resolver.query(name, "TXT")
    except Exception:  # a DNS layer failure must not kill the whole audit
        return None
    for txt in join_txt_answers(answers):
        tags = parse_key_record(txt)
        if tags:
            return tags
    return None


def probe_dkim(domain, resolver, selectors=None):
    """Probe selectors; return (found: list of (selector, tags), findings).

    Repeated findings are consolidated: a wildcard `*._domainkey` record
    (used to block key-namespace abuse) otherwise floods the report with
    one identical finding per selector.
    """
    findings = []
    found = []
    selectors = selectors or DEFAULT_SELECTORS
    for selector in selectors:
        name = "%s._domainkey.%s" % (selector, domain)
        tags = _probe_one(resolver, name)
        if tags:
            found.append((selector, tags))

    if not found:
        findings.append(
            {
                "check": "DKIM",
                "severity": "WARN",
                "code": "dkim-not-found",
                "message": "no DKIM public key found on %d common selectors - if you send signed mail, receivers cannot verify signatures; spoofed mail cannot be DKIM-rejected"
                % len(selectors),
                "hint": "publish TXT `<selector>._domainkey.%s` containing `v=DKIM1; k=rsa; p=<key>`" % domain,
            }
        )
        return found, findings

    revoked, weak, trivial = [], [], []
    for selector, tags in found:
        key_type = tags.get("k", "rsa").lower()
        bits = None
        if key_type == "rsa":
            bits = estimate_rsa_bits(tags.get("p", ""))
        if not tags.get("p"):
            revoked.append(selector)
        elif bits is not None and bits < 1024:
            trivial.append((selector, bits))
        elif bits is not None and bits < 2048:
            weak.append((selector, bits))

    if revoked:
        if len(revoked) > 3:
            msg = ("%d common selectors publish empty (revoked) keys - likely a "
                   "wildcard `*._domainkey` record blocking key-namespace abuse" % len(revoked))
            hint = "expected on hardened reserved domains; verify your real signing selector is active"
        else:
            msg = "selector%s %s publish%s empty (revoked) key%s" % (
                "s" if len(revoked) > 1 else "",
                ", ".join("`%s`" % s for s in revoked),
                "" if len(revoked) > 1 else "es",
                "s" if len(revoked) > 1 else "",
            )
            hint = "expected during rotation; ensure the replacement selector is active"
        findings.append(
            {
                "check": "DKIM",
                "severity": "INFO",
                "code": "dkim-key-revoked",
                "message": msg,
                "hint": hint,
            }
        )

    if trivial:
        findings.append(
            {
                "check": "DKIM",
                "severity": "CRITICAL",
                "code": "dkim-trivial-key",
                "message": "trivially factorable RSA keys (<1024 bits) on: %s"
                % ", ".join("`%s` (~%d bits)" % (s, b) for s, b in trivial),
                "hint": "rotate to 2048-bit keys immediately",
            }
        )
    if weak:
        findings.append(
            {
                "check": "DKIM",
                "severity": "HIGH",
                "code": "dkim-weak-key",
                "message": "RSA keys below 2048 bits on: %s"
                % ", ".join("`%s` (~%d bits)" % (s, b) for s, b in weak),
                "hint": "rotate to 2048-bit keys",
            }
        )
    return found, findings
