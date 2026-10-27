"""DNS-over-HTTPS (DoH) resolution using only the Python standard library.

spoofscope resolves DNS records through public DoH JSON endpoints so it
works from CI runners and sandboxes where only outbound HTTPS (port 443)
is available, and from hosts with no native DNS client libraries.

The two built-in endpoints speak the same JSON shape:

    Cloudflare:  https://cloudflare-dns.com/dns-query?name=...&type=TXT
    Google:      https://dns.google/resolve?name=...&type=TXT

Both return a document like::

    {"Status": 0, "Answer": [{"name": "example.com.", "type": 16,
                             "TTL": 3600, "data": "\"v=spf1 -all\""}]}

TXT records returned on the wire as multiple DNS character-strings are
rejoined into a single logical record.
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request

BUILTIN_RESOLVERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/resolve",
}

_RRTYPE_CODES = {"TXT": 16, "MX": 15, "CNAME": 5}


class DoHError(RuntimeError):
    """Raised when the DoH endpoint is unreachable or returns unusable JSON."""


def normalize_txt_data(raw: str) -> str:
    """Rejoin DNS TXT character-strings into one logical record.

    Wire presentation for a long TXT record is ``"part-one" "part-two"``.
    Endpoints echo that quoting; strip it and concatenate the parts (RFC
    7208 / RFC 7489 treat the concatenation, not each string, as the record).
    """
    s = (raw or "").strip()
    if not (s.startswith('"') and s.endswith('"')) or len(s) < 2:
        return s
    inner = s[1:-1]
    parts = inner.split('" "')
    joined = "".join(parts)
    return joined.replace('\\"', '"')


def join_txt_answers(answers) -> list:
    """Return normalized TXT data strings from a DoH answer list."""
    out = []
    for ans in answers or []:
        if ans.get("type") == _RRTYPE_CODES["TXT"]:
            out.append(normalize_txt_data(ans.get("data", "")))
    return out


def answer_of_type(answers, rrtype: str) -> list:
    """Answers carrying the requested RR type, data untouched."""
    return [a for a in answers or [] if a.get("type") == _RRTYPE_CODES.get(rrtype, -1)]


class DoHResolver:
    """Minimal DoH JSON client with a per-instance query cache."""

    def __init__(self, resolver: str = "cloudflare", timeout: float = 10.0):
        if resolver in BUILTIN_RESOLVERS:
            self.endpoint = BUILTIN_RESOLVERS[resolver]
        else:
            self.endpoint = resolver  # allow a custom DoH URL
        self.timeout = timeout
        self.queries = 0
        self._cache = {}

    def query(self, name: str, rrtype: str = "TXT") -> list:
        """Resolve *name*; return the Answer list ([] when no record exists)."""
        key = (name.lower().rstrip("."), rrtype.upper())
        if key in self._cache:
            return self._cache[key]
        params = urllib.parse.urlencode({"name": name, "type": rrtype.upper()})
        url = "%s?%s" % (self.endpoint, params)
        req = urllib.request.Request(
            url,
            headers={
                "accept": "application/dns-json",
                "user-agent": "spoofscope/0.1 (+security audit tool)",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
        except (OSError, ValueError) as exc:
            raise DoHError("DoH query failed for %s (%s): %s" % (name, rrtype, exc)) from exc
        self.queries += 1
        if not isinstance(payload, dict) or "Status" not in payload:
            raise DoHError("DoH endpoint returned malformed JSON for %s" % name)
        if payload["Status"] != 0:
            self._cache[key] = []
            return []
        answers = payload.get("Answer") or []
        self._cache[key] = answers
        return answers
