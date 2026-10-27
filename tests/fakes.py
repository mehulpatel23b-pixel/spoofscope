"""Shared test fixtures: a canned-zone DNS resolver (no network)."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class FakeResolver:
    """Duck-typed resolver mimicking DoHResolver against a canned zone.

    zone maps (name, rrtype) -> list of answers, where an answer is either
    a dict {"type": <code>, "data": "..."} or an Exception to raise.
    """

    def __init__(self, zone=None):
        self.zone = zone or {}
        self.queries = 0
        self.called = []

    def query(self, name, rrtype="TXT"):
        self.queries += 1
        rrtype = rrtype.upper()
        key = (name.lower().rstrip("."), rrtype)
        self.called.append(key)
        value = self.zone.get(key, [])
        if isinstance(value, Exception):
            raise value
        return list(value)


def txt(*records):
    """Build TXT answers (type 16) with dig-style quoting."""
    return [{"type": 16, "data": '"%s"' % r} for r in records]


def mx(pref, host):
    return {"type": 15, "data": "%d %s" % (pref, host)}
