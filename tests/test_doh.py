import io
import json
import os
import sys
import unittest
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from spoofscope.doh import (  # noqa: E402
    DoHError,
    DoHResolver,
    join_txt_answers,
    normalize_txt_data,
)


def stub_urlopen(payload):
    """Patch urllib.request.urlopen to return `payload` bytes."""

    class FakeResp(io.BytesIO if isinstance(payload, bytes) else object):
        pass

    def fake(req, timeout=None):
        if isinstance(payload, Exception):
            raise payload
        return io.BytesIO(payload)

    return fake


class TestNormalizeTxt(unittest.TestCase):
    def test_plain_quoted(self):
        self.assertEqual(normalize_txt_data('"v=spf1 -all"'), "v=spf1 -all")

    def test_unquoted(self):
        self.assertEqual(normalize_txt_data("v=spf1 -all"), "v=spf1 -all")

    def test_split_strings_rejoined(self):
        self.assertEqual(
            normalize_txt_data('"part-one" "part-two"'), "part-onepart-two"
        )

    def test_escaped_quote(self):
        self.assertEqual(normalize_txt_data('"a\\"b"'), 'a"b')

    def test_empty(self):
        self.assertEqual(normalize_txt_data('""'), "")
        self.assertEqual(normalize_txt_data(""), "")

    def test_join_answers_filters_txt(self):
        answers = [
            {"type": 16, "data": '"v=spf1 -all"'},
            {"type": 15, "data": "10 mx.example.com"},
        ]
        self.assertEqual(join_txt_answers(answers), ["v=spf1 -all"])


class TestDoHResolver(unittest.TestCase):
    def _patch(self, payload):
        original = urllib.request.urlopen
        urllib.request.urlopen = stub_urlopen(payload)
        self.addCleanup(lambda: setattr(urllib.request, "urlopen", original))

    def test_parses_cloudflare_style_payload(self):
        doc = json.dumps(
            {
                "Status": 0,
                "Answer": [
                    {"name": "example.com.", "type": 16, "TTL": 300, "data": '"v=spf1 -all"'}
                ],
            }
        ).encode()
        self._patch(doc)
        res = DoHResolver("cloudflare")
        answers = res.query("example.com", "TXT")
        self.assertEqual(answers[0]["data"], '"v=spf1 -all"')
        self.assertEqual(res.queries, 1)

    def test_nxdomain_returns_empty(self):
        self._patch(json.dumps({"Status": 3}).encode())
        res = DoHResolver("google")
        self.assertEqual(res.query("gone.example", "TXT"), [])

    def test_malformed_json_raises(self):
        self._patch(b"not json at all")
        with self.assertRaises(DoHError):
            DoHResolver("cloudflare").query("example.com", "TXT")

    def test_network_error_raises(self):
        self._patch(OSError("refused"))
        with self.assertRaises(DoHError):
            DoHResolver("cloudflare").query("example.com", "TXT")

    def test_caches_queries(self):
        payload = json.dumps({"Status": 0, "Answer": []}).encode()
        self._patch(payload)
        res = DoHResolver("cloudflare")
        res.query("example.com", "TXT")
        res.query("example.com", "TXT")
        self.assertEqual(res.queries, 1)

    def test_custom_endpoint_url_accepted(self):
        res = DoHResolver("https://doh.example/dns-query")
        self.assertEqual(res.endpoint, "https://doh.example/dns-query")


if __name__ == "__main__":
    unittest.main()
