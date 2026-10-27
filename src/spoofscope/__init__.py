"""spoofscope - email spoofing exposure audit for a domain (SPF / DKIM / DMARC).

Zero-dependency, stdlib-only. Answers one question: "Can anyone in the
world send email that looks like it comes from this domain, and how
quickly would a receiver reject it?"
"""

__version__ = "0.1.0"
__all__ = ["audit_domain", "DoHResolver", "render_text", "DoHError"]
