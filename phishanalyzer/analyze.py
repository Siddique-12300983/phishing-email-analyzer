"""Turn a ParsedEmail into triage findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlparse

from .parser import ParsedEmail

# Words that often signal pressure or credential theft. Lowercased.
URGENCY_WORDS = [
    "urgent", "immediately", "action required", "verify your account",
    "verify your", "suspended", "suspend", "within 24 hours", "within 24hrs",
    "final notice", "password", "confirm your", "update your payment",
    "unusual activity", "click here", "log in now", "validate", "account locked",
    "failure to", "avoid suspension", "reactivate",
]

# Digits commonly swapped for letters in lookalike domains.
_HOMOGLYPH_DIGITS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"}


@dataclass
class Finding:
    severity: str          # high, medium, low, info
    title: str
    detail: str

    _ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

    @property
    def rank(self) -> int:
        return self._ORDER.get(self.severity, 9)


@dataclass
class Analysis:
    findings: List[Finding] = field(default_factory=list)
    auth: dict = field(default_factory=dict)   # spf/dkim/dmarc verdicts


def _domain(addr: str) -> str:
    return addr.split("@", 1)[1].lower() if "@" in addr else ""


def parse_auth_results(header: str) -> dict:
    """Pull spf/dkim/dmarc verdicts out of an Authentication-Results header."""
    verdicts = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", header, re.IGNORECASE)
        if m:
            verdicts[mech] = m.group(1).lower()
    return verdicts


def _looks_like_lookalike(domain: str) -> bool:
    if domain.startswith("xn--") or ".xn--" in domain:
        return True   # punycode / IDN
    for label in domain.split("."):
        letters = sum(c.isalpha() for c in label)
        digits = [c for c in label if c.isdigit()]
        # A mostly-alphabetic label with homoglyph digits inside it.
        if letters >= 3 and digits and all(d in _HOMOGLYPH_DIGITS for d in digits):
            return True
    return False


def analyze(email: ParsedEmail) -> Analysis:
    result = Analysis()
    f = result.findings

    from_dom = _domain(email.from_addr)
    reply_dom = _domain(email.reply_to)
    return_dom = _domain(email.return_path)

    # Header mismatches.
    if reply_dom and reply_dom != from_dom:
        f.append(Finding("high", "Reply-To domain differs from From",
                         f"From is {email.from_addr or '(none)'} but Reply-To is {email.reply_to}. "
                         "Replies would go to a different domain."))
    if return_dom and return_dom != from_dom:
        f.append(Finding("medium", "Return-Path domain differs from From",
                         f"From domain is {from_dom or '(none)'} but the envelope Return-Path is "
                         f"{email.return_path}. Common in spoofed mail."))

    # Authentication-Results.
    auth = parse_auth_results(email.auth_results)
    result.auth = auth
    for mech in ("spf", "dkim", "dmarc"):
        verdict = auth.get(mech)
        if verdict in ("fail", "softfail", "none", "permerror", "temperror"):
            sev = "high" if (mech == "dmarc" and verdict == "fail") else "medium"
            f.append(Finding(sev, f"{mech.upper()} {verdict}",
                             f"Authentication-Results reports {mech}={verdict}."))

    # Display name claims an address that is not the real sender.
    if email.from_display:
        for m in re.findall(r"[\w.+-]+@[\w.-]+\.\w+", email.from_display):
            if _domain(m) and _domain(m) != from_dom:
                f.append(Finding("medium", "Display name shows a different address",
                                 f"The From display name contains {m}, but the real sender is "
                                 f"{email.from_addr}."))

    # Lookalike sender domain.
    if from_dom and _looks_like_lookalike(from_dom):
        f.append(Finding("high", "Sender domain looks like a lookalike",
                         f"{from_dom} uses punycode or digit-for-letter substitution, a typosquatting sign."))

    # Link display text vs href mismatch, and lookalike link domains.
    for link in email.links:
        href_dom = urlparse(link.href).hostname or ""
        text_doms = re.findall(r"[\w.-]+\.\w{2,}", link.text or "")
        for td in text_doms:
            if td.lower() not in href_dom.lower() and href_dom and "." in td:
                f.append(Finding("high", "Link text does not match its destination",
                                 f"The link shows '{link.text}' but points to {link.href}."))
                break
        if href_dom and _looks_like_lookalike(href_dom):
            f.append(Finding("high", "Link points to a lookalike domain",
                             f"{href_dom} looks like a typosquatted domain."))

    # Urgency / credential-theft language.
    haystack = f"{email.subject}\n{email.body_text}".lower()
    hits = sorted({w for w in URGENCY_WORDS if w in haystack})
    if hits:
        sev = "medium" if len(hits) >= 2 else "low"
        f.append(Finding(sev, f"Pressure or credential-theft language ({len(hits)})",
                         "Phrases found: " + ", ".join(hits)))

    # Attachments are informational, but risky types are a flag.
    risky_ext = (".exe", ".scr", ".js", ".vbs", ".jar", ".iso", ".img", ".htm", ".html", ".lnk", ".zip", ".rar")
    for att in email.attachments:
        if att.filename.lower().endswith(risky_ext):
            f.append(Finding("high", "Risky attachment type",
                             f"{att.filename} ({att.content_type}) is a type often used to deliver malware."))

    result.findings.sort(key=lambda x: x.rank)
    return result
