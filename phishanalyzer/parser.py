"""Parse a .eml file into the pieces the analyzer needs. No network is used."""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import getaddresses
from html.parser import HTMLParser
from typing import List, Optional

URL_RE = re.compile(r"(?:https?|ftp)://[^\s<>\"'\)\]]+", re.IGNORECASE)


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class Link:
    href: str
    text: str = ""           # anchor text, for display-vs-href checks


@dataclass
class ParsedEmail:
    from_addr: str = ""
    from_display: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    subject: str = ""
    date: str = ""
    auth_results: str = ""
    received: List[str] = field(default_factory=list)
    body_text: str = ""
    links: List[Link] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)


class _AnchorParser(HTMLParser):
    """Collect <a href> links together with their visible text."""

    def __init__(self):
        super().__init__()
        self.links: List[Link] = []
        self._current: Optional[Link] = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href", "")
            if href:
                self._current = Link(href=href)

    def handle_data(self, data):
        if self._current is not None:
            self._current.text += data.strip()

    def handle_endtag(self, tag):
        if tag == "a" and self._current is not None:
            self.links.append(self._current)
            self._current = None


def _first_address(header_value: Optional[str]) -> str:
    if not header_value:
        return ""
    addrs = getaddresses([str(header_value)])
    return addrs[0][1].lower() if addrs and addrs[0][1] else ""


def _display_name(header_value: Optional[str]) -> str:
    if not header_value:
        return ""
    addrs = getaddresses([str(header_value)])
    return addrs[0][0] if addrs else ""


def parse_eml(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = email.message_from_bytes(raw, policy=email.policy.default)

    parsed = ParsedEmail(
        from_addr=_first_address(msg.get("From")),
        from_display=_display_name(msg.get("From")),
        reply_to=_first_address(msg.get("Reply-To")),
        return_path=_first_address(msg.get("Return-Path")),
        to=_first_address(msg.get("To")),
        subject=str(msg.get("Subject", "")),
        date=str(msg.get("Date", "")),
        auth_results=str(msg.get("Authentication-Results", "")),
        received=[str(h) for h in msg.get_all("Received", [])],
    )

    html_body = ""
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()

        if disposition == "attachment" or filename:
            payload = part.get_payload(decode=True) or b""
            parsed.attachments.append(Attachment(
                filename=filename or "(unnamed)",
                content_type=ctype,
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            ))
            continue

        if ctype == "text/plain":
            parsed.body_text += part.get_content()
        elif ctype == "text/html":
            html_body += part.get_content()

    if html_body:
        ap = _AnchorParser()
        ap.feed(html_body)
        parsed.links.extend(ap.links)

    # All URLs: anchor hrefs plus any bare URLs in the text body.
    urls = {lnk.href for lnk in parsed.links if URL_RE.match(lnk.href)}
    urls.update(URL_RE.findall(parsed.body_text))
    urls.update(URL_RE.findall(html_body))
    parsed.urls = sorted(urls)
    return parsed
