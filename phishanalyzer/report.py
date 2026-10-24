"""Render the triage report."""

from __future__ import annotations

from .analyze import Analysis
from .parser import ParsedEmail

_SEV = {"high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]", "info": "[INFO]"}


def build_report(email: ParsedEmail, analysis: Analysis) -> str:
    L = []
    L.append("Phishing email triage report")
    L.append("=" * 52)
    L.append(f"Subject     : {email.subject}")
    L.append(f"From        : {email.from_display + ' ' if email.from_display else ''}<{email.from_addr}>")
    if email.reply_to:
        L.append(f"Reply-To    : {email.reply_to}")
    if email.return_path:
        L.append(f"Return-Path : {email.return_path}")
    L.append(f"To          : {email.to}")
    L.append(f"Date        : {email.date}")

    # Authentication
    if analysis.auth:
        auth = " ".join(f"{k}={v}" for k, v in analysis.auth.items())
    else:
        auth = "no Authentication-Results header"
    L.append(f"Auth        : {auth}")

    # Received chain
    L.append(f"\nReceived chain ({len(email.received)} hop(s), newest first)")
    if email.received:
        for i, hop in enumerate(email.received, 1):
            first_line = " ".join(hop.split())
            if len(first_line) > 100:
                first_line = first_line[:97] + "..."
            L.append(f"  {i}. {first_line}")
    else:
        L.append("  (none)")

    # URLs
    L.append(f"\nURLs ({len(email.urls)})")
    for u in email.urls:
        L.append(f"  {u}")

    # Attachments
    L.append(f"\nAttachments ({len(email.attachments)})")
    for a in email.attachments:
        L.append(f"  {a.filename} [{a.content_type}, {a.size} bytes]")
        L.append(f"    sha256: {a.sha256}")

    # Findings
    L.append("\n" + "-" * 52)
    if not analysis.findings:
        L.append("Findings    : none, nothing obviously suspicious")
    else:
        L.append(f"Findings    : {len(analysis.findings)}")
        for fnd in analysis.findings:
            L.append(f"  {_SEV.get(fnd.severity, '[????]')} {fnd.title}")
            L.append(f"         {fnd.detail}")
    return "\n".join(L)
