from phishanalyzer.analyze import analyze, parse_auth_results, _looks_like_lookalike
from phishanalyzer.parser import Attachment, Link, ParsedEmail


def test_parse_auth_results():
    v = parse_auth_results("mx; spf=fail smtp.mailfrom=x; dkim=none; dmarc=fail")
    assert v == {"spf": "fail", "dkim": "none", "dmarc": "fail"}


def test_lookalike_detection():
    assert _looks_like_lookalike("examp1e-support.example")   # 1 for l
    assert _looks_like_lookalike("xn--pple-43d.example")      # punycode
    assert not _looks_like_lookalike("example.com")
    assert not _looks_like_lookalike("mail-server.example.net")


def test_reply_to_mismatch_is_high():
    e = ParsedEmail(from_addr="a@good.example", reply_to="b@evil.example")
    titles = {(f.severity, f.title) for f in analyze(e).findings}
    assert ("high", "Reply-To domain differs from From") in titles


def test_dmarc_fail_is_high():
    e = ParsedEmail(from_addr="a@good.example",
                    auth_results="mx; spf=pass; dkim=pass; dmarc=fail")
    sev = {f.title: f.severity for f in analyze(e).findings}
    assert sev.get("DMARC fail") == "high"


def test_display_name_address_mismatch():
    e = ParsedEmail(from_addr="admin@examp-support.example",
                    from_display="IT security@example.com")
    titles = [f.title for f in analyze(e).findings]
    assert "Display name shows a different address" in titles


def test_link_text_vs_href_mismatch():
    e = ParsedEmail(from_addr="a@good.example",
                    links=[Link(href="http://bad.example/pay", text="https://good.example/pay")])
    titles = [f.title for f in analyze(e).findings]
    assert "Link text does not match its destination" in titles


def test_urgency_language():
    e = ParsedEmail(from_addr="a@good.example",
                    subject="URGENT verify your account",
                    body_text="log in now to avoid suspension")
    titles = [f.title for f in analyze(e).findings]
    assert any("Pressure or credential-theft language" in t for t in titles)


def test_risky_attachment():
    e = ParsedEmail(from_addr="a@good.example",
                    attachments=[Attachment("invoice.exe", "application/octet-stream", 10, "x" * 64)])
    titles = [f.title for f in analyze(e).findings]
    assert "Risky attachment type" in titles


def test_clean_email_has_no_findings():
    e = ParsedEmail(from_addr="news@example.com", reply_to="news@example.com",
                    return_path="news@example.com",
                    auth_results="mx; spf=pass; dkim=pass; dmarc=pass",
                    subject="This week", body_text="read our blog")
    assert analyze(e).findings == []
