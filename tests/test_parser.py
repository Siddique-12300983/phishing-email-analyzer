from phishanalyzer.parser import parse_eml

RAW = (
    b"From: \"Billing Team\" <billing@evil.example>\r\n"
    b"Reply-To: collect@other.example\r\n"
    b"Return-Path: bounce@mailer.example.net\r\n"
    b"To: user@example.com\r\n"
    b"Subject: Test message\r\n"
    b"Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail\r\n"
    b"Received: from a.example ([203.0.113.9]) by mx.example.com; Sat, 24 Oct 2026 09:00:00 +0000\r\n"
    b"Content-Type: text/plain\r\n\r\n"
    b"Please verify your account at http://evil.example/login now.\r\n"
)


def test_headers_parsed():
    e = parse_eml(RAW)
    assert e.from_addr == "billing@evil.example"
    assert e.from_display == "Billing Team"
    assert e.reply_to == "collect@other.example"
    assert e.return_path == "bounce@mailer.example.net"
    assert e.subject == "Test message"
    assert len(e.received) == 1


def test_urls_extracted_from_text():
    e = parse_eml(RAW)
    assert "http://evil.example/login" in e.urls


def test_attachment_hash_and_anchor_mismatch():
    raw = (
        b"From: a@evil.example\r\n"
        b"Subject: hi\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
        b"--B\r\nContent-Type: text/html\r\n\r\n"
        b'<a href="http://bad.example/x">https://good.example/x</a>\r\n'
        b"--B\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="p.exe"\r\n\r\n'
        b"MZhello\r\n"
        b"--B--\r\n"
    )
    e = parse_eml(raw)
    assert len(e.attachments) == 1
    assert e.attachments[0].filename == "p.exe"
    assert len(e.attachments[0].sha256) == 64
    hrefs = [l.href for l in e.links]
    assert "http://bad.example/x" in hrefs
