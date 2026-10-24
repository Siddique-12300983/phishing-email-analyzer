import pathlib

from phishanalyzer.analyze import analyze
from phishanalyzer.parser import parse_eml

SAMPLES = pathlib.Path(__file__).resolve().parent.parent / "samples"


def _analyze(name):
    return analyze(parse_eml((SAMPLES / name).read_bytes()))


def test_invoice_fraud_flagged_high():
    a = _analyze("invoice-fraud.eml")
    assert any(f.severity == "high" for f in a.findings)
    assert a.auth.get("dmarc") == "fail"


def test_lookalike_caught_even_though_auth_passes():
    a = _analyze("password-reset-lookalike.eml")
    assert a.auth == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert any("lookalike" in f.title for f in a.findings)


def test_clean_newsletter_is_clean():
    a = _analyze("clean-newsletter.eml")
    assert a.findings == []
