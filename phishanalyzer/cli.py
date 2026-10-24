"""Command-line interface for phishing-email-analyzer."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .analyze import analyze
from .parser import parse_eml
from .report import build_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishing-email-analyzer",
        description="Offline triage of a .eml file: header checks, auth results, URLs, attachments and red flags.",
    )
    p.add_argument("eml", help="path to the .eml file")
    p.add_argument("--version", action="version", version=f"phishing-email-analyzer {__version__}")
    return p


def run(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with open(args.eml, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        print(f"error: cannot read {args.eml}: {exc}", file=sys.stderr)
        return 2

    email = parse_eml(raw)
    analysis = analyze(email)
    print(build_report(email, analysis))

    # Exit 1 if any high-severity finding, so it can gate an automated workflow.
    return 1 if any(f.severity == "high" for f in analysis.findings) else 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
