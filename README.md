# phishing-email-analyzer

A Python CLI that reads a `.eml` file and prints a triage report: sender header
checks, the Received chain, SPF/DKIM/DMARC results, every URL and attachment
with a SHA-256, and a list of red flags. It works entirely offline, so it is
safe to run on a suspicious message without touching anything.

Part of the detection work around my
[purple-team-journey](https://github.com/Siddique-12300983/purple-team-journey)
lab.

## Why it matters

Phishing is still the most common way in. When a suspicious email lands in a
mailbox, the first job is triage: is this a spoof, where does it really come
from, where do the links go, and what is attached. Doing that by reading raw
headers is slow, and opening the message or clicking a link to "just check" is
how people get caught. This tool pulls the useful parts out of the `.eml`
without rendering it or making any network request, and points at the things
that usually give a phish away.

## What it checks

- **Header mismatches**: From vs Reply-To vs Return-Path domains, and a display
  name that shows a different address than the real sender.
- **Authentication**: SPF, DKIM and DMARC results read from the
  `Authentication-Results` header.
- **Received chain**: the hops the message claims to have taken.
- **URLs**: every link, including anchor text that does not match its real
  destination (a classic phishing trick).
- **Attachments**: filename, type, size and SHA-256 (so you can look the hash up
  later without opening the file), with risky types flagged.
- **Language and lookalikes**: pressure and credential-theft phrases, and sender
  or link domains that use punycode or digit-for-letter substitution.

Findings are ranked, and the tool exits `1` when anything high-severity turns
up, so it can gate an automated mailbox workflow.

## Offline by design

The tool never resolves DNS, never fetches a URL, and never contacts a
reputation service. Everything it reports comes from the `.eml` file itself.
That keeps it safe to run on live phishing samples.

## Install

Python 3.9 or newer, standard library only.

```bash
git clone https://github.com/Siddique-12300983/phishing-email-analyzer.git
cd phishing-email-analyzer
```

Optionally install the command:

```bash
pip install .
phishing-email-analyzer samples/invoice-fraud.eml
```

## Usage

```bash
python -m phishanalyzer samples/invoice-fraud.eml
```

## Example output

```
Phishing email triage report
====================================================
Subject     : URGENT: Overdue invoice - payment required immediately
From        : Harbourline Billing <accounts@harbourline-freight.example>
Reply-To    : payments@collections-recovery.example
Return-Path : bounce@mailer.example.net
Auth        : spf=fail dkim=none dmarc=fail

URLs (2)
  http://203.0.113.45/pay
  https://portal.harbourline-freight.example/pay

Attachments (1)
  invoice_2026.html [application/octet-stream, 51 bytes]
    sha256: 88b79c686138c48fb28dc796243238c86533a4796861d2e099d475b511cc033f

----------------------------------------------------
Findings    : 8
  [HIGH] Reply-To domain differs from From
  [HIGH] DMARC fail
  [HIGH] Link text does not match its destination
         The link shows 'https://portal.harbourline-freight.example/pay' but points to http://203.0.113.45/pay.
  [HIGH] Risky attachment type
  [MED ] Return-Path domain differs from From
  ...
```

## Sample emails

Three fictional samples are in `samples/`, all using `example.*` domains and
made-up names, no real brands or people:

- `invoice-fraud.eml`: spoofed billing email, failing auth, a link whose text
  and destination differ, and a risky attachment.
- `password-reset-lookalike.eml`: a lookalike sender domain (`examp1e-support`),
  caught even though SPF, DKIM and DMARC all pass.
- `clean-newsletter.eml`: a legitimate message, reported with no findings, for
  contrast.

## Running the tests

```bash
pip install pytest
pytest
```

The suite covers the parser (headers, URLs, attachment hashing, anchor
mismatch), each analyzer check, and the three sample emails.

## Layout

```
phishanalyzer/
  parser.py    parse the .eml: headers, body, links, attachments
  analyze.py   the triage checks
  report.py    the report
  cli.py       entry point
samples/       three fictional .eml files
tests/         pytest suite
```

## License

MIT. See [LICENSE](LICENSE).
