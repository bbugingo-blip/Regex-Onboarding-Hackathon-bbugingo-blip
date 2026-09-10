# ALU Regex Data Extraction & Secure Validation

**Author:** Bugingo Nshuti Brandon
**GitHub:** [bbugingo-blip](https://github.com/bbugingo-blip)
**Course:** ALU – BSE Software Development

## What this project does

This program simulates a real production scenario: raw text comes back
from an external API (in this case, a support-ticket export), and we need
to (1) pull structured data out of it and (2) never blindly trust it,
because the "API" might return malformed or hostile content.

It extracts **6 data types** with regex:

| Data type            | Notes |
|-----------------------|-------|
| Emails                | General + ALU-specific (`@alueducation.com`, `@alumni.alueducation.com`, `@si.alueducation.com`) |
| Credit card numbers    | Regex finds candidates, then validated with the **Luhn algorithm** + issuer-prefix brand guess |
| URLs                  | `http://` / `https://` only, on purpose |
| Phone numbers          | Handles local & international formats, spacing, dashes, extensions |
| Time                  | 12-hour (`6:45 PM`) and 24-hour (`14:30`) |
| Hashtags               | `#PaymentFailed`, with a fix for false positives like `#INV-2291` |
| Currency amounts       | Symbol-based (`$389.50`, `€12,00`) and ISO-code-based (`RWF 450,000`, `2500 RWF`) |

It also has a **security screening layer** that runs before extraction
(see below), and **masks all sensitive output** (emails, card numbers) so
nothing sensitive is exposed raw in the console or the JSON file.

## Folder structure

```
alu-regex-data-extraction_bbugingo-blip/
├── input/
│   └── raw-text.txt        # messy, realistic sample input (support tickets)
├── src/
│   └── main.py              # all the logic (Python 3, standard library only)
├── output/
│   └── sample-output.json   # generated report (masked/aggregated data)
└── README.md
```

## How to run it

Requires **Python 3.7+** (standard library only — no `pip install` needed).

```bash
cd alu-regex-data-extraction_bbugingo-blip/src
python3 main.py
```

This will:
1. Read `../input/raw-text.txt`
2. Print a summary to the console
3. Write the full structured report to `../output/sample-output.json`

To try it on your own text, just replace the contents of
`input/raw-text.txt` and re-run the script.

## How the program is organized (`src/main.py`)

The file is split into clearly labelled sections:

1. **Security checks** — a list of `(name, regex, explanation)` tuples that
   flag a line as unsafe if it looks like:
   - an XSS payload (`<script>`, `<iframe>`, `onerror=...`)
   - a SQL-injection attempt (`DROP TABLE`, `' OR '1'='1`, `';--`)
   - a path-traversal attempt (`../../etc/passwd`)
   - HTTP header/CRLF injection
   - a template/expression injection (`{{7*7}}`, `${jndi:...}`)
   - a raw, unfiltered upstream log line (see **Security design** below)
   - an abnormally long line (possible DoS attempt)

2. **Extraction regex patterns** — one constant per data type, each with a
   comment explaining exactly what it matches and why it's shaped that way.

3. **Validation & masking helpers** — the Luhn checksum, a simple
   card-brand guesser, and `mask_email()` / `mask_card()` which are used
   **every time** sensitive data is shown, ever.

4. **`extract_data()`** — runs every extractor against the *safe* text
   only (text that already passed the security check).

5. **`main()`** — reads the file line by line, filters out unsafe lines,
   runs extraction, and writes the JSON report + console summary.

## Security design (why these decisions were made)

- **Line-by-line quarantine, not "reject the whole file."**
  Each line is checked independently. If one line is hostile, only that
  line is dropped — the rest of a valid document is still processed. Every
  dropped line is recorded with its line number and the *category* of
  problem detected, but **never the raw offending text itself** — so the
  report/log doesn't become a second place storing the attack payload.

- **Raw upstream log lines are never trusted, even if they look "clean."**
  The sample input includes a block labelled
  `SYSTEM AUDIT LOG (raw, unfiltered feed from upstream API - DO NOT TRUST
  BLINDLY)`. Lines starting with a timestamp like `[2026-09-08T14:01:02Z]`
  are treated as internal telemetry, not user-submitted data, and are
  excluded from extraction by policy. This matters because one of those
  log lines contains a plain, unmasked, Luhn-valid credit card number
  (`4111111111111111`) — if we ran the credit-card regex on every line
  without this rule, that real-looking card number would leak straight
  into our "safe" output. Excluding the whole line prevents that.

- **ALU email validation is anchored, not a substring check.**
  A naive check like `"alueducation.com" in email` would incorrectly
  "validate" a phishing address such as
  `fake.student@alueducation.com.phish-site.net`, because the substring
  is technically present. This program instead uses `re.fullmatch()` with
  a pattern anchored at both ends (`^...@alueducation\.com$`), so the
  **entire address** must end exactly at `alueducation.com`. The sample
  input includes several deliberate lookalikes
  (`...alueducation.com.phish-site.net`, `...alueducation.co`,
  `...alumni.alueducation.com.evil.org`, `...si.alueducation.com.attacker.io`)
  to prove these are correctly rejected as ALU addresses (they still show
  up as ordinary/"external" emails, which is correct — they're valid email
  syntax, just not ALU-owned).

- **URLs are restricted to `http`/`https`.**
  The regex intentionally does not match `ftp://`, `file://`, or
  `javascript:` links, even though a looser pattern could. If a
  downstream system ever assumed "extracted URL = safe to open," allowing
  those schemes would be risky.

- **Credit card numbers are never stored or printed in full.**
  Only the masked form (`**** **** **** 6467`) plus the brand and a
  Luhn-validity flag ever leave the program. The same applies to emails
  (`b*****4@gmail.com`).

- **Digit-sequence overlap is prevented.**
  Before phone numbers are extracted, every digit sequence already
  identified as a credit card is blanked out of a working copy of the
  text. This stops a 16-digit card number from also being reported as a
  (nonsensical) phone number.

## Notes on the sample input

`input/raw-text.txt` is written to resemble a real support-ticket export:
inconsistent spacing, mixed international phone formats, a masked card
number that should be *ignored* (`**** **** **** 4242`), typos, informal
currency notation ("2500 RWF" written backwards), and an embedded "raw
system log" section containing several classic attack payloads (XSS, SQLi,
path traversal, header injection, template injection, and a raw
credit-card dump) to demonstrate that the security layer actually rejects
them rather than silently trusting the API response.

All credit card numbers used are publicly documented **test/dummy card
numbers** (the kind used in payment-gateway sandboxes) — no real financial
data is used anywhere in this project.

