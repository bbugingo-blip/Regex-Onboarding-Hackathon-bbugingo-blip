#!/usr/bin/env python3
"""
ALU Regex Data Extraction & Secure Validation
Author: Bugingo Nshuti Brandon (GitHub: bbugingo-blip)
"""

import re
import json
import os
from datetime import datetime, timezone


SECURITY_PATTERNS = {
    "xss_script_or_event_handler": r"<\s*(script|iframe)\b|on\w+\s*=\s*['\"]?[^\s>]+",
    "sql_injection": r"(?i)(\bdrop\s+table\b|\bunion\s+select\b|;\s*--|'\s*--|'\s*or\s*'1'\s*=\s*'1)",
    "path_traversal": r"\.\./|\.\.\\",
    "header_or_crlf_injection": r"\\r\\n|X-Fake:|Set-Cookie\s*:",
    "template_injection": r"\{\{.*?\}\}|\$\{jndi:",
}
RAW_LOG_LINE = r"^\s*\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\]"
MAX_LINE_LENGTH = 1000


def line_is_safe(line):
    reasons = []
    if len(line) > MAX_LINE_LENGTH:
        reasons.append("oversized_line")
    if re.match(RAW_LOG_LINE, line):
        reasons.append("raw_unfiltered_upstream_log_line")
    for name, pattern in SECURITY_PATTERNS.items():
        if re.search(pattern, line):
            reasons.append(name)
    return (len(reasons) == 0, reasons)


def extract_emails(text):
    return re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)


def extract_credit_cards(text):
    return re.findall(r"\b(?:\d[ -]?){12,18}\d\b", text)


def extract_urls(text):
    return re.findall(r"\bhttps?://[^\s<>\"']+", text)


def extract_phone_numbers(text):
    return re.findall(
        r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?"
        r"\d{2,4}[\s.-]?\d{2,4}(?:[\s.-]?\d{2,6})?"
        r"(?:\s?(?:ext\.?|x)\.?\s?\d{1,5})?(?!\d)",
        text,
    )


def extract_times(text):
    return re.findall(r"\b(?:[01]?\d|2[0-3]):[0-5]\d(?:\s?[APap][Mm])?\b", text)


def extract_hashtags(text):
    return re.findall(r"#[A-Za-z][A-Za-z0-9_]{1,49}\b(?!-)", text)


def extract_currency(text):
    symbol_amounts = re.findall(r"[-+]?[$€£¥]\s?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{1,2})?", text)
    code_amounts = re.findall(
        r"\b(?:USD|RWF|KES|EUR|GBP|UGX|TZS)\s?\d[\d,]*(?:\.\d{1,2})?\b"
        r"|\b\d[\d,]*(?:\.\d{1,2})?\s?(?:USD|RWF|KES|EUR|GBP|UGX|TZS)\b",
        text,
    )
    return symbol_amounts + [c.strip() for c in code_amounts]


def extract_html_tags(text):
    return re.findall(r"<\/?[a-zA-Z][a-zA-Z0-9]*(?:\s+[^<>]*?)?\/?>", text)


def is_valid_luhn(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch) * 2 if i % 2 else int(ch)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


def guess_card_brand(digits):
    if digits[:2] in ("34", "37") and len(digits) == 15:
        return "American Express"
    if digits[0] == "4" and len(digits) in (13, 16):
        return "Visa"
    if digits[:2] in ("51", "52", "53", "54", "55") and len(digits) == 16:
        return "MasterCard"
    if (digits.startswith("6011") or digits.startswith("65")) and len(digits) == 16:
        return "Discover"
    return "Unknown/Other"


def mask_card(digits):
    masked = "*" * (len(digits) - 4) + digits[-4:]
    groups = [masked[max(0, e - 4):e] for e in range(len(masked), 0, -4)]
    return " ".join(reversed(groups))


def mask_email(email):
    local, _, domain = email.partition("@")
    masked_local = local[0] + "*" if len(local) <= 2 else local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def classify_alu_email(email):
    if re.fullmatch(r"[A-Za-z0-9._%+-]+@si\.alueducation\.com", email, re.IGNORECASE):
        return "alu_si"
    if re.fullmatch(r"[A-Za-z0-9._%+-]+@alumni\.alueducation\.com", email, re.IGNORECASE):
        return "alu_alumni"
    if re.fullmatch(r"[A-Za-z0-9._%+-]+@alueducation\.com", email, re.IGNORECASE):
        return "alu_official"
    return "external"


def main():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path = os.path.join(project_root, "input", "raw-text.txt")
    output_path = os.path.join(project_root, "output", "sample-output.json")

    with open(input_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    safe_lines, incidents = [], []
    for line_number, line in enumerate(lines, start=1):
        safe, reasons = line_is_safe(line)
        if safe:
            safe_lines.append(line)
        else:
            incidents.append({"line": line_number, "reasons": reasons})

    safe_text = "".join(safe_lines)

    emails = []
    alu_emails = {"alu_official": [], "alu_alumni": [], "alu_si": []}
    for email in extract_emails(safe_text):
        category = classify_alu_email(email)
        emails.append({"masked": mask_email(email), "category": category})
        if category != "external":
            alu_emails[category].append(mask_email(email))

    cards = []
    scrubbed_text = safe_text
    for raw in extract_credit_cards(safe_text):
        digits = re.sub(r"\D", "", raw)
        if 13 <= len(digits) <= 19:
            cards.append({
                "masked": mask_card(digits),
                "brand": guess_card_brand(digits),
                "luhn_valid": is_valid_luhn(digits),
            })
            scrubbed_text = scrubbed_text.replace(raw, " " * len(raw), 1)

    phones = []
    for raw in extract_phone_numbers(scrubbed_text):
        candidate = raw.strip()
        digit_count = len(re.sub(r"\D", "", candidate))
        if 7 <= digit_count <= 15 and not re.match(r"^\d{4}[-/]\d{2}[-/]\d{2}$", candidate):
            phones.append(candidate)

    results = {
        "emails": emails,
        "alu_emails": alu_emails,
        "credit_cards": cards,
        "urls": [u.rstrip(").,]}'\"") for u in extract_urls(safe_text)],
        "phone_numbers": phones,
        "times": extract_times(safe_text),
        "hashtags": extract_hashtags(safe_text),
        "html_tags": extract_html_tags(safe_text),
        "currency_amounts": extract_currency(safe_text),
    }

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": "input/raw-text.txt",
        "security": {
            "lines_scanned": len(lines),
            "lines_excluded": len(incidents),
            "incidents": incidents,
        },
        "results": results,
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("=" * 60)
    print("ALU REGEX EXTRACTION - SUMMARY")
    print("=" * 60)
    print(f"Lines scanned : {len(lines)}")
    print(f"Lines excluded: {len(incidents)} (flagged as unsafe/untrusted)")
    for inc in incidents:
        print(f"  - line {inc['line']}: {', '.join(inc['reasons'])}")
    print(f"\nEmails found       : {len(emails)}  "
          f"(ALU official: {len(alu_emails['alu_official'])}, "
          f"alumni: {len(alu_emails['alu_alumni'])}, "
          f"SI: {len(alu_emails['alu_si'])})")
    print(f"Credit cards found : {len(cards)}")
    for c in cards:
        print(f"  {c['masked']}  ({c['brand']}, Luhn valid: {c['luhn_valid']})")
    print(f"URLs found         : {len(results['urls'])}")
    print(f"Phone numbers found: {len(phones)}")
    print(f"Times found        : {len(results['times'])}")
    print(f"Hashtags found     : {len(results['hashtags'])}")
    print(f"HTML tags found    : {len(results['html_tags'])}")
    print(f"Currency amounts   : {len(results['currency_amounts'])}")
    print(f"\nFull JSON report saved to: output/sample-output.json")


if __name__ == "__main__":
    main()

