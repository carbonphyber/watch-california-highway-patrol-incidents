#!/usr/bin/env python3
"""Redact PII (phone numbers, CA ID/DL numbers) from <IncidentDetail> tag text.

Operates line-by-line (the feed emits one tag per line) rather than parsing
the file as XML, so a malformed/unexpected document can't crash the scrape.
On any error, the original input is passed through unredacted and a failure
marker file is written so the caller can notify someone instead of silently
shipping unredacted PII or failing the whole job.
"""
import re
import sys

PHONE_NUM_REDACTED = "**PHONE_NUM_REDACTED**"
ID_NUM_REDACTED = "**ID_REDACTED**"

# US phone numbers: (123) 456-7890 | (123-456-7890) | 123-456-7890 | 123.456.7890
PHONE_RE = re.compile(
    r"(?<![0-9A-Za-z])"
    r"(?:"
    r"\(\d{3}\)\s?\d{3}-\d{4}"
    r"|\(\d{3}-\d{3}-\d{4}\)"
    r"|\d{3}-\d{3}-\d{4}"
    r"|\d{3}\.\d{3}\.\d{4}"
    r")"
    r"(?![0-9A-Za-z])"
)

# CA ID / driver's license: one letter followed by exactly 7 digits
CA_ID_RE = re.compile(r"(?<![0-9A-Za-z])[A-Za-z]\d{7}(?![0-9A-Za-z])")

TAG = "IncidentDetail"
TAG_CONTENT_RE = re.compile(
    rf"(<{TAG}>)(.*?)(</{TAG}>)", re.DOTALL
)


def redact_text(text: str) -> str:
    text = PHONE_RE.sub(PHONE_NUM_REDACTED, text)
    text = CA_ID_RE.sub(ID_NUM_REDACTED, text)
    return text


def redact_tag_content(match: "re.Match[str]") -> str:
    open_tag, content, close_tag = match.groups()
    return f"{open_tag}{redact_text(content)}{close_tag}"


def redact(content: str) -> str:
    return TAG_CONTENT_RE.sub(redact_tag_content, content)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <input-file> <failure-marker-file>", file=sys.stderr)
        return 2

    input_path, marker_path = sys.argv[1], sys.argv[2]

    try:
        with open(input_path, "r", encoding="utf-8", errors="replace") as f:
            original = f.read()
        redacted = redact(original)
        with open(input_path, "w", encoding="utf-8") as f:
            f.write(redacted)
    except Exception as exc:  # noqa: BLE001 - deliberately broad: never block the scrape
        with open(marker_path, "w", encoding="utf-8") as f:
            f.write(f"PII redaction failed, raw unfiltered data was kept: {exc!r}\n")
        print(f"redact_pii: failed, keeping raw input unfiltered: {exc!r}", file=sys.stderr)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
