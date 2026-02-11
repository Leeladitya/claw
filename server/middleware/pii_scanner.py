"""
middleware/pii_scanner.py — Stage 1: PII Detection & Masking

Scans extracted browser content for personally identifiable information
using regex patterns. Returns both scan results (for OPA input) and
optionally masked text (for model submission).

Supported PII types:
  - SSN (US Social Security Numbers)
  - Credit card numbers (Visa, MC, Amex, Discover)
  - Email addresses
  - Phone numbers (US/international)
  - IP addresses (v4)

This is the pre-processing layer that runs BEFORE OPA evaluation.
OPA uses the scan results to make policy decisions; the masking
itself is applied based on the policy decision.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import NamedTuple

from server.models import PIIScanResult


# ── Pattern Definitions ──────────────────────────────────────────

class PIIPattern(NamedTuple):
    name: str
    pattern: re.Pattern
    mask: str


PATTERNS: list[PIIPattern] = [
    PIIPattern(
        name="ssn",
        pattern=re.compile(
            r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'
        ),
        mask="[SSN_REDACTED]",
    ),
    PIIPattern(
        name="credit_card",
        pattern=re.compile(
            r'\b(?:'
            r'4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}'  # Visa
            r'|5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}'  # Mastercard
            r'|3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}'  # Amex
            r'|6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}'  # Discover
            r')\b'
        ),
        mask="[CC_REDACTED]",
    ),
    PIIPattern(
        name="email",
        pattern=re.compile(
            r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
        ),
        mask="[EMAIL_REDACTED]",
    ),
    PIIPattern(
        name="phone",
        pattern=re.compile(
            r'(?<!\d)'  # negative lookbehind: no digit before
            r'(?:'
            r'(?:\+1[-.\s]?)?'  # optional +1 country code
            r'(?:\(?\d{3}\)?[-.\s]?)'  # area code
            r'\d{3}[-.\s]?\d{4}'  # number
            r')'
            r'(?!\d)'  # negative lookahead: no digit after
        ),
        mask="[PHONE_REDACTED]",
    ),
    PIIPattern(
        name="ip_address",
        pattern=re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        ),
        mask="[IP_REDACTED]",
    ),
]

# ── Sensitive Keyword Patterns ───────────────────────────────────
# These don't get masked but are reported to OPA for policy decisions

SENSITIVE_KEYWORDS = re.compile(
    r'\b('
    r'confidential|top\s*secret|classified|internal\s+only'
    r'|restricted|proprietary|do\s+not\s+distribute'
    r'|attorney[\s-]client\s+privilege|trade\s+secret'
    r'|password|passwd|api[_\s]?key|secret[_\s]?key|access[_\s]?token'
    r')\b',
    re.IGNORECASE,
)


# ── Scanner ──────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Full scan result with counts, locations, and masked text."""
    pii: PIIScanResult = field(default_factory=PIIScanResult)
    sensitive_keywords: list[str] = field(default_factory=list)
    classification_signals: list[str] = field(default_factory=list)
    masked_text: str = ""


def scan_pii(text: str) -> ScanResult:
    """
    Scan text for PII patterns and sensitive keywords.
    Returns counts for OPA input and pre-masked text.
    """
    result = ScanResult()
    masked = text

    counts: dict[str, int] = {}

    for pat in PATTERNS:
        matches = pat.pattern.findall(text)
        count = len(matches)
        counts[pat.name] = count

        if count > 0:
            masked = pat.pattern.sub(pat.mask, masked)

    # Build PIIScanResult
    result.pii = PIIScanResult(
        ssn=counts.get("ssn", 0),
        credit_card=counts.get("credit_card", 0),
        email=counts.get("email", 0),
        phone=counts.get("phone", 0),
        ip_address=counts.get("ip_address", 0),
        total=sum(counts.values()),
    )

    # Sensitive keyword detection
    kw_matches = SENSITIVE_KEYWORDS.findall(text)
    result.sensitive_keywords = list(set(kw.lower().strip() for kw in kw_matches))

    # Classification signals
    signals = []
    if any(k in result.sensitive_keywords for k in ["confidential", "classified", "top secret", "restricted"]):
        signals.append("confidential")
    if any(k in result.sensitive_keywords for k in ["password", "passwd", "api_key", "secret_key", "access_token"]):
        signals.append("credentials")
    if any(k in result.sensitive_keywords for k in ["attorney-client privilege", "trade secret"]):
        signals.append("legal_privileged")
    if result.pii.ssn > 0 or result.pii.credit_card > 0:
        signals.append("financial_pii")
    result.classification_signals = signals

    result.masked_text = masked

    return result


def mask_text(text: str, modifications: list[str] | None = None) -> tuple[str, list[str]]:
    """
    Apply PII masking to text and return (masked_text, list_of_modifications).
    This is called in Stage 3 (context assembly) after OPA approves with modifications.
    """
    mods = modifications or []
    result = scan_pii(text)

    if result.pii.ssn > 0:
        mods.append(f"pii_redaction: {result.pii.ssn} SSN(s) masked")
    if result.pii.credit_card > 0:
        mods.append(f"pii_redaction: {result.pii.credit_card} credit card number(s) masked")
    if result.pii.email > 0:
        mods.append(f"pii_redaction: {result.pii.email} email address(es) masked")
    if result.pii.phone > 0:
        mods.append(f"pii_redaction: {result.pii.phone} phone number(s) masked")
    if result.pii.ip_address > 0:
        mods.append(f"pii_redaction: {result.pii.ip_address} IP address(es) masked")

    return result.masked_text, mods
