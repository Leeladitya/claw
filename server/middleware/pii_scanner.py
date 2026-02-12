"""
PII Scanner — Pre-processing Content Analysis

Detects and masks personally identifiable information in extracted
browser content before it reaches OPA evaluation or model inference.

Supported PII types: SSN, Credit Cards, Email, Phone, IP addresses.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("claw.pii")


@dataclass
class PIIScanResult:
    counts: dict[str, int] = field(default_factory=lambda: {
        "ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0,
    })
    masked_text: str = ""
    has_critical_pii: bool = False
    has_any_pii: bool = False
    sensitive_keywords: list[str] = field(default_factory=list)
    classification_signals: list[str] = field(default_factory=list)

    @property
    def total_pii_count(self) -> int:
        return sum(self.counts.values())

    def to_dict(self) -> dict:
        return {
            "counts": self.counts,
            "has_critical_pii": self.has_critical_pii,
            "has_any_pii": self.has_any_pii,
            "total_pii_count": self.total_pii_count,
            "sensitive_keywords": self.sensitive_keywords,
            "classification_signals": self.classification_signals,
        }


SSN_PATTERN = re.compile(r'\b(\d{3}[-.\s]?\d{2}[-.\s]?\d{4})\b')
CREDIT_CARD_PATTERNS = [
    re.compile(r'\b(4\d{3}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4})\b'),
    re.compile(r'\b(5[1-5]\d{2}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4})\b'),
    re.compile(r'\b(3[47]\d{2}[-.\s]?\d{6}[-.\s]?\d{5})\b'),
    re.compile(r'\b(6(?:011|5\d{2})[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4})\b'),
]
EMAIL_PATTERN = re.compile(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b')
PHONE_PATTERN = re.compile(r'\b(\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b')
IP_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

SENSITIVE_KEYWORDS = [
    "confidential", "classified", "top secret", "restricted",
    "password", "api_key", "api-key", "secret_key", "secret-key",
    "access_token", "access-token", "private_key", "private-key",
    "ssn", "social security", "credit card",
    "internal only", "do not distribute", "privileged",
]


def scan_pii(text: str) -> PIIScanResult:
    result = PIIScanResult()
    masked = text

    ssns = [s for s in SSN_PATTERN.findall(text) if _validate_ssn(s)]
    result.counts["ssn"] = len(ssns)
    for ssn in ssns:
        masked = masked.replace(ssn, "[SSN_REDACTED]")

    cc_count = 0
    for pattern in CREDIT_CARD_PATTERNS:
        matches = pattern.findall(text)
        cc_count += len(matches)
        for match in matches:
            masked = masked.replace(match, "[CC_REDACTED]")
    result.counts["credit_card"] = cc_count

    emails = EMAIL_PATTERN.findall(text)
    result.counts["email"] = len(emails)
    for email in emails:
        masked = masked.replace(email, "[EMAIL_REDACTED]")

    phones = PHONE_PATTERN.findall(text)
    result.counts["phone"] = len(phones)
    for phone in phones:
        masked = masked.replace(phone, "[PHONE_REDACTED]")

    ips = [ip for ip in IP_PATTERN.findall(text) if _validate_ip(ip)]
    result.counts["ip_address"] = len(ips)
    for ip in ips:
        masked = masked.replace(ip, "[IP_REDACTED]")

    text_lower = text.lower()
    for keyword in SENSITIVE_KEYWORDS:
        if keyword in text_lower:
            result.sensitive_keywords.append(keyword)

    if any(k in text_lower for k in ["confidential", "classified", "top secret"]):
        result.classification_signals.append("confidential")
    if any(k in text_lower for k in ["financial", "revenue", "earnings"]):
        result.classification_signals.append("financial")
    if any(k in text_lower for k in ["medical", "patient", "hipaa"]):
        result.classification_signals.append("medical")
    if any(k in text_lower for k in ["legal", "attorney", "privilege"]):
        result.classification_signals.append("legal")

    result.masked_text = masked
    result.has_critical_pii = result.counts["ssn"] > 0 or result.counts["credit_card"] > 0
    result.has_any_pii = result.total_pii_count > 0

    return result


def _validate_ssn(s: str) -> bool:
    digits = re.sub(r'[^0-9]', '', s)
    if len(digits) != 9:
        return False
    if digits[:3] in ("000", "666") or digits[:3] >= "900":
        return False
    if digits[3:5] == "00" or digits[5:] == "0000":
        return False
    return True


def _validate_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
        if any(o < 0 or o > 255 for o in octets):
            return False
        if octets[0] in (0, 127, 255):
            return False
        return True
    except ValueError:
        return False
