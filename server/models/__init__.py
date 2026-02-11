"""
models/schemas.py — API Request/Response Schemas

These Pydantic models define the complete API contract for Claw v1.
They map 1:1 to the OpenAPI spec from the vision document.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# ── Enums ────────────────────────────────────────────────────────

class PolicyDecision(str, Enum):
    ALLOW = "allow"
    ALLOW_WITH_MODIFICATIONS = "allow_with_modifications"
    DENY = "deny"


class Severity(str, Enum):
    OK = "ok"
    WARNING = "warning"
    DANGER = "danger"


class PolicyPackName(str, Enum):
    STANDARD = "standard"
    FINANCE = "finance"
    STRICT = "strict"
    RESEARCH = "research"


# ── Request Models ───────────────────────────────────────────────

class ContentMetadata(BaseModel):
    author: Optional[str] = None
    site_name: Optional[str] = None
    published_date: Optional[str] = None
    word_count: Optional[int] = None


class AnalyzeOptions(BaseModel):
    policy_pack: Optional[PolicyPackName] = None


class AnalyzeRequest(BaseModel):
    url: str
    title: Optional[str] = None
    text: str = Field(..., min_length=50)
    metadata: Optional[ContentMetadata] = None
    options: Optional[AnalyzeOptions] = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v

    @property
    def domain(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.url).hostname or ""


# ── Policy Models ────────────────────────────────────────────────

class PIIScanResult(BaseModel):
    ssn: int = 0
    credit_card: int = 0
    email: int = 0
    phone: int = 0
    name: int = 0
    ip_address: int = 0
    total: int = 0


class OPAInput(BaseModel):
    """The input document sent to OPA for policy evaluation."""
    url: str
    domain: str
    title: str = ""
    content_features: dict = Field(default_factory=dict)
    pii_detected: dict = Field(default_factory=dict)
    policy_pack: str = "standard"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PolicyResult(BaseModel):
    pack: str
    version: str = "1.0.0"
    decision: PolicyDecision
    modifications_applied: list[str] = Field(default_factory=list)
    rules_evaluated: int = 0
    matched_rules: list[str] = Field(default_factory=list)
    evaluation_ms: int = 0
    reason: Optional[str] = None


# ── Analysis Models ──────────────────────────────────────────────

class SafetyFlag(BaseModel):
    severity: Severity
    message: str


class RiskAnalysis(BaseModel):
    summary: list[str] = Field(default_factory=list)
    risk_score: int = 0
    risk_rationale: str = ""
    safety_flags: list[SafetyFlag] = Field(default_factory=list)


class AuditMetadata(BaseModel):
    content_hash: str = ""
    model: str = ""
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0


# ── Response Models ──────────────────────────────────────────────

class AnalyzeResponse(BaseModel):
    request_id: str = Field(default_factory=lambda: f"clw_req_{uuid.uuid4().hex[:8]}")
    status: str = "analyzed"
    policy: PolicyResult
    analysis: Optional[RiskAnalysis] = None
    audit: Optional[AuditMetadata] = None
    pii_scan: Optional[PIIScanResult] = None


class PolicyDenialResponse(BaseModel):
    request_id: str = Field(default_factory=lambda: f"clw_req_{uuid.uuid4().hex[:8]}")
    status: str = "denied"
    policy: PolicyResult
    reason: str
    matched_rules: list[str] = Field(default_factory=list)


class PolicyEvaluationResponse(BaseModel):
    """Response for the /v1/policy/evaluate dry-run endpoint."""
    decision: PolicyDecision
    rules_matched: list[dict] = Field(default_factory=list)
    modifications: list[str] = Field(default_factory=list)
    pii_scan: PIIScanResult = Field(default_factory=PIIScanResult)
    evaluation_ms: int = 0


class PolicyPackInfo(BaseModel):
    name: str
    version: str
    description: str
    is_active: bool = False


class HealthComponent(BaseModel):
    status: str
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    uptime_seconds: int = 0
    components: dict[str, HealthComponent] = Field(default_factory=dict)


# ── Utility ──────────────────────────────────────────────────────

def compute_content_hash(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode()).hexdigest()[:16]}"
