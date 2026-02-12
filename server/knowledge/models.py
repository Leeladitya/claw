"""
Knowledge Hub Models — Contextual Memory for Claw

The Knowledge Hub stores domain-scoped, time-aware knowledge entries
that enrich the governance pipeline with contextual memory.

Each entry represents a learned insight from a previous analysis:
- Domain reputation (trusted/suspicious/neutral)
- Content patterns (recurring PII, classification signals)
- Policy decision history (what was allowed/denied and why)
- User-provided annotations
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum


class Disposition(str, Enum):
    """Trust disposition for a knowledge entry."""
    TRUSTED = "trusted"
    SUSPICIOUS = "suspicious"
    NEUTRAL = "neutral"
    CONTEXTUAL = "contextual"


class EntryType(str, Enum):
    """Classification of knowledge entries."""
    DOMAIN_REPUTATION = "domain_reputation"
    CONTENT_PATTERN = "content_pattern"
    POLICY_DECISION = "policy_decision"
    USER_ANNOTATION = "user_annotation"
    PII_PATTERN = "pii_pattern"


@dataclass
class KnowledgeEntry:
    """A single entry in the Knowledge Hub."""
    id: str
    domain: str
    entry_type: EntryType
    disposition: Disposition
    summary: str
    content: str = ""
    tags: list[str] = field(default_factory=list)
    relevance_score: float = 0.5
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    access_count: int = 0
    policy_pack: str = "standard"
    metadata: dict = field(default_factory=dict)

    @property
    def content_hash(self) -> str:
        raw = f"{self.domain}:{self.entry_type.value}:{self.content}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def age_hours(self) -> float:
        return (time.time() - self.created_at) / 3600

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "domain": self.domain,
            "entry_type": self.entry_type.value,
            "disposition": self.disposition.value,
            "summary": self.summary,
            "content": self.content,
            "tags": self.tags,
            "relevance_score": self.relevance_score,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "access_count": self.access_count,
            "policy_pack": self.policy_pack,
            "content_hash": self.content_hash,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> KnowledgeEntry:
        return cls(
            id=data["id"],
            domain=data["domain"],
            entry_type=EntryType(data["entry_type"]),
            disposition=Disposition(data["disposition"]),
            summary=data["summary"],
            content=data.get("content", ""),
            tags=data.get("tags", []),
            relevance_score=data.get("relevance_score", 0.5),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
            access_count=data.get("access_count", 0),
            policy_pack=data.get("policy_pack", "standard"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class KnowledgeQuery:
    """Query parameters for Knowledge Hub retrieval."""
    domain: str | None = None
    entry_type: EntryType | None = None
    disposition: Disposition | None = None
    tags: list[str] = field(default_factory=list)
    max_age_hours: float | None = None
    min_relevance: float = 0.0
    limit: int = 10
    policy_pack: str | None = None
