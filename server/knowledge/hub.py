"""
Knowledge Hub — Persistent Contextual Memory for Claw

The Knowledge Hub is Claw's memory layer. It stores and retrieves
domain-scoped knowledge entries that enrich the governance pipeline
with contextual awareness across sessions.

Storage: JSONL (append-only, one entry per line)
Retrieval: Domain-first lookup with tag matching and recency decay
Capacity: Configurable max entries with LRU eviction

Integration points:
- After OPA evaluation: stores policy decisions
- Before context assembly: retrieves relevant knowledge
- In argumentation: provides contextual arguments

This is what makes Claw "learn" — it remembers domain reputations,
content patterns, and policy decisions to inform future evaluations.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path

from .models import (
    KnowledgeEntry,
    KnowledgeQuery,
    Disposition,
    EntryType,
)

logger = logging.getLogger("claw.knowledge")


class KnowledgeHub:
    """
    Persistent knowledge store with domain-scoped retrieval.

    Design principles:
    - Append-only JSONL for auditability
    - Domain-first indexing for fast lookup
    - Relevance decay over time (older knowledge weighs less)
    - Configurable capacity with LRU eviction
    """

    def __init__(
        self,
        storage_path: str = "data/knowledge.jsonl",
        max_entries: int = 10_000,
        decay_halflife_hours: float = 168.0,  # 1 week
    ):
        self.storage_path = Path(storage_path)
        self.max_entries = max_entries
        self.decay_halflife = decay_halflife_hours

        # In-memory index (loaded from disk on init)
        self._entries: dict[str, KnowledgeEntry] = {}
        self._domain_index: dict[str, list[str]] = {}  # domain → [entry_ids]
        self._tag_index: dict[str, list[str]] = {}      # tag → [entry_ids]

        self._load()

    # ── Public API ──────────────────────────────────────────────

    def store(self, entry: KnowledgeEntry) -> KnowledgeEntry:
        """
        Store a knowledge entry. Appends to JSONL and updates indexes.

        If an entry with the same content_hash exists for the same domain,
        updates it instead of creating a duplicate.
        """
        # Check for existing entry with same content
        existing = self._find_duplicate(entry)
        if existing:
            existing.updated_at = time.time()
            existing.access_count += 1
            existing.relevance_score = min(1.0, existing.relevance_score + 0.05)
            self._persist(existing, mode="update")
            return existing

        # Assign ID if not set
        if not entry.id:
            entry.id = f"kh_{uuid.uuid4().hex[:12]}"

        # Evict if at capacity
        if len(self._entries) >= self.max_entries:
            self._evict_lru()

        # Add to indexes
        self._entries[entry.id] = entry
        self._domain_index.setdefault(entry.domain, []).append(entry.id)
        for tag in entry.tags:
            self._tag_index.setdefault(tag, []).append(entry.id)

        # Persist
        self._persist(entry, mode="append")

        logger.info(
            f"Stored knowledge entry {entry.id} for domain={entry.domain} "
            f"type={entry.entry_type.value}"
        )
        return entry

    def query(self, q: KnowledgeQuery) -> list[dict]:
        """
        Query the Knowledge Hub with filters and relevance scoring.

        Returns entries as dicts with computed relevance scores
        that account for temporal decay.
        """
        candidates: list[KnowledgeEntry] = []

        # Domain filter (primary index)
        if q.domain:
            entry_ids = self._domain_index.get(q.domain, [])
            # Also check parent domains (e.g., sub.example.com → example.com)
            parts = q.domain.split(".")
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                entry_ids.extend(self._domain_index.get(parent, []))

            for eid in set(entry_ids):
                entry = self._entries.get(eid)
                if entry:
                    candidates.append(entry)
        else:
            candidates = list(self._entries.values())

        # Apply filters
        if q.entry_type:
            candidates = [e for e in candidates if e.entry_type == q.entry_type]

        if q.disposition:
            candidates = [e for e in candidates if e.disposition == q.disposition]

        if q.tags:
            candidates = [
                e for e in candidates
                if any(t in e.tags for t in q.tags)
            ]

        if q.max_age_hours:
            cutoff = time.time() - (q.max_age_hours * 3600)
            candidates = [e for e in candidates if e.created_at >= cutoff]

        if q.policy_pack:
            candidates = [
                e for e in candidates
                if e.policy_pack == q.policy_pack or e.policy_pack == "standard"
            ]

        # Score with temporal decay
        scored = []
        for entry in candidates:
            decayed_score = self._compute_relevance(entry)
            if decayed_score >= q.min_relevance:
                entry_dict = entry.to_dict()
                entry_dict["relevance_score"] = round(decayed_score, 4)
                scored.append(entry_dict)

        # Sort by relevance (highest first)
        scored.sort(key=lambda x: x["relevance_score"], reverse=True)

        # Update access counts
        for item in scored[:q.limit]:
            entry = self._entries.get(item["id"])
            if entry:
                entry.access_count += 1

        return scored[:q.limit]

    def store_policy_decision(
        self,
        domain: str,
        decision: str,
        matched_rules: list[str],
        policy_pack: str,
        pii_counts: dict | None = None,
    ) -> KnowledgeEntry:
        """
        Convenience method to store a policy decision as knowledge.

        Called automatically after each OPA evaluation to build
        domain reputation over time.
        """
        disposition = Disposition.NEUTRAL
        if decision == "deny":
            disposition = Disposition.SUSPICIOUS
        elif decision == "allow" and not matched_rules:
            disposition = Disposition.TRUSTED

        tags = ["policy_decision", decision, policy_pack]
        if pii_counts and any(v > 0 for v in pii_counts.values()):
            tags.append("has_pii")

        entry = KnowledgeEntry(
            id="",
            domain=domain,
            entry_type=EntryType.POLICY_DECISION,
            disposition=disposition,
            summary=f"Policy {decision} for {domain} under {policy_pack} pack",
            content=json.dumps({
                "decision": decision,
                "matched_rules": matched_rules,
                "pii_counts": pii_counts,
            }),
            tags=tags,
            relevance_score=0.6,
            policy_pack=policy_pack,
        )

        return self.store(entry)

    def get_domain_reputation(self, domain: str) -> dict:
        """
        Compute aggregate reputation for a domain based on
        historical knowledge entries.
        """
        entries = self.query(KnowledgeQuery(domain=domain, limit=50))

        if not entries:
            return {
                "domain": domain,
                "reputation": "unknown",
                "score": 0.5,
                "total_entries": 0,
                "deny_count": 0,
                "allow_count": 0,
            }

        deny_count = sum(1 for e in entries if e.get("disposition") == "suspicious")
        allow_count = sum(1 for e in entries if e.get("disposition") == "trusted")
        total = len(entries)

        if deny_count > allow_count * 2:
            reputation = "suspicious"
            score = max(0.1, 0.5 - (deny_count / total) * 0.5)
        elif allow_count > deny_count * 2:
            reputation = "trusted"
            score = min(0.9, 0.5 + (allow_count / total) * 0.5)
        else:
            reputation = "mixed"
            score = 0.5

        return {
            "domain": domain,
            "reputation": reputation,
            "score": round(score, 3),
            "total_entries": total,
            "deny_count": deny_count,
            "allow_count": allow_count,
        }

    @property
    def stats(self) -> dict:
        """Return hub statistics."""
        return {
            "total_entries": len(self._entries),
            "total_domains": len(self._domain_index),
            "total_tags": len(self._tag_index),
            "storage_path": str(self.storage_path),
        }

    # ── Internal Methods ────────────────────────────────────────

    def _compute_relevance(self, entry: KnowledgeEntry) -> float:
        """
        Compute time-decayed relevance score.

        Uses exponential decay: score * 2^(-age / halflife)
        """
        import math
        age_hours = entry.age_hours
        decay_factor = math.pow(2, -age_hours / self.decay_halflife)
        return entry.relevance_score * decay_factor

    def _find_duplicate(self, entry: KnowledgeEntry) -> KnowledgeEntry | None:
        """Find existing entry with same content hash for same domain."""
        target_hash = entry.content_hash
        for eid in self._domain_index.get(entry.domain, []):
            existing = self._entries.get(eid)
            if existing and existing.content_hash == target_hash:
                return existing
        return None

    def _evict_lru(self) -> None:
        """Evict the least recently used entry."""
        if not self._entries:
            return

        oldest_id = min(
            self._entries.keys(),
            key=lambda eid: self._entries[eid].updated_at,
        )
        entry = self._entries.pop(oldest_id)

        # Clean indexes
        domain_ids = self._domain_index.get(entry.domain, [])
        if oldest_id in domain_ids:
            domain_ids.remove(oldest_id)
        for tag in entry.tags:
            tag_ids = self._tag_index.get(tag, [])
            if oldest_id in tag_ids:
                tag_ids.remove(oldest_id)

        logger.debug(f"Evicted knowledge entry {oldest_id}")

    def _persist(self, entry: KnowledgeEntry, mode: str = "append") -> None:
        """Write entry to JSONL storage."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.storage_path, "a") as f:
            record = entry.to_dict()
            record["_mode"] = mode
            f.write(json.dumps(record) + "\n")

    def _load(self) -> None:
        """Load entries from JSONL storage on startup."""
        if not self.storage_path.exists():
            logger.info(f"Knowledge Hub: no existing store at {self.storage_path}")
            return

        loaded = 0
        try:
            with open(self.storage_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        data.pop("_mode", None)
                        data.pop("content_hash", None)
                        entry = KnowledgeEntry.from_dict(data)
                        self._entries[entry.id] = entry
                        self._domain_index.setdefault(entry.domain, []).append(entry.id)
                        for tag in entry.tags:
                            self._tag_index.setdefault(tag, []).append(entry.id)
                        loaded += 1
                    except (json.JSONDecodeError, KeyError, ValueError) as e:
                        logger.warning(f"Skipping malformed knowledge entry: {e}")

            logger.info(
                f"Knowledge Hub loaded {loaded} entries "
                f"across {len(self._domain_index)} domains"
            )
        except Exception as e:
            logger.error(f"Failed to load Knowledge Hub: {e}")
