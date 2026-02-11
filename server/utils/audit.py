"""
utils/audit.py — Stage 7: Structured Audit Logging

Append-only decision log with hash chaining for tamper detection.
Each entry links to the previous via SHA-256, creating a verifiable
audit trail for compliance review.

Logs are written to both stdout (structured JSON) and an append-only
file for persistence. In production, these would be forwarded to a
SIEM (Splunk, Elastic, Datadog).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("claw.audit")

AUDIT_LOG_PATH = os.environ.get("CLAW_AUDIT_LOG", "audit.jsonl")
_previous_hash: str = "genesis"


def log_decision(
    request_id: str,
    domain: str,
    decision: str,
    policy_pack: str,
    rules_evaluated: int = 0,
    matched_rules: list[str] | None = None,
    modifications: list[str] | None = None,
    content_hash: str = "",
    model: str = "",
    reason: str = "",
) -> dict:
    """
    Log a policy decision to the audit trail.
    Returns the log entry dict.
    """
    global _previous_hash

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "domain": domain,
        "decision": decision,
        "policy_pack": policy_pack,
        "policy_version": "1.0.0",
        "rules_evaluated": rules_evaluated,
        "matched_rules": matched_rules or [],
        "modifications_applied": modifications or [],
        "content_hash": content_hash,
        "model": model,
        "reason": reason,
        "hash_chain_previous": _previous_hash,
    }

    # Compute this entry's hash for chain continuity
    entry_bytes = json.dumps(entry, sort_keys=True).encode()
    entry_hash = hashlib.sha256(entry_bytes).hexdigest()[:16]
    entry["entry_hash"] = entry_hash
    _previous_hash = entry_hash

    # Write to log file
    try:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        log.error(f"Failed to write audit log: {e}")

    # Also emit structured log
    log.info(
        f"DECISION | {request_id} | {domain} | {decision} | "
        f"pack={policy_pack} rules={rules_evaluated} "
        f"matched={matched_rules}"
    )

    return entry


def get_recent_decisions(limit: int = 50) -> list[dict]:
    """Read recent decisions from the audit log file."""
    try:
        path = Path(AUDIT_LOG_PATH)
        if not path.exists():
            return []

        lines = path.read_text().strip().split("\n")
        entries = []
        for line in lines[-limit:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return list(reversed(entries))  # newest first
    except OSError:
        return []
