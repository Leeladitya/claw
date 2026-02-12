"""Audit Logger — Append-only JSONL with SHA-256 hash chaining."""
from __future__ import annotations
import hashlib
import json
import logging
import time
import uuid
from pathlib import Path

logger = logging.getLogger("claw.audit")

class AuditLogger:
    def __init__(self, path: str = "data/audit.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = "genesis"
        self._entries: list[dict] = []
        self._load_last_hash()

    def log(self, **kwargs) -> dict:
        entry = {
            "id": f"aud_{uuid.uuid4().hex[:12]}",
            "timestamp": time.time(),
            "prev_hash": self._prev_hash,
            **kwargs,
        }
        raw = json.dumps(entry, sort_keys=True)
        entry["hash"] = hashlib.sha256(raw.encode()).hexdigest()
        self._prev_hash = entry["hash"]
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        self._entries.append(entry)
        return entry

    def query(self, limit: int = 50, decision: str | None = None) -> list[dict]:
        results = self._entries[-limit * 2:] if self._entries else []
        if decision:
            results = [e for e in results if e.get("decision") == decision]
        return results[-limit:]

    def _load_last_hash(self):
        if not self.path.exists():
            return
        try:
            with open(self.path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        self._prev_hash = entry.get("hash", self._prev_hash)
                        self._entries.append(entry)
        except Exception as e:
            logger.warning(f"Audit load error: {e}")
