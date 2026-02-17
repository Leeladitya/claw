# knowledge/ — Domain Memory

## What This Is (for everyone)

Claw remembers. Every time it processes content from a website, it records what happened — was it allowed, modified, or denied? What rules matched? Over time, websites build reputations: trusted, suspicious, mixed, or unknown.

Recent memories matter more than old ones (exponential decay with a 1-week halflife). So if a domain was clean for months but started triggering flags last week, the system notices.

This is NOT a neural network or opaque ML model. It's a simple log that anyone can read, audit, or delete. Transparency by design.

## What This Is (for developers)

**hub.py** — JSONL-backed key-value store with domain-scoped retrieval. Entries have timestamps for temporal decay scoring (halflife=604800s). Reputation computed from allowed/denied/modified ratios weighted by recency.

**models.py** — KnowledgeEntry, DomainReputation, KnowledgeQuery data classes.
