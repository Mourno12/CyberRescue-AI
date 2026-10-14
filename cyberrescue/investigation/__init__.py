"""CyberRescue Investigation Layer (Phase 3) - deterministic, read-only forensics.

For one incident it builds a reproducible Case from the Core: an annotated,
condensed timeline; an entity graph with pivots; the scope; forensic gaps;
evidence provenance with integrity; agent-claim reconciliation (citation
coverage only); and a read-only view of policy/approval state. Cases export as
JSON, Markdown or static HTML with a verifiable fingerprint.

It cannot change anything: the database is opened with SQLite ``mode=ro`` and
the facade exposes read methods only. No LLM, no clock, no randomness; evidence
content is data (``Untrusted``), never instructions; ground truth is never read.
"""
