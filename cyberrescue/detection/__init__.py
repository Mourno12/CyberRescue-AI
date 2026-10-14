"""CyberRescue Detection & Correlation Engine (Phase 2C).

Deterministic, offline, explainable detection over Phase 2A evidence:

    CoreService.list_evidence -> EvidenceView -> rules (Layer 1)
        -> correlators (Layer 2) -> DetectionReport
        -> (explicit operator step) FindingPublisher -> record_finding

No LLM, no clock, no randomness. Detection reads evidence and reference data
(asset inventory, mock IOC database) only - never ground truth - and has no
path to approvals, sign-offs, actors, incident state, policy or the Commander
gate. A detection is a statement backed by evidence ids, never an authorization.
"""
