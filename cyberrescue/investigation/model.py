"""Investigation case model - frozen, canonical, trust-labelled.

Every string that originates in evidence content (a command line, a path, a
user agent, a process name, an agent's free text) is wrapped in ``Untrusted``,
serialised as ``{"untrusted": "..."}``. Renderers must escape it and show it as
quoted data; a future LLM consumer must treat it as data. Everything else is
Core-derived (ids, hashes, rule ids, counts, inventory values, timestamps).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cyberrescue.core.audit import canonical_json

CASE_SCHEMA = "cyberrescue.case/1"
MAX_UNTRUSTED_CHARS = 2000


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Untrusted(_Frozen):
    """Attacker-influenceable text. Data, never instructions."""

    untrusted: str

    @field_validator("untrusted")
    @classmethod
    def _cap(cls, v: str) -> str:
        return v if len(v) <= MAX_UNTRUSTED_CHARS else v[:MAX_UNTRUSTED_CHARS] + "...[truncated]"


def untrusted(value: object) -> Untrusted | None:
    return None if value is None else Untrusted(untrusted=str(value))


# --- timeline -------------------------------------------------------------------

class Citation(_Frozen):
    finding_id: str
    origin: str                      # detection | agent | human | system
    rule_id: str | None = None
    relation: str                    # supports | context | contradicts


class TimelineEntry(_Frozen):
    entry: Literal["event", "burst"]
    start: str
    end: str
    host: str | None = None
    kind: str
    event_type: str
    count: int
    evidence_ids: tuple[str, ...]
    process: Untrusted | None = None
    detail: Untrusted | None = None
    cited_by: tuple[Citation, ...] = ()
    detection_rules: tuple[str, ...] = ()        # dry-run detections citing it
    observation_rules: tuple[str, ...] = ()


class Timeline(_Frozen):
    entries: tuple[TimelineEntry, ...]
    evidence_total: int
    evidence_shown: int
    condensed: bool
    filters: dict[str, Any] = Field(default_factory=dict)


# --- graph ----------------------------------------------------------------------

class GraphNode(_Frozen):
    key: str                         # "<type>:<normalised value>"
    type: str
    label: Untrusted


class GraphEdge(_Frozen):
    id: str
    src: str
    rel: str
    dst: str
    evidence_ids: tuple[str, ...]
    attrs: dict[str, Any] = Field(default_factory=dict)


class EntityGraph(_Frozen):
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    truncated: bool = False
    limits: dict[str, int] = Field(default_factory=dict)


class Related(_Frozen):
    evidence_id: str
    shared: tuple[str, ...]          # entity keys shared with the pivot
    seconds_apart: int


# --- scope, gaps, claims, provenance, policy -----------------------------------------

class Infrastructure(_Frozen):
    indicator: str
    type: str
    outcome: str
    malware_family: str
    hosts: tuple[str, ...]


class Scope(_Frozen):
    compromised_hosts: tuple[str, ...] = ()
    accessed_hosts: tuple[str, ...] = ()
    targeted_hosts: tuple[str, ...] = ()
    accounts: tuple[Untrusted, ...] = ()
    infrastructure: tuple[Infrastructure, ...] = ()
    data_classes_at_risk: tuple[str, ...] = ()
    hosts_under_hold: tuple[str, ...] = ()
    basis: dict[str, tuple[str, ...]] = Field(default_factory=dict)  # host -> finding refs


class Gap(_Frozen):
    gap_id: str
    code: Literal["G1", "G2", "G3", "G4", "G5", "G6"]
    title: str
    description: str
    host: str | None = None
    evidence_ids: tuple[str, ...] = ()
    refs: tuple[str, ...] = ()       # finding / detection / observation ids


class ClaimReconciliation(_Frozen):
    finding_id: str
    author_kind: str
    author_role: str
    summary: Untrusted
    claims: tuple[Untrusted, ...]
    supporting: int
    context: int
    contradicting: int
    rejected_citations: int
    status: Literal["evidence-backed", "partially backed", "unsupported"]


class ProvenanceRecord(_Frozen):
    evidence_id: str
    incident_id: str
    source: str
    source_ref: str
    kind: str
    event_type: str
    observed_at: str
    ingested_at: str
    provenance: str
    sensor: Untrusted | None = None
    vendor: Untrusted | None = None
    adapter: Untrusted | None = None
    ingested_by: dict[str, str]
    content_sha256: str
    record_sha256: str
    audit_event_uid: str
    integrity_ok: bool
    integrity_errors: tuple[str, ...] = ()
    cited_by: tuple[Citation, ...] = ()


class PolicyView(_Frozen):
    status: str
    severity: str | None = None
    primary_asset: str | None = None
    recruited_roles: tuple[str, ...] = ()
    holds: tuple[dict[str, Any], ...] = ()
    vetoes: tuple[dict[str, Any], ...] = ()
    signoff_request: dict[str, Any] | None = None
    action_requests: tuple[dict[str, Any], ...] = ()
    approvals: tuple[dict[str, Any], ...] = ()


class FindingView(_Frozen):
    finding_id: str
    origin: Literal["detection", "agent", "human", "system"]
    author_role: str
    rule_id: str | None = None
    detection_id: str | None = None
    severity: str | None = None
    summary: Untrusted
    supporting: int
    context: int


class DetectionView(_Frozen):
    detection_id: str
    rule_id: str
    finding_type: str
    severity: str
    confidence: str
    primary_host: str | None
    window_start: str
    window_end: str
    supporting: int
    context: int
    persisted_finding_id: str | None = None


class ObservationView(_Frozen):
    observation_id: str
    rule_id: str
    kind: str
    primary_host: str | None
    reason: Untrusted
    evidence_ids: tuple[str, ...]


class RawLine(_Frozen):
    evidence_id: str
    raw: Untrusted


class Case(_Frozen):
    case_schema: Literal["cyberrescue.case/1"] = CASE_SCHEMA
    case_id: str
    incident_id: str
    aliases: tuple[str, ...]
    title: Untrusted
    as_of: str
    ruleset_version: str
    evidence_count: int
    policy: PolicyView
    findings: tuple[FindingView, ...]
    detections: tuple[DetectionView, ...]
    observations: tuple[ObservationView, ...]
    timeline: Timeline
    graph: EntityGraph
    scope: Scope
    gaps: tuple[Gap, ...]
    claims: tuple[ClaimReconciliation, ...]
    provenance: tuple[ProvenanceRecord, ...]
    integrity: dict[str, Any]
    raw_evidence: tuple[RawLine, ...] = ()
    case_sha256: str = ""

    def content(self) -> dict[str, Any]:
        """Everything except the self-hash."""
        return self.model_dump(mode="json", exclude={"case_sha256"})

    def to_json(self) -> str:
        return canonical_json(self.model_dump(mode="json"))
