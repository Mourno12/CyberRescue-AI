"""Typed entities for the CyberRescue Core.

The Core is the deterministic source of truth: LLM agents *propose*, the Core
*records and decides*. These models are the in-memory shape of the rows in the
SQLite store (``db.py``) and the inputs/outputs of the policy engine
(``policy.py``). Pure Pydantic — no I/O, no Band, no LLM.

Timestamps are UTC ISO-8601 strings (the same style the WarRoom code uses);
the only ``datetime`` is ``IncidentSnapshot.now``, which the policy engine uses
for approval expiry so evaluation stays a pure function of its inputs.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum, IntEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


# --- Vocabulary -------------------------------------------------------------

class ActorKind(str, Enum):
    AGENT = "agent"
    HUMAN = "human"
    SYSTEM = "system"


# Roles an agent can hold. "unknown" is assigned to a sender the transport
# roster doesn't recognise — it can speak (its messages are audited) but can
# never sign off, veto, or drive state.
AGENT_ROLES = frozenset({
    "triage", "threat_intel", "compliance", "commander", "facilitator", "unknown",
})
# Specialists whose sign-off a containment action needs (WarRoom's roster).
SPECIALIST_ROLES = frozenset({"threat_intel", "compliance"})
# Roles a human can hold. Which of them may approve is policy config.
HUMAN_ROLES = frozenset({"ciso", "dpo", "general_counsel", "operator", "observer"})


class IncidentStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    AWAITING_SIGNOFF = "AWAITING_SIGNOFF"
    AWAITING_HUMAN = "AWAITING_HUMAN"
    RESPONDING = "RESPONDING"
    RESOLVED = "RESOLVED"
    CLOSED_FALSE_POSITIVE = "CLOSED_FALSE_POSITIVE"


TERMINAL_STATUSES = frozenset({IncidentStatus.RESOLVED, IncidentStatus.CLOSED_FALSE_POSITIVE})


class EventType(str, Enum):
    # identity / setup
    ACTOR_REGISTERED = "ACTOR_REGISTERED"
    ASSET_SEEDED = "ASSET_SEEDED"
    INCIDENT_OPENED = "INCIDENT_OPENED"
    ALIAS_REGISTERED = "ALIAS_REGISTERED"
    # transport messages
    PROTOCOL_MESSAGE = "PROTOCOL_MESSAGE"
    UNSTRUCTURED_MESSAGE = "UNSTRUCTURED_MESSAGE"
    HUMAN_MESSAGE = "HUMAN_MESSAGE"
    INCIDENT_REF_MISMATCH = "INCIDENT_REF_MISMATCH"
    AGENT_ACTION_CLAIM = "AGENT_ACTION_CLAIM"
    CLAIM_REJECTED = "CLAIM_REJECTED"
    # evidence (Phase 2A): externally observed data, and findings citing it
    EVIDENCE_INGESTED = "EVIDENCE_INGESTED"
    FINDING_EVIDENCE_LINKED = "FINDING_EVIDENCE_LINKED"
    # analysis / positions
    CLAIM_RECORDED = "CLAIM_RECORDED"          # a statement written inside a finding
    # LEGACY (schema v1): claims were recorded under this misleading name. Kept
    # so v1 audit chains stay readable and verifiable; never emitted since v2.
    EVIDENCE_RECORDED = "EVIDENCE_RECORDED"
    FINDING_RECORDED = "FINDING_RECORDED"
    SIGNOFF_REQUESTED = "SIGNOFF_REQUESTED"
    SIGNOFF_RECORDED = "SIGNOFF_RECORDED"
    VETO_RECORDED = "VETO_RECORDED"
    LEGAL_HOLD_PLACED = "LEGAL_HOLD_PLACED"
    RISK_RECORDED = "RISK_RECORDED"
    # the gate
    ACTION_PROPOSED = "ACTION_PROPOSED"
    POLICY_DECISION = "POLICY_DECISION"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    ACTION_AUTHORIZED = "ACTION_AUTHORIZED"
    GATE_DECISION = "GATE_DECISION"   # Commander hook verdict (shadow or enforce)
    # lifecycle
    STATE_CHANGED = "STATE_CHANGED"
    STATE_TRANSITION_REJECTED = "STATE_TRANSITION_REJECTED"
    # Phase 6: emitted ONLY by CoreService.record_simulated_execution, for
    # SIMULATED executions (payload "mode": "simulated"); never for real ones.
    ACTION_EXECUTED = "ACTION_EXECUTED"
    ACTION_VERIFIED = "ACTION_VERIFIED"


# Post-plan ACCOUNTABILITY events: they record what happened to an authorization
# after a case/plan was built. A Phase 3 case anchors its audit state at the
# last event that is NOT one of these (see investigation/builder.case_anchor),
# so recording an execution does not change an existing case/plan identity,
# while the full chain - these events included - is still verified.
ACCOUNTABILITY_EVENT_TYPES = frozenset({EventType.ACTION_EXECUTED.value,
                                        EventType.ACTION_VERIFIED.value})


class LinkRelation(str, Enum):
    """Typed edge from a NEWER audit event to an OLDER one it refers to.

    Read ``A --relation--> B`` as "A <relation> B", e.g.
    ``CLAIM --supports--> FINDING``, ``FINDING_EVIDENCE_LINKED --cites-->
    EVIDENCE_INGESTED``, ``POLICY_DECISION --evaluates--> ACTION_PROPOSED``.
    """

    DERIVED_FROM = "derived_from"   # domain event -> the transport message it came from
    SUPPORTS = "supports"           # claim -> the finding it was written in
    CITES = "cites"                 # finding-evidence link -> EVIDENCE_INGESTED
    RESPONDS_TO = "responds_to"     # signoff/veto -> signoff request
    EVALUATES = "evaluates"         # policy decision -> action proposed
    RELIED_ON = "relied_on"         # policy decision -> approval/signoff it used
    BLOCKED_BY = "blocked_by"       # policy decision -> veto/hold that blocked it
    AUTHORIZES = "authorizes"       # action authorized -> policy decision
    CONSUMES = "consumes"           # action authorized -> approval (single use)
    CAUSED_BY = "caused_by"         # state change -> triggering event
    CONCERNS = "concerns"           # approval/claim -> the event it is about
    # Phase 6 (simulated executions only).
    EXECUTES = "executes"           # action executed -> action authorized
    VERIFIES = "verifies"           # action verified -> action executed


class ActionTier(IntEnum):
    READ_ONLY = 0      # queries/enrichment — not actions, never gated
    LOW = 1            # non-destructive, e.g. imaging, internal notification
    CONTAINMENT = 2    # reversible containment, e.g. isolate host
    DESTRUCTIVE = 3    # destructive/irreversible/external, e.g. wipe host


class PolicyOutcome(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"   # blocked, but a valid human approval can unblock it
    DENY = "DENY"                           # hard deny — no approval can unblock it


class ActionStatus(str, Enum):
    PROPOSED = "proposed"
    REQUIRES_APPROVAL = "requires_approval"
    DENIED = "denied"
    AUTHORIZED = "authorized"
    # Reserved for Phase 4.
    EXECUTED = "executed"
    VERIFIED = "verified"
    FAILED = "failed"


class ApprovalDecision(str, Enum):
    APPROVE = "approve"
    DENY = "deny"


class VetoStatus(str, Enum):
    ACTIVE = "active"
    OVERRIDDEN = "overridden"
    WITHDRAWN = "withdrawn"


class HoldStatus(str, Enum):
    ACTIVE = "active"
    RELEASED = "released"


# --- Entities ---------------------------------------------------------------

class _Model(BaseModel):
    model_config = {"use_enum_values": False}


class Actor(_Model):
    id: str
    kind: ActorKind
    role: str
    display_name: str = ""
    external_ref: str | None = None
    created_at: str = ""


class Asset(_Model):
    asset_id: str
    hostname: str | None = None
    role: str | None = None
    criticality: str = "low"
    network_segment: str | None = None
    data_classes: list[str] = Field(default_factory=list)
    provenance: str = "simulated"


class Incident(_Model):
    id: str
    title: str = ""
    category: str | None = None
    severity: str | None = None
    status: IncidentStatus = IncidentStatus.NEW
    primary_asset_id: str | None = None
    recruited_roles: list[str] = Field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    closed_at: str | None = None

    @property
    def specialists(self) -> set[str]:
        """Recruited roles whose sign-off containment needs."""
        return set(self.recruited_roles) & SPECIALIST_ROLES

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES


class EventLink(_Model):
    relation: LinkRelation
    target_uid: str


class AuditEvent(_Model):
    uid: str
    chain: str
    incident_id: str | None = None
    seq: int
    ts: str
    event_type: str
    actor_id: str | None = None
    source: str = "core"
    external_id: str | None = None
    protocol_type: str | None = None
    protocol_valid: bool | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    links: list[EventLink] = Field(default_factory=list)
    prev_hash: str
    hash: str


class FindingClaim(_Model):
    """A statement written inside a finding (e.g. an entry in a FINDING
    message's ``evidence`` list). It is the analyst's CLAIM — not evidence."""
    id: str
    incident_id: str
    finding_id: str | None = None
    kind: str = "text"
    content: str = ""
    event_uid: str
    created_at: str = ""


class EvidenceKind(str, Enum):
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    AUTH = "auth"
    LOG = "log"
    ALERT = "alert"
    IOC = "ioc"
    OTHER = "other"


class Provenance(str, Enum):
    SYNTHETIC = "synthetic"   # generated for tests/demos
    REPLAYED = "replayed"     # real recorded telemetry, replayed offline
    LIVE = "live"             # collected from a live system


class EvidenceRelation(str, Enum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    CONTEXT = "context"


class EvidenceRecord(_Model):
    """Externally observed security data bound to exactly one incident.

    Immutable once stored. ``content_sha256`` seals ``raw``; ``record_sha256``
    seals every stored field (see ``evidence.SEALED_FIELDS``); both are also
    recorded in the EVIDENCE_INGESTED audit event.
    """
    id: str
    incident_id: str
    source: str
    source_ref: str = ""
    kind: EvidenceKind
    event_type: str
    observed_at: str
    ingested_at: str
    host: str | None = None
    asset_id: str | None = None
    user: str | None = None
    raw: str
    data: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance
    content_sha256: str
    record_sha256: str
    ingested_by: str
    event_uid: str


class FindingEvidence(_Model):
    finding_id: str
    evidence_id: str
    relation: EvidenceRelation = EvidenceRelation.SUPPORTS
    linked_by: str
    event_uid: str
    created_at: str = ""


class Finding(_Model):
    id: str
    incident_id: str
    author_actor_id: str | None = None
    severity: str | None = None
    summary: str = ""
    event_uid: str
    created_at: str = ""


class SignOffRequest(_Model):
    """A Commander SIGNOFF_REQUEST — the plan specialists sign off against."""
    event_uid: str
    incident_id: str
    actor_id: str | None = None
    actions: list[str] = Field(default_factory=list)
    created_at: str = ""


class SignOff(_Model):
    id: str
    incident_id: str
    actor_id: str
    actor_role: str = ""
    request_event_uid: str | None = None
    covered_actions: list[str] = Field(default_factory=list)
    event_uid: str
    created_at: str = ""


class Veto(_Model):
    id: str
    incident_id: str
    actor_id: str
    action: str | None = None      # None = every tier-3 action on the incident
    asset_id: str | None = None    # None = any asset
    regulation: str | None = None
    reason: str = ""
    status: VetoStatus = VetoStatus.ACTIVE
    event_uid: str
    created_at: str = ""


class LegalHold(_Model):
    id: str
    asset_id: str
    incident_id: str | None = None
    rule_ids: list[str] = Field(default_factory=list)
    requires_human_authorization: bool = False
    status: HoldStatus = HoldStatus.ACTIVE
    event_uid: str
    created_at: str = ""


class ActionRequest(_Model):
    id: str
    incident_id: str
    action: str
    asset_id: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    tier: int = 0
    requested_by: str | None = None
    status: ActionStatus = ActionStatus.PROPOSED
    event_uid: str
    created_at: str = ""
    updated_at: str = ""


class Approval(_Model):
    id: str
    incident_id: str
    action: str
    asset_id: str | None = None
    approver_actor_id: str
    # Joined from ``actors`` on read so the policy engine can re-validate the
    # approver (defense in depth) without trusting the approval row alone.
    approver_kind: ActorKind | None = None
    approver_role: str | None = None
    decision: ApprovalDecision = ApprovalDecision.APPROVE
    overrides_hold: bool = False
    overrides_veto: bool = False
    reason: str = ""
    expires_at: str
    consumed_by_request_id: str | None = None
    consumed_at: str | None = None
    event_uid: str
    created_at: str = ""


class ExecutionRecord(_Model):
    """Phase 6: the Core's record that a SIMULATED execution used one authorized
    action request (schema v3 ``execution_records``; append-only, one per request).
    ``action_requests.status`` stays ``authorized``: this record is the source of
    truth for "this authorization has been used"."""
    id: str
    incident_id: str
    action_request_id: str
    mode: Literal["simulated"] = "simulated"
    action: str
    asset_id: str | None = None
    plan_id: str
    plan_sha256: str
    step_id: str
    step_sha256: str
    report_sha256: str
    evidence_fingerprint: str
    environment_sha256: str
    outcome: Literal["succeeded", "failed"]
    criteria: list[dict[str, Any]] = Field(default_factory=list)
    audit_head_hash: str
    recorded_by: str
    authorized_event_uid: str
    executed_event_uid: str
    verified_event_uid: str
    event_uid: str = ""
    created_at: str = ""


class RiskSnapshot(_Model):
    id: str
    incident_id: str
    level: str
    score: float | None = None
    factors: dict[str, Any] = Field(default_factory=dict)
    method: str = "recorded"
    event_uid: str
    created_at: str = ""


# --- Policy I/O ---------------------------------------------------------------

class RuleResult(_Model):
    """One policy rule that fired.

    ``effect`` is what the rule demands (hard ``deny`` or ``require_approval``);
    ``satisfied`` is True when a valid human approval met the demand.
    """
    rule: str
    effect: str                   # "deny" | "require_approval"
    reason: str
    satisfied: bool = False


class PolicyDecision(_Model):
    id: str | None = None
    action_request_id: str | None = None
    incident_id: str | None = None
    action: str
    asset_id: str | None = None
    tier: int | None = None
    outcome: PolicyOutcome
    rule_results: list[RuleResult] = Field(default_factory=list)
    approval_id: str | None = None
    relied_on_event_uids: list[str] = Field(default_factory=list)
    blocked_by_event_uids: list[str] = Field(default_factory=list)
    policy_version: str = ""
    snapshot_hash: str = ""
    event_uid: str | None = None
    created_at: str | None = None

    @property
    def rules_failed(self) -> list[str]:
        return [r.rule for r in self.rule_results if not r.satisfied]

    @property
    def reasons(self) -> list[str]:
        return [f"{r.rule}: {r.reason}" for r in self.rule_results if not r.satisfied]


class IncidentSnapshot(_Model):
    """Everything the policy engine may look at — nothing else.

    Built by the store from persisted records only. Nothing an LLM wrote
    reaches the policy engine except via records the Core itself validated
    (sign-offs from recruited specialists, vetoes from Compliance).
    """
    incident: Incident | None = None
    assets: dict[str, Asset] = Field(default_factory=dict)
    signoff_request: SignOffRequest | None = None
    signoffs: list[SignOff] = Field(default_factory=list)      # responding to signoff_request
    vetoes: list[Veto] = Field(default_factory=list)           # active only
    holds: list[LegalHold] = Field(default_factory=list)       # active only
    approvals: list[Approval] = Field(default_factory=list)    # unconsumed only
    now: datetime
