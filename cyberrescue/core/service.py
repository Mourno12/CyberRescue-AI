"""``CoreService`` — the single entry point to the CyberRescue Core.

Trust boundary (the reason this module exists):

* **Approvals** are created ONLY by ``grant_approval()``, which requires the id
  of a *registered* HUMAN actor with an approver role. There is no other path:
  the protocol ingestor never calls it, and LLM text such as
  ``{"approved": true}`` has no route into the approvals table.
* **Actors are re-loaded from the database by id** for every privileged call
  (``request_action``, ``grant_approval``), so a caller cannot hand in a
  fabricated ``Actor(role="ciso")`` object.
* **Sign-offs** count only from recruited specialist agents; **vetoes** only
  from the Compliance agent; anything else is recorded as ``CLAIM_REJECTED``.
* **Actions** are authorized only by the policy engine (``ACTION_AUTHORIZED``);
  an agent saying it acted is recorded as ``AGENT_ACTION_CLAIM`` and nothing
  more. Phase 1 has no executor — "authorized" is the end of the line.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cyberrescue.core import db
from cyberrescue.core.audit import AuditEvent, AuditLog, VerifyResult, utcnow
from cyberrescue.core.catalog import ASSET_BOUND_ACTIONS, get_action, match_actions_in_text
from cyberrescue.core.evidence import EvidenceEnvelope, parse_envelope, prepare_record
from cyberrescue.core.evidence_store import EvidenceStore, EvidenceVerifyResult
from cyberrescue.core.holds import assess_holds
from cyberrescue.core.models import (
    ActionRequest,
    ActionStatus,
    ActionTier,
    Actor,
    ActorKind,
    Approval,
    ApprovalDecision,
    Asset,
    EventType,
    EvidenceRecord,
    EvidenceRelation,
    ExecutionRecord,
    Finding,
    FindingEvidence,
    Incident,
    LegalHold,
    LinkRelation,
    PolicyDecision,
    PolicyOutcome,
    RiskSnapshot,
    SignOff,
    SignOffRequest,
    Veto,
)
from cyberrescue.core.policy import PolicyConfig, PolicyEngine
from cyberrescue.core.state_machine import TransitionResult, Trigger, next_status
from cyberrescue.core.store import CoreStore


class ApprovalError(PermissionError):
    """Raised when an approval request does not come from a valid approver."""


class CoreError(ValueError):
    """Raised on an invalid Core request (unknown incident, bad arguments)."""


class CollectorError(PermissionError):
    """Raised when an actor that may not submit evidence tries to."""


class CitationError(PermissionError):
    """Raised when an actor may not link evidence to a finding."""


class ExecutionError(PermissionError):
    """Raised when a simulated execution may not be recorded."""


# Phase 6: the only actor role that may record a simulated execution.
EXECUTOR_ROLE = "executor"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_STEP_ID = re.compile(r"^STEP-[0-9a-f]{12}$")
_PLAN_ID = re.compile(r"^PLAN-[0-9a-f]{16}$")
_CHECK = re.compile(r"^[a-z][a-z_]{0,63}$")


# Humans who may submit evidence (system collectors always may; agents never).
COLLECTOR_HUMAN_ROLES = frozenset({"operator", "ciso", "dpo", "general_counsel"})
# Upper bound on evidence ids one finding may cite in a single message.
MAX_CITATIONS_PER_FINDING = 50


@dataclass(frozen=True)
class EvidenceIngestResult:
    record: EvidenceRecord
    duplicate: bool


@dataclass
class EvidenceBatchReport:
    incident_id: str
    ingested: list[str]
    duplicates: list[str]


@dataclass(frozen=True)
class ActionOutcome:
    request: ActionRequest
    decision: PolicyDecision
    authorization_event_uid: str | None = None

    @property
    def authorized(self) -> bool:
        return self.authorization_event_uid is not None


class CoreService:
    def __init__(self, conn: sqlite3.Connection, *, config: PolicyConfig | None = None,
                 clock: Callable[[], datetime] = utcnow) -> None:
        self.conn = conn
        self.clock = clock
        self.config = config or PolicyConfig.from_env()
        self.engine = PolicyEngine(self.config)
        self.store = CoreStore(conn, clock)
        self.evidence = EvidenceStore(conn, self.store.audit)

    @classmethod
    def open(cls, path: str | Path | None = None, **kwargs: Any) -> CoreService:
        return cls(db.connect(path), **kwargs)

    @property
    def audit(self) -> AuditLog:
        return self.store.audit

    @property
    def system(self) -> Actor:
        return self.store.system_actor()

    # --- helpers --------------------------------------------------------------
    def _incident(self, incident_id: str) -> Incident:
        inc = self.store.get_incident(incident_id)
        if inc is None:
            raise CoreError(f"unknown incident {incident_id!r}")
        return inc

    def _registered(self, actor: Actor | str) -> Actor:
        actor_id = actor if isinstance(actor, str) else actor.id
        found = self.store.get_actor(actor_id)
        if found is None:
            raise ApprovalError(f"actor {actor_id!r} is not registered with the Core")
        return found

    # --- actors & assets --------------------------------------------------------
    def register_actor(self, kind: ActorKind | str, role: str, display_name: str = "",
                       external_ref: str | None = None) -> Actor:
        return self.store.register_actor(kind, role, display_name, external_ref,
                                         registered_by=self.system.id)

    def seed_assets_from_mock(self) -> int:
        """Load ``shared/mock_env/asset_inventory.json`` (provenance: simulated)."""
        from shared.mock_data import load_assets
        n = 0
        for a in load_assets():
            asset = Asset(**{k: v for k, v in a.items() if k in Asset.model_fields},
                          provenance="simulated")
            if self.store.get_asset(asset.asset_id) is None:
                self.store.add_asset(asset, actor_id=self.system.id)
                n += 1
        return n

    # --- incidents ----------------------------------------------------------------
    def open_incident(self, incident_id: str | None = None, *, title: str = "",
                      category: str | None = None, severity: str | None = None,
                      primary_asset_id: str | None = None,
                      recruited_roles: Iterable[str] = (), aliases: Iterable[str] = (),
                      opened_by: Actor | None = None, source: str = "core") -> Incident:
        """Open an incident; place any legal hold its primary asset requires."""
        with db.transaction(self.conn):
            inc = self.store.create_incident(
                incident_id=incident_id, title=title, category=category, severity=severity,
                primary_asset_id=primary_asset_id, recruited_roles=recruited_roles,
                aliases=aliases, opened_by=(opened_by or self.system).id, source=source)
            if primary_asset_id:
                self.place_holds_for(primary_asset_id, inc.id)
        return inc

    def place_holds_for(self, asset_id: str, incident_id: str | None) -> LegalHold | None:
        """Derive and record the legal hold an asset's data classes require."""
        asset = self.store.get_asset(asset_id)
        if asset is None:
            raise CoreError(f"unknown asset {asset_id!r}")
        h = assess_holds(asset)
        if not h.preservation_required:
            return None
        return self.store.add_hold(
            asset_id, incident_id=incident_id, rule_ids=list(h.preservation_rule_ids),
            requires_human_authorization=h.requires_human_authorization,
            actor_id=self.system.id)

    def apply_trigger(self, incident_id: str, trigger: Trigger | str, actor: Actor, *,
                      cause_uid: str | None = None, source: str = "core") -> TransitionResult:
        """Run the state machine; record the change or the rejection."""
        inc = self._incident(incident_id)
        res = next_status(inc.status, trigger, actor.kind, actor.role)
        trig = Trigger(trigger).value
        if not res.allowed:
            self.audit.append(
                EventType.STATE_TRANSITION_REJECTED, incident_id=incident_id,
                actor_id=actor.id, source=source,
                payload={"trigger": trig, "status": inc.status.value, "reason": res.reason},
                links=[(LinkRelation.CAUSED_BY, cause_uid)] if cause_uid else [])
        elif res.changed:
            self.store.set_status(incident_id, res.to_status, trigger=trig,
                                  actor_id=actor.id, cause_uid=cause_uid)
        return res

    # --- analysis records ---------------------------------------------------------
    def record_finding(self, incident_id: str, author: Actor, summary: str, *,
                       severity: str | None = None, claims: Iterable[str] = (),
                       evidence_ids: Iterable[str] = (),
                       evidence_relation: EvidenceRelation | str = EvidenceRelation.SUPPORTS,
                       source_uid: str | None = None, source: str = "core",
                       claim_kind: str = "protocol_claim") -> Finding:
        """Record a finding, the statements (claims) written in it, and the
        evidence it cites.

        ``claims`` are the analyst's own assertions — for WarRoom agents, the
        entries of a FINDING message's ``evidence`` list. They are stored as
        finding claims, never as evidence. ``evidence_ids`` must name existing
        evidence of the SAME incident; any invalid id rejects the whole call
        (strict programmatic API — see ``cite_evidence_from_message`` for the
        audited, lenient path used for agent messages).

        ``claim_kind`` labels the stored claims (default ``protocol_claim``;
        the Phase 2C detection publisher uses ``detection``).
        """
        inc = self._incident(incident_id)
        ids = list(dict.fromkeys(evidence_ids))
        records = [self._citable_evidence(inc.id, eid) for eid in ids]
        if records and inc.is_terminal:
            raise CoreError(f"incident {inc.id} is {inc.status.value}: citations are frozen")
        if records and not self._may_cite(author, author_id=author.id):
            raise CitationError(f"{author.kind.value}/{author.role} may not cite evidence")
        with db.transaction(self.conn):
            f = self.store.add_finding(incident_id, author_actor_id=author.id, summary=summary,
                                       severity=severity, source_uid=source_uid, source=source)
            for item in claims:
                self.store.add_claim(incident_id, content=str(item), kind=claim_kind,
                                     finding=f, actor_id=author.id, source_uid=source_uid,
                                     source=source)
            for record in records:
                self.evidence.link(f, record, relation=EvidenceRelation(evidence_relation),
                                   linked_by=author.id, source=source)
        return f

    # --- citations (finding -> evidence) --------------------------------------------
    def _citable_evidence(self, incident_id: str, evidence_id: Any) -> EvidenceRecord:
        record = self.evidence.get(evidence_id) if isinstance(evidence_id, str) else None
        if record is None or record.incident_id != incident_id:
            # One message for "missing" and "other incident": no cross-incident oracle.
            raise CoreError(f"unknown evidence id {evidence_id!r} for incident {incident_id}")
        return record

    @staticmethod
    def _may_cite(actor: Actor, *, author_id: str | None) -> bool:
        """System collectors and human operators may link any finding; an agent
        may only cite evidence in a finding it authored itself."""
        if actor.kind == ActorKind.SYSTEM:
            return True
        if actor.kind == ActorKind.HUMAN:
            return actor.role in COLLECTOR_HUMAN_ROLES
        return actor.role != "unknown" and actor.id == author_id

    def link_evidence(self, finding_id: str, evidence_id: str, *, linked_by: str,
                      relation: EvidenceRelation | str = EvidenceRelation.SUPPORTS,
                      source: str = "core") -> FindingEvidence:
        """Record that a finding cites evidence (same incident; idempotent)."""
        actor = self.store.get_actor(linked_by)
        if actor is None:
            raise CitationError(f"actor {linked_by!r} is not registered with the Core")
        finding = self.store.get_finding(finding_id)
        if finding is None:
            raise CoreError(f"unknown finding {finding_id!r}")
        inc = self._incident(finding.incident_id)
        if inc.is_terminal:
            raise CoreError(f"incident {inc.id} is {inc.status.value}: citations are frozen")
        if not self._may_cite(actor, author_id=finding.author_actor_id):
            raise CitationError(f"{actor.kind.value}/{actor.role} may not link evidence to "
                                f"finding {finding_id}")
        record = self._citable_evidence(inc.id, evidence_id)
        link, _ = self.evidence.link(finding, record, relation=EvidenceRelation(relation),
                                     linked_by=actor.id, source=source)
        return link

    def cite_evidence_from_message(self, finding: Finding, actor: Actor, evidence_ids: Any,
                                   *, source_uid: str | None = None,
                                   source: str = "core") -> tuple[list[str], list[str]]:
        """Citations taken from an agent's FINDING message (untrusted text).

        Lenient but audited: the finding stands; each valid id is linked; each
        invalid one (not a string, unknown, another incident's, over the cap)
        is recorded as CLAIM_REJECTED. Returns ``(linked_ids, rejected_refs)``.
        Citing never creates, alters or deletes evidence.
        """
        linked: list[str] = []
        rejected: list[str] = []

        def reject(ref: Any, reason: str) -> None:
            rejected.append(repr(ref))
            self.reject_claim(finding.incident_id, actor, "EVIDENCE_CITATION",
                              f"{reason}: {ref!r}"[:500], source_uid=source_uid, source=source)

        if not isinstance(evidence_ids, list):
            reject(evidence_ids, "evidence_ids must be a list of evidence ids")
            return linked, rejected
        if self._incident(finding.incident_id).is_terminal:
            for ref in evidence_ids:
                reject(ref, "incident is closed; citations are frozen")
            return linked, rejected
        if not self._may_cite(actor, author_id=finding.author_actor_id):
            for ref in evidence_ids:
                reject(ref, f"{actor.kind.value}/{actor.role} may not cite evidence")
            return linked, rejected
        seen: set[str] = set()
        for n, ref in enumerate(evidence_ids):
            if n >= MAX_CITATIONS_PER_FINDING:
                reject(ref, f"more than {MAX_CITATIONS_PER_FINDING} citations")
                continue
            if isinstance(ref, str) and ref in seen:
                continue
            try:
                record = self._citable_evidence(finding.incident_id, ref)
            except CoreError:
                reject(ref, "unknown evidence id for this incident")
                continue
            seen.add(record.id)
            self.evidence.link(finding, record, relation=EvidenceRelation.SUPPORTS,
                               linked_by=actor.id, source=source)
            linked.append(record.id)
        return linked, rejected

    def reject_claim(self, incident_id: str, actor: Actor, claim: str, reason: str, *,
                     source_uid: str | None = None, source: str = "core") -> AuditEvent:
        return self.audit.append(
            EventType.CLAIM_REJECTED, incident_id=incident_id, actor_id=actor.id,
            source=source, payload={"claim": claim, "role": actor.role, "reason": reason},
            links=[(LinkRelation.CONCERNS, source_uid)] if source_uid else [])

    def record_action_claim(self, incident_id: str, actor: Actor, actions: list[str], *,
                            summary: str = "", source_uid: str | None = None,
                            source: str = "core") -> AuditEvent:
        """An agent SAYS it acted. Recorded for the audit trail; authorizes nothing."""
        return self.audit.append(
            EventType.AGENT_ACTION_CLAIM, incident_id=incident_id, actor_id=actor.id,
            source=source,
            payload={"claimed_actions": actions, "summary": summary,
                     "note": "claim only — not an authorization or an execution"},
            links=[(LinkRelation.DERIVED_FROM, source_uid)] if source_uid else [])

    def record_signoff_request(self, incident_id: str, actor: Actor, actions: list[str], *,
                               source_uid: str | None = None,
                               source: str = "core") -> SignOffRequest | None:
        inc = self._incident(incident_id)
        if not (actor.kind == ActorKind.AGENT and actor.role == "commander"):
            self.reject_claim(incident_id, actor, "SIGNOFF_REQUEST",
                              "only the Commander may request sign-off",
                              source_uid=source_uid, source=source)
            return None
        known = [a for a in dict.fromkeys(actions) if get_action(a)]
        with db.transaction(self.conn):
            req = self.store.add_signoff_request(incident_id, actor_id=actor.id, actions=known,
                                                 source_uid=source_uid, source=source)
            for name in known:
                spec = get_action(name)
                target = inc.primary_asset_id if spec.target == "host" else None
                self.store.add_action_request(
                    incident_id, action=name, asset_id=target, tier=int(spec.tier),
                    requested_by=actor.id,
                    params={"inferred_target": target is not None},
                    links=[(LinkRelation.DERIVED_FROM, req.event_uid)], source=source)
            self.apply_trigger(incident_id, Trigger.SIGNOFF_REQUEST, actor,
                               cause_uid=req.event_uid, source=source)
        return req

    def record_signoff(self, incident_id: str, actor: Actor, *, source_uid: str | None = None,
                       source: str = "core") -> SignOff | None:
        inc = self._incident(incident_id)
        if not (actor.kind == ActorKind.AGENT and actor.role in inc.specialists):
            self.reject_claim(incident_id, actor, "SIGNOFF",
                              f"{actor.kind.value}/{actor.role} is not a recruited specialist",
                              source_uid=source_uid, source=source)
            return None
        req = self.store.latest_signoff_request(incident_id)
        if req is None:
            self.reject_claim(incident_id, actor, "SIGNOFF", "no SIGNOFF_REQUEST to sign off",
                              source_uid=source_uid, source=source)
            return None
        return self.store.add_signoff(incident_id, actor=actor, request=req,
                                      source_uid=source_uid, source=source)

    def record_veto(self, incident_id: str, actor: Actor, *, text: str,
                    regulation: str | None = None, asset_id: str | None = None,
                    source_uid: str | None = None, source: str = "core") -> list[Veto]:
        """Record a Compliance veto, scoped to the tier-3 actions it names.

        A veto that names no tier-3 action is recorded with ``action=None``,
        which blocks EVERY tier-3 action on the incident (the cautious reading;
        per protocol §E.2 a veto never blocks non-destructive containment).
        """
        inc = self._incident(incident_id)
        if not (actor.kind == ActorKind.AGENT and actor.role == "compliance"
                and "compliance" in inc.recruited_roles):
            self.reject_claim(incident_id, actor, "VETO",
                              f"{actor.kind.value}/{actor.role} may not veto",
                              source_uid=source_uid, source=source)
            return []
        named = [a for a in match_actions_in_text(text)
                 if get_action(a).tier == ActionTier.DESTRUCTIVE]
        req = self.store.latest_signoff_request(incident_id)
        with db.transaction(self.conn):
            return [self.store.add_veto(
                incident_id, actor_id=actor.id, action=action, asset_id=asset_id,
                regulation=regulation, reason=text[:2000],
                request_uid=req.event_uid if req else None,
                source_uid=source_uid, source=source) for action in (named or [None])]

    def record_risk(self, incident_id: str, *, level: str, score: float | None = None,
                    factors: dict[str, Any] | None = None, method: str = "recorded",
                    actor: Actor | None = None) -> RiskSnapshot:
        """Store a risk value (Phase 1 records values only; no scoring logic)."""
        self._incident(incident_id)
        return self.store.add_risk(incident_id, level=level, score=score,
                                   factors=factors or {}, method=method,
                                   actor_id=(actor or self.system).id)

    # --- the gate -----------------------------------------------------------------
    def request_action(self, incident_id: str, action: str, asset_id: str | None,
                       requested_by: Actor | str, *, params: dict[str, Any] | None = None,
                       request_id: str | None = None, source: str = "core") -> ActionOutcome:
        """Propose an action and run it through the policy engine.

        ALLOW -> ACTION_AUTHORIZED (the approval used, if any, is consumed).
        REQUIRE_APPROVAL -> APPROVAL_REQUESTED. DENY -> request denied.
        """
        requester = self._registered(requested_by)
        self._incident(incident_id)
        spec = get_action(action)
        with db.transaction(self.conn):
            if request_id:
                req = self.store.get_action_request(request_id)
                if req is None or (req.incident_id, req.action, req.asset_id) != \
                        (incident_id, action, asset_id):
                    raise CoreError(f"request {request_id!r} does not match "
                                    f"({incident_id}, {action}, {asset_id})")
                if req.status not in (ActionStatus.PROPOSED, ActionStatus.REQUIRES_APPROVAL):
                    raise CoreError(f"request {request_id} is already {req.status.value}")
            else:
                req = self.store.add_action_request(
                    incident_id, action=action, asset_id=asset_id,
                    tier=int(spec.tier) if spec else -1, requested_by=requester.id,
                    params=params, source=source)
            snap = self.store.snapshot(incident_id, now=self.clock())
            decision = self.engine.evaluate(action=action, asset_id=asset_id,
                                            requester=requester, snapshot=snap)
            decision = self.store.add_policy_decision(req, decision, actor_id=self.system.id)
            auth_uid = None
            if decision.outcome == PolicyOutcome.ALLOW:
                approval = (self.store.get_approval(decision.approval_id)
                            if decision.approval_id else None)
                ev = self.store.authorize(req, decision, approval=approval,
                                          actor_id=self.system.id)
                auth_uid = ev.uid
                self.apply_trigger(incident_id, Trigger.ACTION_AUTHORIZED, self.system,
                                   cause_uid=ev.uid)
            elif decision.outcome == PolicyOutcome.REQUIRE_APPROVAL and any(
                    r.effect == "require_approval" and not r.satisfied
                    for r in decision.rule_results):
                # Only when a HUMAN approval is among what's missing; unmet
                # specialist sign-offs (P4) are not something a human can grant.
                self.audit.append(
                    EventType.APPROVAL_REQUESTED, incident_id=incident_id,
                    actor_id=self.system.id,
                    payload={"request_id": req.id, "action": action, "asset_id": asset_id,
                             "unmet_rules": decision.rules_failed,
                             "reasons": decision.reasons},
                    links=[(LinkRelation.CONCERNS, decision.event_uid)])
        return ActionOutcome(request=self.store.get_action_request(req.id),
                             decision=decision, authorization_event_uid=auth_uid)

    def grant_approval(self, incident_id: str, *, action: str, asset_id: str | None,
                       approver_actor_id: str, reason: str,
                       decision: ApprovalDecision | str = ApprovalDecision.APPROVE,
                       overrides_hold: bool = False, overrides_veto: bool = False,
                       ttl_minutes: int | None = None, request_id: str | None = None,
                       source: str = "core") -> Approval:
        """THE ONLY WAY TO CREATE AN APPROVAL.

        ``approver_actor_id`` must be a registered HUMAN actor whose role is in
        ``PolicyConfig.approver_roles``. Overrides and denials need a reason.
        The approval covers exactly (incident, action, asset), expires after
        ``ttl_minutes`` (default ``PolicyConfig.approval_ttl_minutes``), and is
        consumed by the first action it authorizes.
        """
        approver = self._registered(approver_actor_id)
        if approver.kind != ActorKind.HUMAN:
            raise ApprovalError(f"approver must be a human, got {approver.kind.value}")
        if approver.role not in self.config.approver_roles:
            raise ApprovalError(f"role {approver.role!r} may not approve actions "
                                f"(approvers: {list(self.config.approver_roles)})")
        inc = self._incident(incident_id)
        if inc.is_terminal:
            raise CoreError(f"incident {incident_id} is {inc.status.value}")
        if get_action(action) is None:
            raise CoreError(f"unknown action {action!r}")
        decision = ApprovalDecision(decision)
        if (overrides_hold or overrides_veto or decision == ApprovalDecision.DENY) \
                and not (reason or "").strip():
            raise ApprovalError("a written reason is required for overrides and denials")
        ttl = ttl_minutes if ttl_minutes is not None else self.config.approval_ttl_minutes
        if ttl <= 0:
            raise ApprovalError("approval lifetime must be positive")
        concerns = None
        if request_id:
            req = self.store.get_action_request(request_id)
            if req is None or (req.incident_id, req.action, req.asset_id) != \
                    (incident_id, action, asset_id):
                raise CoreError(f"request {request_id!r} does not match the approval scope")
            concerns = req.event_uid
        return self.store.add_approval(
            incident_id, action=action, asset_id=asset_id, approver=approver,
            decision=decision, reason=reason,
            expires_at=(self.clock() + timedelta(minutes=ttl)).isoformat(),
            overrides_hold=overrides_hold, overrides_veto=overrides_veto,
            concerns_uid=concerns, source=source)

    # --- simulated execution records (Phase 6) ------------------------------------------
    def record_simulated_execution(
            self, incident_id: str, *, request_id: str, recorder_actor_id: str, action: str,
            asset_id: str | None, plan_id: str, plan_sha256: str, step_id: str, step_sha256: str, report_sha256: str,
            evidence_fingerprint: str, environment_sha256: str, outcome: str,
            criteria: list[dict[str, Any]], source: str = "core") -> ExecutionRecord:
        """THE ONLY WAY TO RECORD AN EXECUTION - and only a SIMULATED one.

        Re-checks everything itself (the caller is never trusted), inside one
        BEGIN IMMEDIATE transaction so the checks and the write cannot interleave:

        * the recorder is a registered SYSTEM actor with role ``executor``;
        * the incident exists and is open;
        * the request belongs to THIS incident, is ``authorized``, is a tier-1/2
          non-destructive catalogue action, has an ALLOW decision with the
          ``ACTION_AUTHORIZED`` event linked to it, and was requested by an actor
          policy rule P1 allows;
        * the step's ``action`` and ``asset_id`` equal the request's (no target
          substitution);
        * binding: a request carrying ``params.plan_step`` must name ``step_id``;
          one without it is accepted only for asset-bound actions;
        * the authorization is not older than the approval lifetime
          (``PolicyConfig.approval_ttl_minutes``, $CYBERRESCUE_APPROVAL_TTL_MINUTES);
        * ``evidence_fingerprint`` equals the incident's evidence now;
        * the policy engine does not DENY the request now;
        * the request has no execution record yet (the database's UNIQUE
          constraint backs this up).

        Writes ACTION_EXECUTED, ACTION_VERIFIED and the record. Never changes the
        request's status, the incident's state, approvals, sign-offs or actors.
        """
        def refuse(reason: str) -> None:
            raise ExecutionError(f"cannot record execution: {reason}")

        recorder = self._registered(recorder_actor_id)
        if not (recorder.kind == ActorKind.SYSTEM and recorder.role == EXECUTOR_ROLE):
            refuse(f"{recorder.kind.value}/{recorder.role} is not the executor")
        for name, value, pattern in (
                ("plan_id", plan_id, _PLAN_ID), ("step_id", step_id, _STEP_ID),
                ("plan_sha256", plan_sha256, _HEX64), ("step_sha256", step_sha256, _HEX64),
                ("report_sha256", report_sha256, _HEX64),
                ("evidence_fingerprint", evidence_fingerprint, _HEX64),
                ("environment_sha256", environment_sha256, _HEX64)):
            if not isinstance(value, str) or not pattern.match(value):
                refuse(f"{name} is malformed")
        if outcome not in ("succeeded", "failed"):
            refuse("outcome must be 'succeeded' or 'failed'")
        if not isinstance(criteria, list) or not criteria or not all(
                isinstance(c, dict) and set(c) == {"check", "satisfied"}
                and isinstance(c["check"], str) and _CHECK.match(c["check"])
                and isinstance(c["satisfied"], bool) for c in criteria):
            refuse("criteria must be a non-empty list of {check, satisfied}")
        if outcome == "succeeded" and not all(c["satisfied"] for c in criteria):
            refuse("a success needs every criterion satisfied")

        with db.transaction(self.conn):
            inc = self._incident(incident_id)
            if inc.is_terminal:
                refuse(f"incident {inc.id} is {inc.status.value}")
            req = self.store.get_action_request(request_id) \
                if isinstance(request_id, str) else None
            if req is None or req.incident_id != inc.id:
                refuse("the request does not belong to this incident")
            if (action, asset_id) != (req.action, req.asset_id):
                refuse("the step's action or target differs from the authorized request")
            if req.status != ActionStatus.AUTHORIZED:
                refuse(f"the request is {req.status.value}, not authorized")
            spec = get_action(req.action)
            if spec is None or spec.tier not in (ActionTier.LOW, ActionTier.CONTAINMENT) \
                    or spec.destructive or req.tier != int(spec.tier):
                refuse("only tier-1/2 non-destructive actions can be recorded")
            rows = self.store.decisions_for(req.id)
            if not rows or rows[-1]["outcome"] != PolicyOutcome.ALLOW.value:
                refuse("the request has no ALLOW decision")
            decision_uid = rows[-1]["event_uid"]
            auth = next((e for e in self.audit.events(inc.id,
                                                      event_type=EventType.ACTION_AUTHORIZED)
                         if e.payload.get("request_id") == req.id
                         and any(LinkRelation(lk.relation) == LinkRelation.AUTHORIZES
                                 and lk.target_uid == decision_uid for lk in e.links)), None)
            if auth is None:
                refuse("no ACTION_AUTHORIZED event is linked to the request's decision")
            requester = self.store.get_actor(req.requested_by) if req.requested_by else None
            cfg = self.config
            if requester is None or not (
                    (requester.kind == ActorKind.AGENT
                     and requester.role in cfg.agent_requester_roles)
                    or (requester.kind == ActorKind.HUMAN
                        and requester.role in cfg.human_requester_roles)):
                refuse("the request was not made by an actor allowed to request actions")
            bound = req.params.get("plan_step")
            if bound is not None and bound != step_id:
                refuse("the authorization names a different plan step")
            if bound is None and req.action not in ASSET_BOUND_ACTIONS:
                refuse(f"{req.action} needs an authorization bound to its plan step "
                       "(params.plan_step)")
            now = self.clock()
            if now - datetime.fromisoformat(auth.ts) > timedelta(
                    minutes=cfg.approval_ttl_minutes):
                refuse(f"the authorization is older than {cfg.approval_ttl_minutes} minutes")
            if evidence_fingerprint != self.store.evidence_fingerprint(inc.id):
                refuse("evidence_fingerprint does not match the incident's evidence")
            existing = self.store.execution_record_for(req.id)
            if existing is not None:
                refuse(f"the request was already executed (record {existing.id})")
            current = self.engine.evaluate(action=req.action, asset_id=req.asset_id,
                                           requester=requester,
                                           snapshot=self.store.snapshot(inc.id, now))
            if PolicyOutcome(current.outcome) == PolicyOutcome.DENY:
                refuse(f"current policy denies the action ({', '.join(current.rules_failed)})")
            try:
                return self.store.add_execution_record(
                    req, recorder_id=recorder.id, authorized_event_uid=auth.uid,
                    plan_id=plan_id, plan_sha256=plan_sha256, step_id=step_id,
                    step_sha256=step_sha256, report_sha256=report_sha256,
                    evidence_fingerprint=evidence_fingerprint,
                    environment_sha256=environment_sha256, outcome=outcome,
                    criteria=[{"check": c["check"], "satisfied": c["satisfied"]}
                              for c in criteria], source=source)
            except sqlite3.IntegrityError as e:
                refuse(f"rejected by the database ({e})")

    def execution_records(self, incident_ref: str) -> list[ExecutionRecord]:
        iid = self.store.resolve_incident(incident_ref)
        if iid is None:
            raise CoreError(f"no Core incident for {incident_ref!r}")
        return self.store.execution_records(iid)

    # --- evidence (Phase 2A) ----------------------------------------------------------
    # Evidence is externally observed data. Only collectors — a SYSTEM actor, or
    # a human with an operator/approver role — may submit it. LLM agents never
    # can: they may only CITE existing evidence ids in their findings. Evidence
    # is never parsed as protocol, never enters the policy snapshot, and has no
    # path to approvals, actors or incident state.

    def _collector(self, actor_id: str) -> Actor:
        actor = self.store.get_actor(actor_id)
        if actor is None:
            raise CollectorError(f"actor {actor_id!r} is not registered with the Core")
        if actor.kind == ActorKind.SYSTEM or (
                actor.kind == ActorKind.HUMAN and actor.role in COLLECTOR_HUMAN_ROLES):
            return actor
        raise CollectorError(f"{actor.kind.value}/{actor.role} may not submit evidence "
                             "(only collectors and human operators; agents may only cite)")

    def _open_incident_for_evidence(self, incident_ref: str) -> Incident:
        iid = self.store.resolve_incident(incident_ref)
        if iid is None:
            raise CoreError(f"no Core incident for {incident_ref!r}")
        inc = self._incident(iid)
        if inc.is_terminal:
            raise CoreError(f"incident {iid} is {inc.status.value}: new evidence is rejected "
                            "for closed incidents (the incident is not reopened)")
        return inc

    def _prepare_evidence(self, inc: Incident, envelope: EvidenceEnvelope | dict[str, Any],
                          collector: Actor, now: datetime) -> dict[str, Any]:
        env = parse_envelope(envelope)
        asset = self.store.get_asset(env.host) if env.host else None
        return prepare_record(env, incident_id=inc.id, ingested_by=collector.id,
                              ingested_at=now, asset_id=asset.asset_id if asset else None)

    def ingest_evidence(self, incident_ref: str, envelope: EvidenceEnvelope | dict[str, Any],
                        *, collector_id: str, source: str = "collector") -> EvidenceIngestResult:
        """Validate, seal and store one piece of evidence (idempotent by id)."""
        collector = self._collector(collector_id)
        inc = self._open_incident_for_evidence(incident_ref)
        fields = self._prepare_evidence(inc, envelope, collector, self.clock())
        record, duplicate = self.evidence.add(fields, source=source)
        return EvidenceIngestResult(record=record, duplicate=duplicate)

    def ingest_evidence_batch(self, incident_ref: str,
                              envelopes: Iterable[EvidenceEnvelope | dict[str, Any]], *,
                              collector_id: str,
                              source: str = "collector") -> EvidenceBatchReport:
        """All-or-nothing: every envelope is validated before any is stored."""
        collector = self._collector(collector_id)
        inc = self._open_incident_for_evidence(incident_ref)
        now = self.clock()
        prepared, errors = [], []
        for i, env in enumerate(envelopes, start=1):
            try:
                prepared.append(self._prepare_evidence(inc, env, collector, now))
            except ValueError as e:
                errors.append(f"item {i}: {e}")
        if errors:
            raise CoreError("evidence batch rejected, nothing stored: " + " | ".join(errors[:20]))
        report = EvidenceBatchReport(incident_id=inc.id, ingested=[], duplicates=[])
        with db.transaction(self.conn):
            for fields in prepared:
                record, duplicate = self.evidence.add(fields, source=source)
                (report.duplicates if duplicate else report.ingested).append(record.id)
        return report

    def get_evidence(self, evidence_id: str) -> EvidenceRecord | None:
        return self.evidence.get(evidence_id)

    def list_evidence(self, incident_ref: str, **filters: Any) -> list[EvidenceRecord]:
        iid = self.store.resolve_incident(incident_ref)
        if iid is None:
            raise CoreError(f"no Core incident for {incident_ref!r}")
        return self.evidence.list(iid, **filters)

    def verify_evidence(self, incident_ref: str) -> EvidenceVerifyResult:
        iid = self.store.resolve_incident(incident_ref)
        if iid is None:
            raise CoreError(f"no Core incident for {incident_ref!r}")
        return self.evidence.verify(iid)

    # --- audit ----------------------------------------------------------------------
    def verify_audit(self, incident_id: str | None = None) -> VerifyResult:
        return self.audit.verify(incident_id)
