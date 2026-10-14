"""Persistence for the Core's domain records.

Invariant: every write here produces its audit event **in the same
transaction** (the domain row stores that event's ``event_uid``). Mutable
fields — incident status, action-request status, approval consumption — only
ever change inside a method that also appends the audit event explaining the
change. Nothing in this module decides policy; ``policy.py`` does, and
``service.py`` orchestrates.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any

from cyberrescue.core.audit import AuditEvent, AuditLog, LinkSpec, canonical_json, utcnow
from cyberrescue.core.db import transaction
from cyberrescue.core.ids import (
    generate_incident_id,
    is_valid_incident_id,
    legacy_alias_for,
    parse_incident_ref,
)
from cyberrescue.core.models import (
    AGENT_ROLES,
    HUMAN_ROLES,
    ActionRequest,
    ActionStatus,
    Actor,
    ActorKind,
    Approval,
    ApprovalDecision,
    Asset,
    EventType,
    ExecutionRecord,
    Finding,
    FindingClaim,
    HoldStatus,
    Incident,
    IncidentSnapshot,
    IncidentStatus,
    LegalHold,
    LinkRelation,
    PolicyDecision,
    PolicyOutcome,
    RiskSnapshot,
    SignOff,
    SignOffRequest,
    Veto,
    VetoStatus,
)

SYSTEM_ACTOR_REF = "core:system"


def _new_id() -> str:
    return uuid.uuid4().hex


def _j(value: Any) -> str:
    return json.dumps(value, default=str)


class CoreStore:
    def __init__(self, conn: sqlite3.Connection,
                 clock: Callable[[], datetime] = utcnow) -> None:
        self.conn = conn
        self.clock = clock
        self.audit = AuditLog(conn, clock)

    def _ts(self) -> str:
        return self.clock().isoformat()

    def _one(self, sql: str, args: Iterable[Any] = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, tuple(args)).fetchone()

    def _all(self, sql: str, args: Iterable[Any] = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, tuple(args)).fetchall()

    # --- actors -------------------------------------------------------------
    @staticmethod
    def _actor(row: sqlite3.Row) -> Actor:
        return Actor(id=row["id"], kind=ActorKind(row["kind"]), role=row["role"],
                     display_name=row["display_name"], external_ref=row["external_ref"],
                     created_at=row["created_at"])

    def get_actor(self, actor_id: str) -> Actor | None:
        row = self._one("SELECT * FROM actors WHERE id = ?", (actor_id,))
        return self._actor(row) if row else None

    def find_actor(self, external_ref: str) -> Actor | None:
        row = self._one("SELECT * FROM actors WHERE external_ref = ?", (external_ref,))
        return self._actor(row) if row else None

    def register_actor(self, kind: ActorKind | str, role: str, display_name: str = "",
                       external_ref: str | None = None, *,
                       registered_by: str | None = None) -> Actor:
        """Register an actor. Identity is sticky: an existing ``external_ref``
        returns the existing actor unchanged (a later message cannot re-role it)."""
        kind = ActorKind(kind)
        if kind == ActorKind.AGENT and role not in AGENT_ROLES:
            raise ValueError(f"unknown agent role {role!r}; expected one of {sorted(AGENT_ROLES)}")
        if kind == ActorKind.HUMAN and role not in HUMAN_ROLES:
            raise ValueError(f"unknown human role {role!r}; expected one of {sorted(HUMAN_ROLES)}")
        if external_ref:
            existing = self.find_actor(external_ref)
            if existing:
                return existing
        actor = Actor(id=_new_id(), kind=kind, role=role, display_name=display_name,
                      external_ref=external_ref, created_at=self._ts())
        with transaction(self.conn):
            self.conn.execute(
                "INSERT INTO actors(id, kind, role, display_name, external_ref, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (actor.id, kind.value, role, display_name, external_ref, actor.created_at))
            self.audit.append(EventType.ACTOR_REGISTERED, actor_id=registered_by or actor.id,
                              payload={"actor_id": actor.id, "kind": kind.value, "role": role,
                                       "display_name": display_name,
                                       "external_ref": external_ref})
        return actor

    def system_actor(self) -> Actor:
        return self.find_actor(SYSTEM_ACTOR_REF) or self.register_actor(
            ActorKind.SYSTEM, "core", "CyberRescue Core", SYSTEM_ACTOR_REF)

    # --- assets -------------------------------------------------------------
    @staticmethod
    def _asset(row: sqlite3.Row) -> Asset:
        return Asset(asset_id=row["asset_id"], hostname=row["hostname"], role=row["role"],
                     criticality=row["criticality"], network_segment=row["network_segment"],
                     data_classes=json.loads(row["data_classes"]), provenance=row["provenance"])

    def get_asset(self, asset_id: str | None) -> Asset | None:
        if not asset_id:
            return None
        row = self._one("SELECT * FROM assets WHERE asset_id = ?", (asset_id,))
        return self._asset(row) if row else None

    def list_assets(self) -> list[Asset]:
        return [self._asset(r) for r in self._all("SELECT * FROM assets ORDER BY asset_id")]

    def add_asset(self, asset: Asset, *, actor_id: str | None = None) -> Asset:
        """Insert an asset once (Phase 1 does not update inventory records)."""
        existing = self.get_asset(asset.asset_id)
        if existing:
            return existing
        with transaction(self.conn):
            self.conn.execute(
                "INSERT INTO assets(asset_id, hostname, role, criticality, network_segment, "
                "data_classes, provenance, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (asset.asset_id, asset.hostname, asset.role, asset.criticality,
                 asset.network_segment, _j(asset.data_classes), asset.provenance, self._ts()))
            self.audit.append(EventType.ASSET_SEEDED, actor_id=actor_id,
                              payload=asset.model_dump())
        return asset

    # --- incidents ----------------------------------------------------------
    @staticmethod
    def _incident(row: sqlite3.Row) -> Incident:
        return Incident(id=row["id"], title=row["title"], category=row["category"],
                        severity=row["severity"], status=IncidentStatus(row["status"]),
                        primary_asset_id=row["primary_asset_id"],
                        recruited_roles=json.loads(row["recruited_roles"]),
                        created_at=row["created_at"], updated_at=row["updated_at"],
                        closed_at=row["closed_at"])

    def get_incident(self, incident_id: str) -> Incident | None:
        row = self._one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        return self._incident(row) if row else None

    def resolve_incident(self, ref: str) -> str | None:
        """Existing incident id for a reference (alias, id, or decorated id)."""
        key = (ref or "").strip().upper()
        row = self._one("SELECT incident_id FROM incident_aliases WHERE alias = ?", (key,))
        if row:
            return row["incident_id"]
        parsed = parse_incident_ref(key)
        if parsed and self.get_incident(parsed):
            return parsed
        return None

    def next_generated_id(self) -> str:
        now = self.clock()
        prefix = generate_incident_id(1, now)[:-4]  # "INC-YYYYMMDD-"
        n = self._one("SELECT COUNT(*) AS n FROM incidents WHERE id LIKE ?",
                      (prefix + "%",))["n"]
        return generate_incident_id(n + 1, now)

    def create_incident(self, *, incident_id: str | None = None, title: str = "",
                        category: str | None = None, severity: str | None = None,
                        primary_asset_id: str | None = None,
                        recruited_roles: Iterable[str] = (), aliases: Iterable[str] = (),
                        opened_by: str | None = None, source: str = "core") -> Incident:
        iid = (incident_id or self.next_generated_id()).upper()
        if not is_valid_incident_id(iid):
            raise ValueError(f"invalid incident id {iid!r}")
        if self.get_incident(iid):
            raise ValueError(f"incident {iid} already exists")
        if primary_asset_id and not self.get_asset(primary_asset_id):
            raise ValueError(f"unknown asset {primary_asset_id!r}; seed assets first")
        roles = sorted(set(recruited_roles))
        alias_set = {a.strip().upper() for a in aliases if a}
        if legacy_alias_for(iid):
            alias_set.add(legacy_alias_for(iid))
        now = self._ts()
        inc = Incident(id=iid, title=title, category=category, severity=severity,
                       status=IncidentStatus.NEW, primary_asset_id=primary_asset_id,
                       recruited_roles=roles, created_at=now, updated_at=now)
        with transaction(self.conn):
            self.conn.execute(
                "INSERT INTO incidents(id, title, category, severity, status, "
                "primary_asset_id, recruited_roles, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (iid, title, category, severity, inc.status.value, primary_asset_id,
                 _j(roles), now, now))
            self.audit.append(EventType.INCIDENT_OPENED, incident_id=iid, actor_id=opened_by,
                              source=source, payload=inc.model_dump(mode="json"))
            for alias in sorted(alias_set):
                self.conn.execute(
                    "INSERT INTO incident_aliases(alias, incident_id, created_at) VALUES (?,?,?)",
                    (alias, iid, now))
                self.audit.append(EventType.ALIAS_REGISTERED, incident_id=iid,
                                  actor_id=opened_by, source=source, payload={"alias": alias})
        return inc

    def open_incidents_for_asset(self, asset_id: str) -> list[str]:
        """Non-terminal incidents whose primary asset is ``asset_id``, newest first."""
        return [r["id"] for r in self._all(
            "SELECT id FROM incidents WHERE primary_asset_id = ? AND status NOT IN (?, ?) "
            "ORDER BY updated_at DESC, id DESC",
            (asset_id, IncidentStatus.RESOLVED.value,
             IncidentStatus.CLOSED_FALSE_POSITIVE.value))]

    def aliases_of(self, incident_id: str) -> list[str]:
        return [r["alias"] for r in self._all(
            "SELECT alias FROM incident_aliases WHERE incident_id = ? ORDER BY alias",
            (incident_id,))]

    def set_status(self, incident_id: str, new_status: IncidentStatus, *, trigger: str,
                   actor_id: str | None, cause_uid: str | None) -> AuditEvent:
        inc = self.get_incident(incident_id)
        if inc is None:
            raise KeyError(incident_id)
        now = self._ts()
        closed = now if new_status in (IncidentStatus.RESOLVED,
                                       IncidentStatus.CLOSED_FALSE_POSITIVE) else None
        with transaction(self.conn):
            self.conn.execute(
                "UPDATE incidents SET status = ?, updated_at = ?, "
                "closed_at = COALESCE(?, closed_at) WHERE id = ?",
                (new_status.value, now, closed, incident_id))
            return self.audit.append(
                EventType.STATE_CHANGED, incident_id=incident_id, actor_id=actor_id,
                payload={"from": inc.status.value, "to": new_status.value, "trigger": trigger},
                links=[(LinkRelation.CAUSED_BY, cause_uid)] if cause_uid else [])

    # --- findings & claims -----------------------------------------------------
    def add_finding(self, incident_id: str, *, author_actor_id: str | None, summary: str,
                    severity: str | None = None, source_uid: str | None = None,
                    source: str = "core") -> Finding:
        fid = _new_id()
        with transaction(self.conn):
            ev = self.audit.append(
                EventType.FINDING_RECORDED, incident_id=incident_id, actor_id=author_actor_id,
                source=source, payload={"finding_id": fid, "summary": summary,
                                        "severity": severity},
                links=[(LinkRelation.DERIVED_FROM, source_uid)] if source_uid else [])
            f = Finding(id=fid, incident_id=incident_id, author_actor_id=author_actor_id,
                        severity=severity, summary=summary, event_uid=ev.uid,
                        created_at=ev.ts)
            self.conn.execute(
                "INSERT INTO findings(id, incident_id, author_actor_id, severity, summary, "
                "event_uid, created_at) VALUES (?,?,?,?,?,?,?)",
                (fid, incident_id, author_actor_id, severity, summary, ev.uid, ev.ts))
        return f

    def add_claim(self, incident_id: str, *, content: str, kind: str = "text",
                  finding: Finding | None = None, actor_id: str | None = None,
                  source_uid: str | None = None, source: str = "core") -> FindingClaim:
        """Record a statement made inside a finding. A claim, NOT evidence."""
        cid = _new_id()
        links: list[LinkSpec] = []
        if finding:
            links.append((LinkRelation.SUPPORTS, finding.event_uid))
        if source_uid:
            links.append((LinkRelation.DERIVED_FROM, source_uid))
        with transaction(self.conn):
            ev = self.audit.append(
                EventType.CLAIM_RECORDED, incident_id=incident_id, actor_id=actor_id,
                source=source, payload={"claim_id": cid, "kind": kind, "content": content,
                                        "finding_id": finding.id if finding else None},
                links=links)
            self.conn.execute(
                "INSERT INTO finding_claims(id, incident_id, finding_id, kind, content, "
                "event_uid, created_at) VALUES (?,?,?,?,?,?,?)",
                (cid, incident_id, finding.id if finding else None, kind, content, ev.uid, ev.ts))
        return FindingClaim(id=cid, incident_id=incident_id,
                            finding_id=finding.id if finding else None, kind=kind,
                            content=content, event_uid=ev.uid, created_at=ev.ts)

    def findings(self, incident_id: str) -> list[Finding]:
        return [Finding(**dict(r)) for r in self._all(
            "SELECT * FROM findings WHERE incident_id = ? ORDER BY created_at", (incident_id,))]

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self._one("SELECT * FROM findings WHERE id = ?", (finding_id,))
        return Finding(**dict(row)) if row else None

    def claims_for(self, finding_id: str) -> list[FindingClaim]:
        return [FindingClaim(**dict(r)) for r in self._all(
            "SELECT * FROM finding_claims WHERE finding_id = ? ORDER BY created_at",
            (finding_id,))]

    # --- sign-offs ------------------------------------------------------------
    def add_signoff_request(self, incident_id: str, *, actor_id: str, actions: list[str],
                            source_uid: str | None = None,
                            source: str = "core") -> SignOffRequest:
        ev = self.audit.append(
            EventType.SIGNOFF_REQUESTED, incident_id=incident_id, actor_id=actor_id,
            source=source, payload={"actions": actions},
            links=[(LinkRelation.DERIVED_FROM, source_uid)] if source_uid else [])
        return SignOffRequest(event_uid=ev.uid, incident_id=incident_id, actor_id=actor_id,
                              actions=actions, created_at=ev.ts)

    def latest_signoff_request(self, incident_id: str) -> SignOffRequest | None:
        row = self._one(
            "SELECT uid, actor_id, payload, ts FROM audit_events WHERE incident_id = ? "
            "AND event_type = ? ORDER BY seq DESC LIMIT 1",
            (incident_id, EventType.SIGNOFF_REQUESTED.value))
        if not row:
            return None
        return SignOffRequest(event_uid=row["uid"], incident_id=incident_id,
                              actor_id=row["actor_id"],
                              actions=json.loads(row["payload"]).get("actions", []),
                              created_at=row["ts"])

    def add_signoff(self, incident_id: str, *, actor: Actor, request: SignOffRequest | None,
                    source_uid: str | None = None, source: str = "core") -> SignOff:
        sid = _new_id()
        covered = list(request.actions) if request else []
        links: list[LinkSpec] = []
        if request:
            links.append((LinkRelation.RESPONDS_TO, request.event_uid))
        if source_uid:
            links.append((LinkRelation.DERIVED_FROM, source_uid))
        with transaction(self.conn):
            ev = self.audit.append(
                EventType.SIGNOFF_RECORDED, incident_id=incident_id, actor_id=actor.id,
                source=source, payload={"signoff_id": sid, "role": actor.role,
                                        "covered_actions": covered}, links=links)
            self.conn.execute(
                "INSERT INTO signoffs(id, incident_id, actor_id, request_event_uid, "
                "covered_actions, event_uid, created_at) VALUES (?,?,?,?,?,?,?)",
                (sid, incident_id, actor.id, request.event_uid if request else None,
                 _j(covered), ev.uid, ev.ts))
        return SignOff(id=sid, incident_id=incident_id, actor_id=actor.id, actor_role=actor.role,
                       request_event_uid=request.event_uid if request else None,
                       covered_actions=covered, event_uid=ev.uid, created_at=ev.ts)

    def signoffs_for(self, request_event_uid: str) -> list[SignOff]:
        rows = self._all(
            "SELECT s.*, a.role AS actor_role FROM signoffs s JOIN actors a "
            "ON a.id = s.actor_id WHERE s.request_event_uid = ? ORDER BY s.created_at",
            (request_event_uid,))
        return [SignOff(**{**dict(r), "covered_actions": json.loads(r["covered_actions"])})
                for r in rows]

    # --- vetoes & holds -------------------------------------------------------
    def add_veto(self, incident_id: str, *, actor_id: str, action: str | None,
                 asset_id: str | None, regulation: str | None, reason: str,
                 request_uid: str | None = None, source_uid: str | None = None,
                 source: str = "core") -> Veto:
        vid = _new_id()
        links: list[LinkSpec] = []
        if request_uid:
            links.append((LinkRelation.RESPONDS_TO, request_uid))
        if source_uid:
            links.append((LinkRelation.DERIVED_FROM, source_uid))
        with transaction(self.conn):
            ev = self.audit.append(
                EventType.VETO_RECORDED, incident_id=incident_id, actor_id=actor_id,
                source=source, payload={"veto_id": vid, "action": action, "asset_id": asset_id,
                                        "regulation": regulation, "reason": reason},
                links=links)
            self.conn.execute(
                "INSERT INTO vetoes(id, incident_id, actor_id, action, asset_id, regulation, "
                "reason, status, event_uid, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (vid, incident_id, actor_id, action, asset_id, regulation, reason,
                 VetoStatus.ACTIVE.value, ev.uid, ev.ts))
        return Veto(id=vid, incident_id=incident_id, actor_id=actor_id, action=action,
                    asset_id=asset_id, regulation=regulation, reason=reason,
                    event_uid=ev.uid, created_at=ev.ts)

    def active_vetoes(self, incident_id: str) -> list[Veto]:
        return [Veto(**dict(r)) for r in self._all(
            "SELECT * FROM vetoes WHERE incident_id = ? AND status = 'active' "
            "ORDER BY created_at", (incident_id,))]

    @staticmethod
    def _hold(row: sqlite3.Row) -> LegalHold:
        return LegalHold(**{**dict(row), "rule_ids": json.loads(row["rule_ids"]),
                            "requires_human_authorization":
                                bool(row["requires_human_authorization"])})

    def add_hold(self, asset_id: str, *, incident_id: str | None, rule_ids: list[str],
                 requires_human_authorization: bool, actor_id: str | None = None,
                 source: str = "core") -> LegalHold:
        existing = self._one(
            "SELECT * FROM legal_holds WHERE asset_id = ? AND incident_id IS ? "
            "AND status = 'active'", (asset_id, incident_id))
        if existing:
            return self._hold(existing)
        hid = _new_id()
        with transaction(self.conn):
            ev = self.audit.append(
                EventType.LEGAL_HOLD_PLACED, incident_id=incident_id, actor_id=actor_id,
                source=source, payload={"hold_id": hid, "asset_id": asset_id,
                                        "rule_ids": rule_ids,
                                        "requires_human_authorization":
                                            requires_human_authorization})
            self.conn.execute(
                "INSERT INTO legal_holds(id, asset_id, incident_id, rule_ids, "
                "requires_human_authorization, status, event_uid, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (hid, asset_id, incident_id, _j(rule_ids), int(requires_human_authorization),
                 HoldStatus.ACTIVE.value, ev.uid, ev.ts))
        return LegalHold(id=hid, asset_id=asset_id, incident_id=incident_id, rule_ids=rule_ids,
                         requires_human_authorization=requires_human_authorization,
                         event_uid=ev.uid, created_at=ev.ts)

    def active_holds(self, asset_id: str | None = None) -> list[LegalHold]:
        """Active holds — holds are per ASSET, so they bind every incident."""
        if asset_id is None:
            rows = self._all("SELECT * FROM legal_holds WHERE status = 'active'")
        else:
            rows = self._all("SELECT * FROM legal_holds WHERE asset_id = ? "
                             "AND status = 'active'", (asset_id,))
        return [self._hold(r) for r in rows]

    # --- action requests & decisions -------------------------------------------
    @staticmethod
    def _request(row: sqlite3.Row) -> ActionRequest:
        return ActionRequest(**{**dict(row), "params": json.loads(row["params"]),
                                "status": ActionStatus(row["status"])})

    def add_action_request(self, incident_id: str, *, action: str, asset_id: str | None,
                           tier: int, requested_by: str | None,
                           params: dict[str, Any] | None = None,
                           links: Iterable[LinkSpec] = (), source: str = "core") -> ActionRequest:
        rid = _new_id()
        params = params or {}
        with transaction(self.conn):
            ev = self.audit.append(
                EventType.ACTION_PROPOSED, incident_id=incident_id, actor_id=requested_by,
                source=source, payload={"request_id": rid, "action": action,
                                        "asset_id": asset_id, "tier": tier, "params": params},
                links=links)
            self.conn.execute(
                "INSERT INTO action_requests(id, incident_id, action, asset_id, params, tier, "
                "requested_by, status, event_uid, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (rid, incident_id, action, asset_id, _j(params), tier, requested_by,
                 ActionStatus.PROPOSED.value, ev.uid, ev.ts, ev.ts))
        return ActionRequest(id=rid, incident_id=incident_id, action=action, asset_id=asset_id,
                             params=params, tier=tier, requested_by=requested_by,
                             event_uid=ev.uid, created_at=ev.ts, updated_at=ev.ts)

    def get_action_request(self, request_id: str) -> ActionRequest | None:
        row = self._one("SELECT * FROM action_requests WHERE id = ?", (request_id,))
        return self._request(row) if row else None

    def action_requests(self, incident_id: str) -> list[ActionRequest]:
        return [self._request(r) for r in self._all(
            "SELECT * FROM action_requests WHERE incident_id = ? ORDER BY created_at",
            (incident_id,))]

    def _set_request_status(self, request_id: str, status: ActionStatus) -> None:
        # Only called inside a transaction that also appends the explaining event.
        assert self.conn.in_transaction, "request status must change with an audit event"
        self.conn.execute("UPDATE action_requests SET status = ?, updated_at = ? WHERE id = ?",
                          (status.value, self._ts(), request_id))

    def add_policy_decision(self, request: ActionRequest, decision: PolicyDecision, *,
                            actor_id: str | None) -> PolicyDecision:
        did = _new_id()
        links: list[LinkSpec] = [(LinkRelation.EVALUATES, request.event_uid)]
        links += [(LinkRelation.RELIED_ON, u) for u in decision.relied_on_event_uids]
        links += [(LinkRelation.BLOCKED_BY, u) for u in decision.blocked_by_event_uids]
        new_status = {
            PolicyOutcome.ALLOW: None,  # AUTHORIZED is set by authorize()
            PolicyOutcome.REQUIRE_APPROVAL: ActionStatus.REQUIRES_APPROVAL,
            PolicyOutcome.DENY: ActionStatus.DENIED,
        }[PolicyOutcome(decision.outcome)]
        with transaction(self.conn):
            ev = self.audit.append(
                EventType.POLICY_DECISION, incident_id=request.incident_id, actor_id=actor_id,
                payload={"decision_id": did, "request_id": request.id,
                         "action": decision.action, "asset_id": decision.asset_id,
                         "tier": decision.tier, "outcome": PolicyOutcome(decision.outcome).value,
                         "rule_results": [r.model_dump() for r in decision.rule_results],
                         "approval_id": decision.approval_id,
                         "policy_version": decision.policy_version,
                         "snapshot_hash": decision.snapshot_hash},
                links=dict.fromkeys(links))  # de-dup, keep order
            self.conn.execute(
                "INSERT INTO policy_decisions(id, action_request_id, incident_id, outcome, "
                "rule_results, approval_id, policy_version, snapshot_hash, event_uid, "
                "created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (did, request.id, request.incident_id, PolicyOutcome(decision.outcome).value,
                 _j([r.model_dump() for r in decision.rule_results]), decision.approval_id,
                 decision.policy_version, decision.snapshot_hash, ev.uid, ev.ts))
            if new_status:
                self._set_request_status(request.id, new_status)
        return decision.model_copy(update={"id": did, "action_request_id": request.id,
                                           "event_uid": ev.uid, "created_at": ev.ts})

    def authorize(self, request: ActionRequest, decision: PolicyDecision, *,
                  approval: Approval | None, actor_id: str | None) -> AuditEvent:
        """Record ACTION_AUTHORIZED; consume the approval it used (single use)."""
        links: list[LinkSpec] = [(LinkRelation.AUTHORIZES, decision.event_uid)]
        if approval:
            links.append((LinkRelation.CONSUMES, approval.event_uid))
        with transaction(self.conn):
            ev = self.audit.append(
                EventType.ACTION_AUTHORIZED, incident_id=request.incident_id, actor_id=actor_id,
                payload={"request_id": request.id, "action": request.action,
                         "asset_id": request.asset_id,
                         "approval_id": approval.id if approval else None},
                links=links)
            if approval:
                cur = self.conn.execute(
                    "UPDATE approvals SET consumed_by_request_id = ?, consumed_at = ? "
                    "WHERE id = ? AND consumed_by_request_id IS NULL",
                    (request.id, ev.ts, approval.id))
                if cur.rowcount != 1:
                    raise RuntimeError(f"approval {approval.id} was already consumed")
            self._set_request_status(request.id, ActionStatus.AUTHORIZED)
        return ev

    def decisions_for(self, request_id: str) -> list[sqlite3.Row]:
        return self._all("SELECT * FROM policy_decisions WHERE action_request_id = ? "
                         "ORDER BY created_at", (request_id,))

    # --- approvals ------------------------------------------------------------
    @staticmethod
    def _approval(row: sqlite3.Row) -> Approval:
        d = dict(row)
        return Approval(**{**d, "approver_kind": ActorKind(d["approver_kind"]),
                           "decision": ApprovalDecision(d["decision"]),
                           "overrides_hold": bool(d["overrides_hold"]),
                           "overrides_veto": bool(d["overrides_veto"])})

    _APPROVAL_SELECT = ("SELECT p.*, a.kind AS approver_kind, a.role AS approver_role "
                        "FROM approvals p JOIN actors a ON a.id = p.approver_actor_id ")

    def add_approval(self, incident_id: str, *, action: str, asset_id: str | None,
                     approver: Actor, decision: ApprovalDecision, reason: str,
                     expires_at: str, overrides_hold: bool = False,
                     overrides_veto: bool = False, concerns_uid: str | None = None,
                     source: str = "core") -> Approval:
        """Low-level insert. Callers must go through ``CoreService.grant_approval``,
        which enforces who may approve."""
        aid = _new_id()
        etype = (EventType.APPROVAL_GRANTED if decision == ApprovalDecision.APPROVE
                 else EventType.APPROVAL_DENIED)
        with transaction(self.conn):
            ev = self.audit.append(
                etype, incident_id=incident_id, actor_id=approver.id, source=source,
                payload={"approval_id": aid, "action": action, "asset_id": asset_id,
                         "decision": decision.value, "approver_role": approver.role,
                         "overrides_hold": overrides_hold, "overrides_veto": overrides_veto,
                         "reason": reason, "expires_at": expires_at},
                links=[(LinkRelation.CONCERNS, concerns_uid)] if concerns_uid else [])
            self.conn.execute(
                "INSERT INTO approvals(id, incident_id, action, asset_id, approver_actor_id, "
                "decision, overrides_hold, overrides_veto, reason, expires_at, event_uid, "
                "created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (aid, incident_id, action, asset_id, approver.id, decision.value,
                 int(overrides_hold), int(overrides_veto), reason, expires_at, ev.uid, ev.ts))
        return self.get_approval(aid)  # type: ignore[return-value]

    def get_approval(self, approval_id: str) -> Approval | None:
        row = self._one(self._APPROVAL_SELECT + "WHERE p.id = ?", (approval_id,))
        return self._approval(row) if row else None

    def unconsumed_approvals(self, incident_id: str) -> list[Approval]:
        return [self._approval(r) for r in self._all(
            self._APPROVAL_SELECT + "WHERE p.incident_id = ? AND "
            "p.consumed_by_request_id IS NULL ORDER BY p.created_at", (incident_id,))]

    # --- risk -----------------------------------------------------------------
    def add_risk(self, incident_id: str, *, level: str, score: float | None,
                 factors: dict[str, Any], method: str, actor_id: str | None) -> RiskSnapshot:
        rid = _new_id()
        with transaction(self.conn):
            ev = self.audit.append(
                EventType.RISK_RECORDED, incident_id=incident_id, actor_id=actor_id,
                payload={"risk_id": rid, "level": level, "score": score,
                         "factors": factors, "method": method})
            self.conn.execute(
                "INSERT INTO risk_snapshots(id, incident_id, level, score, factors, method, "
                "event_uid, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (rid, incident_id, level, score, _j(factors), method, ev.uid, ev.ts))
        return RiskSnapshot(id=rid, incident_id=incident_id, level=level, score=score,
                            factors=factors, method=method, event_uid=ev.uid, created_at=ev.ts)

    # --- simulated execution records (Phase 6, schema v3) ---------------------------
    @staticmethod
    def _execution(row: sqlite3.Row) -> ExecutionRecord:
        return ExecutionRecord(**{**dict(row), "criteria": json.loads(row["criteria"]),
                                  "event_uid": row["executed_event_uid"]})

    def execution_record_for(self, request_id: str) -> ExecutionRecord | None:
        row = self._one("SELECT * FROM execution_records WHERE action_request_id = ?",
                        (request_id,))
        return self._execution(row) if row else None

    def execution_records(self, incident_id: str) -> list[ExecutionRecord]:
        return [self._execution(r) for r in self._all(
            "SELECT * FROM execution_records WHERE incident_id = ? ORDER BY created_at, id",
            (incident_id,))]

    def evidence_fingerprint(self, incident_id: str) -> str:
        """Content fingerprint of an incident's evidence - the same value as the
        detection layer's ``EvidenceView.fingerprint`` (sorted (id, content hash))."""
        rows = self._all("SELECT id, content_sha256 FROM evidence WHERE incident_id = ?",
                         (incident_id,))
        body = sorted([r["id"], r["content_sha256"]] for r in rows)
        return hashlib.sha256(canonical_json(body).encode()).hexdigest()

    def chain_head(self, incident_id: str) -> str | None:
        row = self._one("SELECT hash FROM audit_events WHERE chain = ? ORDER BY seq DESC "
                        "LIMIT 1", (incident_id,))
        return row["hash"] if row else None

    def add_execution_record(self, request: ActionRequest, *, recorder_id: str,
                             authorized_event_uid: str, plan_id: str, plan_sha256: str,
                             step_id: str, step_sha256: str, report_sha256: str,
                             evidence_fingerprint: str, environment_sha256: str,
                             outcome: str, criteria: list[dict[str, Any]],
                             source: str = "core") -> ExecutionRecord:
        """ACTION_EXECUTED (executes -> ACTION_AUTHORIZED), ACTION_VERIFIED
        (verifies -> ACTION_EXECUTED) and the execution_records row, in ONE
        transaction. The request's status is deliberately left unchanged."""
        rid = _new_id()
        with transaction(self.conn):
            head = self.chain_head(request.incident_id) or ""
            executed = self.audit.append(
                EventType.ACTION_EXECUTED, incident_id=request.incident_id,
                actor_id=recorder_id, source=source,
                payload={"mode": "simulated", "execution_id": rid, "request_id": request.id,
                         "action": request.action, "asset_id": request.asset_id,
                         "plan_id": plan_id, "plan_sha256": plan_sha256, "step_id": step_id,
                         "step_sha256": step_sha256, "report_sha256": report_sha256,
                         "evidence_fingerprint": evidence_fingerprint,
                         "environment_sha256": environment_sha256, "audit_head_hash": head},
                links=[(LinkRelation.EXECUTES, authorized_event_uid)])
            verified = self.audit.append(
                EventType.ACTION_VERIFIED, incident_id=request.incident_id,
                actor_id=recorder_id, source=source,
                payload={"mode": "simulated", "execution_id": rid, "request_id": request.id,
                         "outcome": outcome, "criteria": criteria},
                links=[(LinkRelation.VERIFIES, executed.uid)])
            self.conn.execute(
                "INSERT INTO execution_records(id, incident_id, action_request_id, mode, "
                "action, asset_id, plan_id, plan_sha256, step_id, step_sha256, report_sha256, "
                "evidence_fingerprint, environment_sha256, outcome, criteria, audit_head_hash, "
                "recorded_by, authorized_event_uid, executed_event_uid, verified_event_uid, "
                "created_at) VALUES (?,?,?,'simulated',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rid, request.incident_id, request.id, request.action, request.asset_id,
                 plan_id, plan_sha256, step_id, step_sha256, report_sha256,
                 evidence_fingerprint, environment_sha256, outcome, _j(criteria), head,
                 recorder_id, authorized_event_uid, executed.uid, verified.uid, executed.ts))
        return self.execution_record_for(request.id)

    # --- snapshot for the policy engine -----------------------------------------
    def snapshot(self, incident_id: str, now: datetime | None = None) -> IncidentSnapshot:
        """Everything the policy engine may consider, from persisted records only."""
        req = self.latest_signoff_request(incident_id)
        return IncidentSnapshot(
            incident=self.get_incident(incident_id),
            assets={a.asset_id: a for a in self.list_assets()},
            signoff_request=req,
            signoffs=self.signoffs_for(req.event_uid) if req else [],
            vetoes=self.active_vetoes(incident_id),
            holds=self.active_holds(),
            approvals=self.unconsumed_approvals(incident_id),
            now=now or self.clock(),
        )
