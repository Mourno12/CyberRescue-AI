"""Commander action gate (Phase 1b): the WarRoom Commander asks the Core.

WarRoom's ``agents/commander/tools.py`` calls ``check_commander_action()``
before executing any action tool. The Core evaluates the action with the
deterministic policy engine and returns a decision record.

Modes — ``CYBERRESCUE_GATE_MODE`` (default **shadow**):

* ``shadow``  — evaluate and LOG only. The Commander always proceeds exactly as
  in original WarRoom; the Core changes no incident state, creates no action
  request and consumes no approval. Only a ``GATE_DECISION`` audit event and a
  JSONL log line are written.
* ``enforce`` — the Core is the final authority. The action goes through
  ``CoreService.request_action`` (proposal -> policy decision -> authorization,
  approvals consumed single-use); the Commander proceeds ONLY on ALLOW.
  Enforce fails closed: no bound incident, a Core error, or an unavailable
  Core all block the action.

An unrecognised mode value falls back to shadow with a warning — a typo can
never silently switch enforcement on (nor crash the Commander).

Context resolution (all from the operator/environment — never from LLM text):
  incident  ``CYBERRESCUE_INCIDENT`` (id or alias; a WarRoom demo alias
            INC-A/B/C is opened automatically), else the single most recent
            open Core incident whose primary asset is the action's target.
  requester the Core actor with ref ``CYBERRESCUE_COMMANDER_REF`` (default
            ``warroom:commander``; set it to ``band:<commander-id>`` to match
            an imported Band history), registered as the Commander if absent.

Every decision is appended to ``CYBERRESCUE_GATE_LOG`` (default
``<repo>/cyberrescue_gate_log.jsonl``) and, in the Core, as ``GATE_DECISION``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from cyberrescue.core.audit import utcnow
from cyberrescue.core.db import REPO_ROOT
from cyberrescue.core.ids import legacy_alias_for, parse_incident_ref
from cyberrescue.core.models import (
    EventType,
    IncidentSnapshot,
    LinkRelation,
    PolicyOutcome,
)
from cyberrescue.core.policy import PolicyConfig, applicable_rules
from cyberrescue.core.service import CoreService

GATE_MODE_ENV = "CYBERRESCUE_GATE_MODE"
GATE_LOG_ENV = "CYBERRESCUE_GATE_LOG"
INCIDENT_ENV = "CYBERRESCUE_INCIDENT"
COMMANDER_REF_ENV = "CYBERRESCUE_COMMANDER_REF"
DEFAULT_COMMANDER_REF = "warroom:commander"
SOURCE = "commander_gate"


class GateMode(str, Enum):
    SHADOW = "shadow"
    ENFORCE = "enforce"


DEFAULT_MODE = GateMode.SHADOW


def resolve_mode(raw: str | None = None) -> tuple[GateMode, str | None]:
    """(mode, warning). ``raw`` defaults to ``$CYBERRESCUE_GATE_MODE``."""
    value = os.getenv(GATE_MODE_ENV) if raw is None else raw
    if value is None or not value.strip():
        return DEFAULT_MODE, None
    try:
        return GateMode(value.strip().lower()), None
    except ValueError:
        return DEFAULT_MODE, (f"invalid {GATE_MODE_ENV}={value!r}; using shadow "
                              "(enforcement is never enabled by an unrecognised value)")


def default_log_path() -> Path:
    env = os.getenv(GATE_LOG_ENV)
    return Path(env) if env else REPO_ROOT / "cyberrescue_gate_log.jsonl"


class CommanderGate:
    def __init__(self, *, mode: GateMode | str | None = None,
                 db_path: str | Path | None = None, log_path: str | Path | None = None,
                 clock: Callable[[], datetime] = utcnow,
                 config: PolicyConfig | None = None) -> None:
        raw = mode.value if isinstance(mode, GateMode) else mode
        self.mode, self.warning = resolve_mode(raw)
        self.db_path = db_path
        self.log_path = Path(log_path) if log_path else default_log_path()
        self.clock = clock
        self.config = config

    # --- public -------------------------------------------------------------
    def check(self, action: str, details: dict[str, Any]) -> dict[str, Any]:
        """Evaluate one Commander action. Never raises; returns the record.

        ``record["proceed"]`` tells the caller whether to execute: always True
        in shadow mode; True only on ALLOW in enforce mode.
        """
        now = self.clock()
        record: dict[str, Any] = {
            "ts": now.isoformat(),
            "mode": self.mode.value,
            "enforced": self.mode == GateMode.ENFORCE,
            "incident": None,
            "action": action,
            "target_asset": details.get("asset_id"),
            "commander_reason": details.get("reason"),
            "outcome": None,
            "verdict": "DENY",
            "would_allow": False,
            "proceed": None,
            "blocked": None,
            "rules_evaluated": applicable_rules(action),
            "rule_results": [],
            "unmet_rules": [],
            "reason": "",
            "signoff_request": None,
            "signoffs_considered": [],
            "approvals_considered": [],
            "relied_on_event_uids": [],
            "blocked_by_event_uids": [],
            "policy_version": None,
            "snapshot_hash": None,
            "request_id": None,
            "core_event_uid": None,
            "warnings": [self.warning] if self.warning else [],
            "error": None,
        }
        try:
            self._evaluate(action, details, now, record)
        except Exception as e:  # noqa: BLE001 — the gate must never crash the Commander
            record.update(error=f"{type(e).__name__}: {e}", would_allow=False, verdict="DENY",
                          reason=f"Core evaluation failed ({type(e).__name__}: {e})")
        self._finalise(record)
        self._log(record)
        return record

    # --- internals ----------------------------------------------------------
    def _finalise(self, record: dict[str, Any]) -> None:
        if self.mode == GateMode.SHADOW:
            record["proceed"] = True
        else:  # enforce: fail closed
            record["proceed"] = bool(record["would_allow"]) and record["error"] is None
        record["blocked"] = not record["proceed"]

    def _resolve_incident(self, svc: CoreService, asset_id: str | None,
                          warnings: list[str]) -> str | None:
        ref = os.getenv(INCIDENT_ENV)
        if ref:
            iid = svc.store.resolve_incident(ref)
            if iid is None and legacy_alias_for(parse_incident_ref(ref) or ""):
                from cyberrescue.core.band_import import open_legacy_incident
                iid = open_legacy_incident(svc, ref).id
                warnings.append(f"opened WarRoom demo incident {iid} in the Core "
                                f"(from {INCIDENT_ENV}={ref})")
            if iid is None:
                warnings.append(f"{INCIDENT_ENV}={ref!r} is not a Core incident")
            return iid
        if asset_id:
            candidates = svc.store.open_incidents_for_asset(asset_id)
            if len(candidates) > 1:
                warnings.append(f"{len(candidates)} open incidents on {asset_id}; using the "
                                f"most recent ({candidates[0]}) — set {INCIDENT_ENV} to choose")
            if candidates:
                return candidates[0]
        warnings.append(f"no Core incident bound (set {INCIDENT_ENV}, or open an incident "
                        f"whose primary asset is {asset_id or 'the target'})")
        return None

    def _requester(self, svc: CoreService):
        ref = os.getenv(COMMANDER_REF_ENV) or DEFAULT_COMMANDER_REF
        return svc.store.find_actor(ref) or svc.register_actor(
            "agent", "commander", "WarRoom Commander (gate)", ref)

    def _evaluate(self, action: str, details: dict[str, Any], now: datetime,
                  record: dict[str, Any]) -> None:
        asset_id = details.get("asset_id")
        svc = CoreService.open(self.db_path, config=self.config, clock=lambda: now)
        try:
            if not svc.store.list_assets():
                svc.seed_assets_from_mock()
            iid = self._resolve_incident(svc, asset_id, record["warnings"])
            record["incident"] = iid
            requester = self._requester(svc)
            snap = (svc.store.snapshot(iid, now) if iid else IncidentSnapshot(
                incident=None, assets={a.asset_id: a for a in svc.store.list_assets()},
                now=now))
            self._describe_inputs(svc, snap, action, asset_id, record)

            links: list[tuple[LinkRelation, str]] = []
            if self.mode == GateMode.ENFORCE and iid is not None:
                out = svc.request_action(iid, action, asset_id, requester,
                                         params={"reason": details.get("reason"),
                                                 "via": SOURCE}, source=SOURCE)
                decision = out.decision
                record["request_id"] = out.request.id
                links.append((LinkRelation.CONCERNS, decision.event_uid))
            else:
                # Shadow (or enforce with no incident -> P2 DENY): pure evaluation,
                # no Core state change.
                decision = svc.engine.evaluate(action=action, asset_id=asset_id,
                                               requester=requester, snapshot=snap)
                links += [(LinkRelation.RELIED_ON, u) for u in decision.relied_on_event_uids]
                links += [(LinkRelation.BLOCKED_BY, u) for u in decision.blocked_by_event_uids]

            allow = PolicyOutcome(decision.outcome) == PolicyOutcome.ALLOW
            record.update(
                outcome=PolicyOutcome(decision.outcome).value,
                would_allow=allow,
                verdict="ALLOW" if allow else "DENY",
                rule_results=[r.model_dump() for r in decision.rule_results],
                unmet_rules=decision.rules_failed,
                reason="; ".join(decision.reasons) or "all applicable policy rules satisfied",
                relied_on_event_uids=decision.relied_on_event_uids,
                blocked_by_event_uids=decision.blocked_by_event_uids,
                policy_version=decision.policy_version,
                snapshot_hash=decision.snapshot_hash,
            )
            self._finalise(record)
            ev = svc.audit.append(
                EventType.GATE_DECISION, incident_id=iid, actor_id=requester.id,
                source=SOURCE, payload={k: v for k, v in record.items()
                                        if k != "core_event_uid"},
                links=dict.fromkeys(links))
            record["core_event_uid"] = ev.uid
        finally:
            svc.conn.close()

    def _describe_inputs(self, svc: CoreService, snap: IncidentSnapshot, action: str,
                         asset_id: str | None, record: dict[str, Any]) -> None:
        """Which sign-offs and approvals the decision could draw on."""
        if snap.signoff_request:
            record["signoff_request"] = {"event_uid": snap.signoff_request.event_uid,
                                         "actions": snap.signoff_request.actions}
        record["signoffs_considered"] = [
            {"role": s.actor_role, "event_uid": s.event_uid,
             "covers_action": action in s.covered_actions} for s in snap.signoffs]
        inc_id = snap.incident.id if snap.incident else None
        record["approvals_considered"] = [
            {"approval_id": a.id, "action": a.action, "asset_id": a.asset_id,
             "decision": a.decision.value, "approver_role": a.approver_role,
             "overrides_hold": a.overrides_hold, "overrides_veto": a.overrides_veto,
             "expires_at": a.expires_at,
             "valid_for_this_action": svc.engine.approval_is_valid(
                 a, incident_id=inc_id, action=action, asset_id=asset_id, now=snap.now)}
            for a in snap.approvals]

    def _log(self, record: dict[str, Any]) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except OSError as e:
            record["warnings"].append(f"could not write gate log: {e}")


def check_commander_action(action: str, details: dict[str, Any]) -> dict[str, Any]:
    """Entry point for ``agents/commander/tools.py``. Never raises."""
    try:
        return CommanderGate().check(action, details)
    except Exception as e:  # noqa: BLE001 — last line of defence
        mode, _ = resolve_mode()
        proceed = mode == GateMode.SHADOW
        return {"mode": mode.value, "action": action, "target_asset": details.get("asset_id"),
                "outcome": None, "verdict": "DENY", "would_allow": False,
                "proceed": proceed, "blocked": not proceed,
                "reason": f"gate failed ({type(e).__name__}: {e})",
                "error": f"{type(e).__name__}: {e}"}
