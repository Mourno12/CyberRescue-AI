"""Find the Core's authorization for a plan item - read it, never create it.

The plan is NOT authority. An item may be simulated only if the CyberRescue
Core itself authorized that action, through the normal path
(``request_action`` / the Commander gate in enforce mode / ``core request``):

* an ``action_requests`` row with status ``authorized``;
* its latest ``policy_decisions`` row with outcome ALLOW;
* an ``ACTION_AUTHORIZED`` audit event for that request, linked (``authorizes``)
  to that decision's event;
* requested by a Core actor allowed to request actions (Commander agent, or a
  human operator/approver - policy rule P1).

Binding a Core authorization to a plan item:

* ``plan_step`` - the request's audited params name the item
  (``{"plan_step": "STEP-..."}``) and action and asset id agree. Works for
  every action.
* ``asset``     - for actions whose (action, asset id) fully identifies what is
  done (``isolate_host``, ``preserve_disk_image``, ``notify_stakeholders``),
  an authorized request with the same action and asset id - how the WarRoom
  Commander gate authorizes. ``kill_process``, ``quarantine_file``,
  ``block_ip`` and ``disable_account`` need ``plan_step``: the Core's
  authorization scope (incident, action, asset id) cannot say which process,
  file, address or account is meant.

Each authorization is used by at most one item per run.

Phase 6: an authorization that already has a Core execution record
(``execution_records``, schema v3) is spent - ``select_authorization`` reports
the item ``already_executed`` - and one older than the approval lifetime at
the plan's ``as_of`` is ``expired``. The Core enforces both again, with its own
clock, when a run is recorded.

``recheck`` then asks the policy engine (via the Phase 4 previewer, pure) about
the state NOW: a hard DENY blocks the item, and so does a veto that the
authorizing decision did not consider.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta

from cyberrescue.core.catalog import ASSET_BOUND_ACTIONS
from cyberrescue.core.models import ActionStatus, ActorKind, EventType
from cyberrescue.core.policy import PolicyConfig
from cyberrescue.execution.model import AuthorizationView
from cyberrescue.investigation.readonly import ReadOnlyCore
from cyberrescue.response.model import PolicyPreview, Target
from cyberrescue.response.preview import Previewer

ASSET_BOUND = ASSET_BOUND_ACTIONS


@dataclass(frozen=True)
class CoreAuthorization:
    request_id: str
    action: str
    asset_id: str | None
    plan_step: str | None
    decision_id: str
    decision_event_uid: str
    decision_rules: tuple[str, ...]          # rules the authorizing decision evaluated
    authorized_event_uid: str
    authorized_at: str
    requested_by_role: str
    approval_id: str | None
    created_at: str
    executed_record_id: str | None = None        # Phase 6: already used by a record


def core_authorizations(core: ReadOnlyCore, incident_id: str) -> list[CoreAuthorization]:
    """Every complete, consistent authorization record of the incident, oldest first."""
    cfg = PolicyConfig()
    events = {e.payload.get("request_id"): e for e in core.audit.events(
        incident_id, event_type=EventType.ACTION_AUTHORIZED)}
    out = []
    for req in core.store.action_requests(incident_id):
        if req.status != ActionStatus.AUTHORIZED:
            continue
        rows = core.store.decisions_for(req.id)
        ev = events.get(req.id)
        if not rows or ev is None or rows[-1]["outcome"] != "ALLOW":
            continue
        decision = rows[-1]
        if ("authorizes", decision["event_uid"]) not in \
                {(lk.relation.value if hasattr(lk.relation, "value") else lk.relation,
                  lk.target_uid) for lk in ev.links}:
            continue
        actor = core.store.get_actor(req.requested_by) if req.requested_by else None
        allowed = actor is not None and (
            (actor.kind == ActorKind.AGENT and actor.role in cfg.agent_requester_roles)
            or (actor.kind == ActorKind.HUMAN and actor.role in cfg.human_requester_roles))
        if not allowed:
            continue
        step = req.params.get("plan_step")
        record = core.store.execution_record_for(req.id)
        out.append(CoreAuthorization(
            request_id=req.id, action=req.action, asset_id=req.asset_id,
            plan_step=step if isinstance(step, str) else None,
            decision_id=decision["id"], decision_event_uid=decision["event_uid"],
            decision_rules=tuple(r["rule"] for r in json.loads(decision["rule_results"])),
            authorized_event_uid=ev.uid, authorized_at=ev.ts,
            requested_by_role=f"{actor.kind.value}/{actor.role}",
            approval_id=decision["approval_id"], created_at=req.created_at,
            executed_record_id=record.id if record else None))
    return sorted(out, key=lambda a: (a.created_at, a.request_id))


def _asset(target: Target) -> str | None:
    return target.value if target.kind == "host" else None


def find_authorization(records: list[CoreAuthorization], item_id: str, action: str,
                       target: Target, used: set[str]) -> tuple[AuthorizationView | None, str]:
    """The authorization for one plan item (marking it used), or why there is none."""
    asset = _asset(target)
    candidates = [a for a in records if a.request_id not in used
                  and a.action == action and a.asset_id == asset]
    named = [a for a in candidates if a.plan_step == item_id]
    bound = "plan_step" if named else None
    if not named and action in ASSET_BOUND:
        named = [a for a in candidates if a.plan_step is None]
        bound = "asset" if named else None
    if not named:
        if candidates and action not in ASSET_BOUND:
            return None, ("the Core authorized this action but the authorization does not name "
                          "this plan item; its scope (incident, action, asset) cannot identify "
                          "the process, file, address or account - request it with "
                          "params.plan_step")
        return None, "no Core authorization exists for this action and target"
    a = named[0]
    used.add(a.request_id)
    return AuthorizationView(
        request_id=a.request_id, decision_id=a.decision_id,
        decision_event_uid=a.decision_event_uid, authorized_event_uid=a.authorized_event_uid,
        binding=bound, requested_by_role=a.requested_by_role, approval_id=a.approval_id,
        authorized_at=a.authorized_at), f"authorized by the Core (binding: {bound})"


def select_authorization(records: list[CoreAuthorization], item_id: str, action: str,
                         target: Target, used: set[str], *, as_of: str, max_age_minutes: int
                         ) -> tuple[AuthorizationView | None, str, str | None]:
    """``find_authorization`` over authorizations that are neither spent (an
    execution record exists) nor older than ``max_age_minutes`` at ``as_of``.
    Returns (view, reason, block category or None)."""
    at = datetime.fromisoformat(as_of)          # the plan's as_of - never a wall clock

    def fresh(a: CoreAuthorization) -> bool:
        return at - datetime.fromisoformat(a.authorized_at) <= timedelta(minutes=max_age_minutes)

    usable = [a for a in records if a.executed_record_id is None and fresh(a)]
    view, why = find_authorization(usable, item_id, action, target, used)
    if view is not None:
        return view, why, None
    spent = [a for a in records if a.executed_record_id is not None]
    hit, _ = find_authorization(spent, item_id, action, target, set())
    if hit is not None:
        rec = next(a.executed_record_id for a in spent if a.request_id == hit.request_id)
        return None, (f"the Core authorization was already used by simulated execution "
                      f"record {rec}"), "already_executed"
    stale = [a for a in records if a.executed_record_id is None and not fresh(a)]
    hit, _ = find_authorization(stale, item_id, action, target, set())
    if hit is not None:
        return None, (f"the Core authorization is older than {max_age_minutes} minutes "
                      "at the plan's as_of"), "expired"
    return None, why, "authorization"


def recheck(previewer: Previewer, action: str, target: Target,
            authorizing_rules: tuple[str, ...] = ()) -> tuple[str | None, str, PolicyPreview]:
    """Current policy for the item: (block category or None, reason, preview)."""
    p = previewer.preview(action, target.value, kind=target.kind)
    if p.outcome_if_requested == "DENY":
        return "policy", f"current policy denies this action ({', '.join(p.unmet_rules)})", p
    if "P7" in p.unmet_rules and "P7" not in authorizing_rules:
        return "veto", "a Compliance veto now covers this action and was not considered " \
                       "when it was authorized", p
    return None, "current policy has no new objection", p
