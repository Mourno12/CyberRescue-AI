"""Shared helpers for the Phase 5 execution tests.

Authorizations are created ONLY through the Core's normal path: a registered
Commander calls ``request_action`` (policy decides), and a registered human
approver calls ``grant_approval``. The executor never does either.
"""

from __future__ import annotations

from pathlib import Path

from cyberrescue.core.service import CoreService
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.planner import build_plan

COMMANDER = "band:synthetic-agent-commander"


def plans_of(db: Path, refs=("INC-A", "INC-B", "INC-C")):
    with open_readonly(db) as ro:
        return {r: build_plan(ro, r) for r in refs}


def request(db: Path, plan, items=None, *, plan_step: bool = True):
    """The Commander requests plan items through the Core; returns the outcomes."""
    svc = CoreService.open(db)
    try:
        cmd = svc.store.find_actor(COMMANDER)
        out = []
        for s in items if items is not None else plan.steps:
            ident = getattr(s, "step_id", None) or s.decision_id
            asset = s.target.value if s.target.kind == "host" else None
            out.append(svc.request_action(plan.incident_id, s.action, asset, cmd.id,
                                          params={"plan_step": ident} if plan_step else {},
                                          source="test"))
        return out
    finally:
        svc.conn.close()


def approve(db: Path, incident_id: str, action: str, asset: str | None, **kw):
    svc = CoreService.open(db)
    try:
        ciso = svc.store.find_actor("test:ciso") or svc.register_actor(
            "human", "ciso", "ciso", "test:ciso")
        return svc.grant_approval(incident_id, action=action, asset_id=asset,
                                  approver_actor_id=ciso.id, reason=kw.pop("reason", "ok"), **kw)
    finally:
        svc.conn.close()
