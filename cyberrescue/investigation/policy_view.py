"""Read-only view of an incident's policy and approval state.

Shown so a human approver sees the authority state next to the evidence. The
investigation layer never evaluates, requests, approves or consumes anything.
"""

from __future__ import annotations

import json

from cyberrescue.investigation.model import PolicyView, untrusted
from cyberrescue.investigation.readonly import ReadOnlyCore

_APPROVALS = ("SELECT p.id, p.action, p.asset_id, p.decision, p.overrides_hold, "
              "p.overrides_veto, p.reason, p.expires_at, p.consumed_by_request_id, "
              "p.consumed_at, a.kind AS approver_kind, a.role AS approver_role "
              "FROM approvals p JOIN actors a ON a.id = p.approver_actor_id "
              "WHERE p.incident_id = ? ORDER BY p.created_at, p.id")


def build_policy_view(core: ReadOnlyCore, incident_id: str) -> PolicyView:
    store = core.store
    inc = store.get_incident(incident_id)
    holds = [h for h in store.active_holds()
             if h.incident_id == incident_id or h.asset_id == inc.primary_asset_id]
    req = store.latest_signoff_request(incident_id)
    signoff = None
    if req is not None:
        signed = sorted({s.actor_role for s in store.signoffs_for(req.event_uid)})
        signoff = {"actions": list(req.actions), "requested_at": req.created_at,
                   "signed_by": signed,
                   "pending": sorted(set(inc.recruited_roles) - {"commander"} - set(signed))}
    requests = []
    for r in store.action_requests(incident_id):
        decisions = store.decisions_for(r.id)
        last = decisions[-1] if decisions else None
        failed = [x["rule"] for x in json.loads(last["rule_results"])
                  if not x.get("satisfied")] if last else []
        requests.append({"id": r.id, "action": r.action, "asset_id": r.asset_id,
                         "status": r.status.value,
                         "latest_outcome": last["outcome"] if last else None,
                         "unmet_rules": failed,
                         "policy_version": last["policy_version"] if last else None})
    approvals = [{"id": a["id"], "action": a["action"], "asset_id": a["asset_id"],
                  "decision": a["decision"], "approver_kind": a["approver_kind"],
                  "approver_role": a["approver_role"],
                  "overrides_hold": bool(a["overrides_hold"]),
                  "overrides_veto": bool(a["overrides_veto"]),
                  "expires_at": a["expires_at"], "consumed": a["consumed_at"] is not None,
                  "reason": untrusted(a["reason"]).model_dump()}
                 for a in core.select(_APPROVALS, (incident_id,))]
    return PolicyView(
        status=inc.status.value, severity=inc.severity, primary_asset=inc.primary_asset_id,
        recruited_roles=tuple(inc.recruited_roles),
        holds=tuple({"id": h.id, "asset_id": h.asset_id, "rule_ids": list(h.rule_ids),
                     "requires_human_authorization": h.requires_human_authorization}
                    for h in sorted(holds, key=lambda h: h.id)),
        vetoes=tuple({"id": v.id, "action": v.action, "asset_id": v.asset_id,
                      "regulation": v.regulation, "reason": untrusted(v.reason).model_dump()}
                     for v in store.active_vetoes(incident_id)),
        signoff_request=signoff, action_requests=tuple(requests),
        approvals=tuple(approvals))
