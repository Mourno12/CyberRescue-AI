"""The policy engine — CyberRescue's action gate.

``PolicyEngine.evaluate()`` is a **pure function** of (action, target asset,
requesting actor, ``IncidentSnapshot``). It performs no I/O and reads no clock
(``snapshot.now`` is the only time source), so the same inputs always produce
the same decision — and the decision can be re-derived later from the audit
trail. The snapshot is built only from records the Core itself validated; no
LLM text reaches this module.

Rules (policy-v2). Hard DENY — nothing can lift these:
  P0  action is not in the catalogue
  P1  requester may not request actions (only the Commander agent, or a
      human with an operator/approver role — WarRoom's single-action-authority)
  P2  incident missing or closed
  P3  host-targeted action whose asset is missing/unknown
  P9  a valid human approval record explicitly DENIES this action
Specialist sign-off — ONLY sign-offs satisfy this; a human approval cannot:
  P4  tier-2: a recruited specialist has not signed off on the latest
      SIGNOFF_REQUEST covering this action
Human approval — a valid human approval satisfies these:
  P5  tier-2 on an asset whose criticality is configured as needing a human
      (default: high, critical)
  P6  tier-3: always needs a human
  P7  an active Compliance veto covers this action/asset — the approval must
      carry ``overrides_veto``
  P8  destructive action on a host under a hold that requires human
      authorization — the approval must carry ``overrides_hold`` and a reason

Outcome: any unmet DENY rule -> DENY; otherwise any unmet sign-off or approval
rule -> REQUIRE_APPROVAL ("blocked pending authorization": the unmet rules say
whether sign-offs, a human approval, or both are still needed); else ALLOW.
Sign-off and approval requirements are independent — both must be met.

policy-v1 (Phase 1a) let a human approval stand in for a missing P4 sign-off;
policy-v2 removes that (Phase 1b decision). Decisions record their version.

A valid approval: decision=approve, approver is a HUMAN whose role is in
``approver_roles``, scope equals (incident, action, asset) exactly, not
expired at ``snapshot.now``, not yet consumed. One approval must satisfy every
approval-demanding rule at once.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime

from pydantic import BaseModel

from cyberrescue.core.audit import canonical_json
from cyberrescue.core.catalog import get_action
from cyberrescue.core.models import (
    ActionTier,
    Actor,
    ActorKind,
    Approval,
    ApprovalDecision,
    IncidentSnapshot,
    PolicyDecision,
    PolicyOutcome,
    RuleResult,
)

POLICY_VERSION = "policy-v2"
DEFAULT_APPROVAL_TTL_MINUTES = 60
TTL_ENV = "CYBERRESCUE_APPROVAL_TTL_MINUTES"

DENY = "deny"
REQUIRE = "require_approval"
REQUIRE_SIGNOFF = "require_signoff"


def applicable_rules(action: str) -> list[str]:
    """Every rule the engine checks for ``action`` (for explainability logs)."""
    spec = get_action(action)
    rules = ["P0", "P1", "P2", "P3", "P9"]
    if spec is not None:
        if spec.tier == ActionTier.CONTAINMENT:
            rules += ["P4", "P5"]
        if spec.tier == ActionTier.DESTRUCTIVE:
            rules += ["P6"]
        rules += ["P7", "P8"]
    return sorted(rules, key=lambda r: int(r[1:]))


class PolicyConfig(BaseModel):
    version: str = POLICY_VERSION
    approval_ttl_minutes: int = DEFAULT_APPROVAL_TTL_MINUTES
    containment_human_approval_criticality: tuple[str, ...] = ("high", "critical")
    approver_roles: tuple[str, ...] = ("ciso", "dpo", "general_counsel")
    human_requester_roles: tuple[str, ...] = ("ciso", "dpo", "general_counsel", "operator")
    agent_requester_roles: tuple[str, ...] = ("commander",)

    model_config = {"frozen": True}

    @classmethod
    def from_env(cls, **overrides) -> PolicyConfig:
        """Defaults, with the approval lifetime overridable via
        ``CYBERRESCUE_APPROVAL_TTL_MINUTES``."""
        raw = os.getenv(TTL_ENV)
        if raw is not None and "approval_ttl_minutes" not in overrides:
            ttl = int(raw)
            if ttl <= 0:
                raise ValueError(f"{TTL_ENV} must be a positive integer, got {raw!r}")
            overrides["approval_ttl_minutes"] = ttl
        return cls(**overrides)


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def snapshot_hash(snapshot: IncidentSnapshot, action: str, asset_id: str | None,
                  requester: Actor) -> str:
    body = {"snapshot": snapshot.model_dump(mode="json"), "action": action,
            "asset_id": asset_id, "requester": requester.model_dump(mode="json")}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


class PolicyEngine:
    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()

    # --- approval validity ----------------------------------------------------
    def approval_is_valid(self, a: Approval, *, incident_id: str | None, action: str,
                          asset_id: str | None, now: datetime) -> bool:
        return (a.incident_id == incident_id
                and a.action == action
                and a.asset_id == asset_id
                and a.consumed_by_request_id is None
                and a.approver_kind == ActorKind.HUMAN
                and a.approver_role in self.config.approver_roles
                and _parse_ts(a.expires_at) > now)

    # --- evaluation -------------------------------------------------------------
    def evaluate(self, *, action: str, asset_id: str | None, requester: Actor,
                 snapshot: IncidentSnapshot) -> PolicyDecision:
        cfg = self.config
        inc = snapshot.incident
        spec = get_action(action)
        results: list[RuleResult] = []
        relied: list[str] = []
        blockers: list[tuple[str, str]] = []  # (rule, event_uid) for unmet demands

        def deny(rule: str, reason: str) -> None:
            results.append(RuleResult(rule=rule, effect=DENY, reason=reason))

        # P0 — known action
        if spec is None:
            deny("P0", f"action {action!r} is not in the catalogue")

        # P1 — who may request actions
        kind = requester.kind
        if not ((kind == ActorKind.AGENT and requester.role in cfg.agent_requester_roles)
                or (kind == ActorKind.HUMAN and requester.role in cfg.human_requester_roles)):
            deny("P1", f"{kind.value}/{requester.role} may not request response actions")

        # P2 — incident open
        if inc is None:
            deny("P2", "incident does not exist")
        elif inc.is_terminal:
            deny("P2", f"incident is {inc.status.value}")

        # P3 — known target for host actions
        asset = snapshot.assets.get(asset_id) if asset_id else None
        if spec is not None and spec.target == "host":
            if not asset_id:
                deny("P3", f"{action} requires a target host")
            elif asset is None:
                deny("P3", f"asset {asset_id!r} is not in the inventory")

        incident_id = inc.id if inc else None
        valid = [a for a in snapshot.approvals
                 if self.approval_is_valid(a, incident_id=incident_id, action=action,
                                           asset_id=asset_id, now=snapshot.now)]
        approves = [a for a in valid if a.decision == ApprovalDecision.APPROVE]
        denials = [a for a in valid if a.decision == ApprovalDecision.DENY]

        # P9 — explicit human denial
        for d in denials:
            deny("P9", f"denied by human {d.approver_role} (approval {d.id}): {d.reason}")
            relied.append(d.event_uid)

        # Approval-demanding rules (only meaningful for a known action).
        demands: list[tuple[str, str, bool, bool]] = []  # rule, reason, needs_veto, needs_hold
        if spec is not None:
            tier = spec.tier
            if tier == ActionTier.CONTAINMENT and inc is not None:
                # P4 — specialist sign-offs on the plan covering this action.
                # Independent of human approval: only sign-offs satisfy it.
                need = inc.specialists
                req = snapshot.signoff_request
                if need:
                    if req is None or action not in req.actions:
                        results.append(RuleResult(
                            rule="P4", effect=REQUIRE_SIGNOFF,
                            reason=f"no SIGNOFF_REQUEST covering {action}; sign-off needed "
                                   f"from {sorted(need)} (a human approval cannot substitute)"))
                    else:
                        signed = {s.actor_role: s for s in snapshot.signoffs
                                  if s.actor_role in need}
                        missing = sorted(need - set(signed))
                        if missing:
                            results.append(RuleResult(
                                rule="P4", effect=REQUIRE_SIGNOFF,
                                reason=f"missing sign-off from {missing} "
                                       "(a human approval cannot substitute)"))
                        else:
                            relied += [s.event_uid for s in signed.values()]
                # P5 — containment on a high-value asset needs a human
                crit = asset.criticality if asset else None
                if crit in cfg.containment_human_approval_criticality:
                    demands.append(("P5", f"containment on a {crit}-criticality asset "
                                    "requires human approval", False, False))
            if tier == ActionTier.DESTRUCTIVE:
                demands.append(("P6", "tier-3 action always requires human approval",
                                False, False))
            # P7 — Compliance veto
            for v in snapshot.vetoes:
                covers_action = v.action == action or (
                    v.action is None and tier == ActionTier.DESTRUCTIVE)
                covers_asset = v.asset_id is None or v.asset_id == asset_id
                if covers_action and covers_asset:
                    demands.append(("P7", f"vetoed by compliance ({v.regulation or 'no rule cited'}); "
                                    "approval must override the veto", True, False))
                    blockers.append(("P7", v.event_uid))
            # P8 — legal hold
            if spec.destructive and asset_id:
                for h in snapshot.holds:
                    if h.asset_id == asset_id and h.requires_human_authorization:
                        demands.append(("P8", f"{asset_id} is under legal hold {h.rule_ids}; "
                                        "approval must override the hold with a reason",
                                        False, True))
                        blockers.append(("P8", h.event_uid))

        # One approval must satisfy every demand at once.
        chosen: Approval | None = None
        if demands:
            needs_veto = any(d[2] for d in demands)
            needs_hold = any(d[3] for d in demands)
            for a in approves:
                if needs_veto and not a.overrides_veto:
                    continue
                if needs_hold and not (a.overrides_hold and a.reason.strip()):
                    continue
                chosen = a
                break
        for rule, reason, nv, nh in demands:
            if chosen is None and approves:
                lacking = [flag for flag, need in (("overrides_veto", nv),
                                                   ("overrides_hold + reason", nh)) if need]
                if lacking:
                    reason += f" (an approval exists but lacks {', '.join(lacking)})"
            results.append(RuleResult(rule=rule, effect=REQUIRE, reason=reason,
                                      satisfied=chosen is not None))
        if chosen is not None:
            relied.append(chosen.event_uid)

        if any(r.effect == DENY for r in results):
            outcome = PolicyOutcome.DENY
        elif any(not r.satisfied for r in results):
            outcome = PolicyOutcome.REQUIRE_APPROVAL
        else:
            outcome = PolicyOutcome.ALLOW

        blocked = [uid for rule, uid in blockers if outcome != PolicyOutcome.ALLOW]
        return PolicyDecision(
            incident_id=incident_id, action=action, asset_id=asset_id,
            tier=int(spec.tier) if spec else None, outcome=outcome,
            rule_results=results,
            approval_id=chosen.id if (chosen and outcome == PolicyOutcome.ALLOW) else None,
            relied_on_event_uids=list(dict.fromkeys(relied)),
            blocked_by_event_uids=list(dict.fromkeys(blocked)),
            policy_version=cfg.version,
            snapshot_hash=snapshot_hash(snapshot, action, asset_id, requester),
        )
