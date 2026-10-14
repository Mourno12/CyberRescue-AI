"""Policy PREVIEW: what the policy engine would answer - never a decision.

``PolicyEngine.evaluate`` is a pure function (no I/O, no clock). The preview
feeds it an ``IncidentSnapshot`` assembled from the same allow-listed reads
``CoreStore.snapshot`` uses (here through the read-only facade, so nothing can
be written), with ``now`` fixed to the plan's ``as_of``, and a HYPOTHETICAL
Commander requester that exists only in memory - it is not registered with the
Core and nothing it "requests" is recorded.

The result is wrapped in ``PolicyPreview`` (``authorizes`` is literally False).
Approvals that are valid at ``as_of`` may have expired by the time anyone
reads the plan; the real decision is made by ``request_action`` / the
Commander gate at request time.
"""

from __future__ import annotations

from datetime import datetime

from cyberrescue.core.models import Actor, ActorKind, IncidentSnapshot, PolicyOutcome
from cyberrescue.core.policy import PolicyConfig, PolicyEngine
from cyberrescue.investigation.model import untrusted
from cyberrescue.investigation.readonly import ReadOnlyCore
from cyberrescue.response.model import PolicyPreview, PreviewRule

HYPOTHETICAL_COMMANDER = Actor(id="hypothetical:commander", kind=ActorKind.AGENT,
                               role="commander",
                               display_name="hypothetical Commander (preview only)")


def readonly_snapshot(core: ReadOnlyCore, incident_id: str, as_of: str) -> IncidentSnapshot:
    """``CoreStore.snapshot`` rebuilt from allow-listed reads, with ``now = as_of``."""
    store = core.store
    req = store.latest_signoff_request(incident_id)
    return IncidentSnapshot(
        incident=store.get_incident(incident_id),
        assets={a.asset_id: a for a in store.list_assets()},
        signoff_request=req,
        signoffs=store.signoffs_for(req.event_uid) if req else [],
        vetoes=store.active_vetoes(incident_id),
        holds=store.active_holds(),
        approvals=store.unconsumed_approvals(incident_id),
        now=datetime.fromisoformat(as_of),
    )


class Previewer:
    """Evaluates hypothetical Commander requests against one snapshot."""

    def __init__(self, snapshot: IncidentSnapshot, *, as_of: str,
                 config: PolicyConfig | None = None) -> None:
        self.snapshot = snapshot
        self.as_of = as_of                 # the snapshot's fixed time, as the plan states it
        self._engine = PolicyEngine(config or PolicyConfig())

    @property
    def policy_version(self) -> str:
        return self._engine.config.version

    def preview(self, action: str, target: str | None, *, kind: str = "host") -> PolicyPreview:
        """``kind`` is the target kind; only host targets are evaluated with an asset id
        (``action_requests.asset_id`` references the inventory, so the Core itself can
        only request ip/account actions without one)."""
        asset_id = target if kind == "host" else None
        d = self._engine.evaluate(action=action, asset_id=asset_id,
                                  requester=HYPOTHETICAL_COMMANDER, snapshot=self.snapshot)
        return PolicyPreview(
            as_of=self.as_of, evaluated_asset_id=asset_id,
            outcome_if_requested=PolicyOutcome(d.outcome).value,
            unmet_rules=tuple(d.rules_failed),
            rule_results=tuple(PreviewRule(rule=r.rule, effect=r.effect, satisfied=r.satisfied,
                                           reason=untrusted(r.reason))
                               for r in d.rule_results),
            policy_version=d.policy_version, snapshot_hash=d.snapshot_hash)
