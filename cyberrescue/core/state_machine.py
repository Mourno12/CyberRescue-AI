"""Incident lifecycle state machine (pure, deterministic).

Mirrors the WarRoom protocol (shared/protocol.md §E.2) as explicit, checked
transitions instead of prompt instructions:

    NEW --BRIEF--> INVESTIGATING --SIGNOFF_REQUEST--> AWAITING_SIGNOFF
        --ACTION_AUTHORIZED--> RESPONDING --ESCALATION--> AWAITING_HUMAN
        --HUMAN_RULING--> RESPONDING --RESOLUTION--> RESOLVED
    NEW --CLOSE--> CLOSED_FALSE_POSITIVE

Each trigger also names WHO may fire it (role/kind taken from the actor the
Core resolved from transport metadata — never from message text). Two
protocol rules become hard checks here:
  * only a human can resolve an incident that is AWAITING_HUMAN (the
    Commander must wait for the CISO's ruling);
  * terminal states are frozen (no re-litigation after RESOLUTION/CLOSE).

Later phases add VERIFYING / RECOVERING states.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from cyberrescue.core.models import TERMINAL_STATUSES, ActorKind, IncidentStatus

S = IncidentStatus

# Humans whose word counts as a ruling on an escalation.
HUMAN_AUTHORITY_ROLES = frozenset({"ciso", "dpo", "general_counsel", "operator"})


class Trigger(str, Enum):
    BRIEF = "BRIEF"
    CLOSE = "CLOSE"
    SIGNOFF_REQUEST = "SIGNOFF_REQUEST"
    ESCALATION = "ESCALATION"
    HUMAN_RULING = "HUMAN_RULING"
    ACTION_AUTHORIZED = "ACTION_AUTHORIZED"
    RESOLUTION = "RESOLUTION"


# (trigger, from_status) -> to_status. to == from means "allowed, no change".
TRANSITIONS: dict[tuple[Trigger, IncidentStatus], IncidentStatus] = {
    (Trigger.BRIEF, S.NEW): S.INVESTIGATING,
    (Trigger.CLOSE, S.NEW): S.CLOSED_FALSE_POSITIVE,

    (Trigger.SIGNOFF_REQUEST, S.INVESTIGATING): S.AWAITING_SIGNOFF,
    (Trigger.SIGNOFF_REQUEST, S.AWAITING_SIGNOFF): S.AWAITING_SIGNOFF,
    (Trigger.SIGNOFF_REQUEST, S.RESPONDING): S.AWAITING_SIGNOFF,

    (Trigger.ESCALATION, S.INVESTIGATING): S.AWAITING_HUMAN,
    (Trigger.ESCALATION, S.AWAITING_SIGNOFF): S.AWAITING_HUMAN,
    (Trigger.ESCALATION, S.RESPONDING): S.AWAITING_HUMAN,
    (Trigger.ESCALATION, S.AWAITING_HUMAN): S.AWAITING_HUMAN,

    (Trigger.HUMAN_RULING, S.AWAITING_HUMAN): S.RESPONDING,

    (Trigger.ACTION_AUTHORIZED, S.INVESTIGATING): S.RESPONDING,
    (Trigger.ACTION_AUTHORIZED, S.AWAITING_SIGNOFF): S.RESPONDING,
    (Trigger.ACTION_AUTHORIZED, S.RESPONDING): S.RESPONDING,
    # An authorized side action (e.g. imaging) does not end an escalation.
    (Trigger.ACTION_AUTHORIZED, S.AWAITING_HUMAN): S.AWAITING_HUMAN,

    (Trigger.RESOLUTION, S.INVESTIGATING): S.RESOLVED,
    (Trigger.RESOLUTION, S.AWAITING_SIGNOFF): S.RESOLVED,
    (Trigger.RESOLUTION, S.RESPONDING): S.RESOLVED,
    (Trigger.RESOLUTION, S.AWAITING_HUMAN): S.RESOLVED,  # humans only, see below
}


def _actor_may_fire(trigger: Trigger, kind: ActorKind, role: str) -> bool:
    human_authority = kind == ActorKind.HUMAN and role in HUMAN_AUTHORITY_ROLES
    agent = kind == ActorKind.AGENT
    if trigger in (Trigger.BRIEF, Trigger.CLOSE):
        return agent and role == "triage"
    if trigger in (Trigger.SIGNOFF_REQUEST, Trigger.ESCALATION):
        return agent and role == "commander"
    if trigger == Trigger.RESOLUTION:
        return (agent and role == "commander") or human_authority
    if trigger == Trigger.HUMAN_RULING:
        return human_authority
    if trigger == Trigger.ACTION_AUTHORIZED:
        return kind == ActorKind.SYSTEM
    return False


@dataclass(frozen=True)
class TransitionResult:
    allowed: bool
    from_status: IncidentStatus
    to_status: IncidentStatus   # == from_status when rejected or a no-op
    reason: str = ""

    @property
    def changed(self) -> bool:
        return self.allowed and self.to_status != self.from_status


def next_status(current: IncidentStatus, trigger: Trigger | str,
                actor_kind: ActorKind, actor_role: str) -> TransitionResult:
    """Decide the effect of ``trigger`` fired by an actor in state ``current``."""
    trig = Trigger(trigger)
    cur = IncidentStatus(current)

    def reject(reason: str) -> TransitionResult:
        return TransitionResult(False, cur, cur, reason)

    if cur in TERMINAL_STATUSES:
        return reject(f"incident is {cur.value}; terminal states are frozen")
    if not _actor_may_fire(trig, ActorKind(actor_kind), actor_role):
        return reject(f"{actor_kind.value if isinstance(actor_kind, ActorKind) else actor_kind}"
                      f"/{actor_role} may not fire {trig.value}")
    if trig == Trigger.RESOLUTION and cur == S.AWAITING_HUMAN \
            and ActorKind(actor_kind) != ActorKind.HUMAN:
        return reject("incident is awaiting a human ruling; only a human may resolve it")
    target = TRANSITIONS.get((trig, cur))
    if target is None:
        return reject(f"{trig.value} is not valid from {cur.value}")
    return TransitionResult(True, cur, target)
