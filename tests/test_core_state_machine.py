"""CyberRescue Core — incident lifecycle (cyberrescue/core/state_machine.py)."""

from cyberrescue.core.models import ActorKind, IncidentStatus
from cyberrescue.core.state_machine import Trigger, next_status

S = IncidentStatus
AGENT, HUMAN, SYSTEM = ActorKind.AGENT, ActorKind.HUMAN, ActorKind.SYSTEM


def _run(steps, start=S.NEW):
    """Apply (trigger, kind, role) steps; return the list of statuses visited."""
    cur, seen = start, [start]
    for trig, kind, role in steps:
        res = next_status(cur, trig, kind, role)
        assert res.allowed, (trig, cur, res.reason)
        cur = res.to_status
        seen.append(cur)
    return seen


def test_inc_c_contested_path_with_escalation():
    seen = _run([
        (Trigger.BRIEF, AGENT, "triage"),
        (Trigger.SIGNOFF_REQUEST, AGENT, "commander"),
        (Trigger.ACTION_AUTHORIZED, SYSTEM, "core"),      # isolate/image
        (Trigger.ESCALATION, AGENT, "commander"),         # the contested wipe
        (Trigger.ACTION_AUTHORIZED, SYSTEM, "core"),      # side action: stays escalated
        (Trigger.HUMAN_RULING, HUMAN, "ciso"),
        (Trigger.RESOLUTION, AGENT, "commander"),
    ])
    assert seen == [S.NEW, S.INVESTIGATING, S.AWAITING_SIGNOFF, S.RESPONDING,
                    S.AWAITING_HUMAN, S.AWAITING_HUMAN, S.RESPONDING, S.RESOLVED]


def test_inc_a_clean_path_without_escalation():
    seen = _run([
        (Trigger.BRIEF, AGENT, "triage"),
        (Trigger.SIGNOFF_REQUEST, AGENT, "commander"),
        (Trigger.ACTION_AUTHORIZED, SYSTEM, "core"),
        (Trigger.RESOLUTION, AGENT, "commander"),
    ])
    assert S.AWAITING_HUMAN not in seen and seen[-1] == S.RESOLVED


def test_inc_b_false_positive_close():
    assert _run([(Trigger.CLOSE, AGENT, "triage")])[-1] == S.CLOSED_FALSE_POSITIVE


def test_illegal_transitions_are_rejected_with_a_reason():
    res = next_status(S.NEW, Trigger.RESOLUTION, AGENT, "commander")
    assert not res.allowed and res.to_status == S.NEW and "not valid from NEW" in res.reason
    res = next_status(S.INVESTIGATING, Trigger.HUMAN_RULING, HUMAN, "ciso")
    assert not res.allowed


def test_terminal_states_are_frozen():
    for terminal in (S.RESOLVED, S.CLOSED_FALSE_POSITIVE):
        for trig in Trigger:
            res = next_status(terminal, trig, HUMAN, "ciso")
            assert not res.allowed and "terminal" in res.reason


def test_role_restrictions_and_awaiting_human_rule():
    # Threat Intel cannot resolve; Triage cannot escalate; an agent cannot
    # masquerade as the system that authorizes actions.
    assert not next_status(S.RESPONDING, Trigger.RESOLUTION, AGENT, "threat_intel").allowed
    assert not next_status(S.AWAITING_SIGNOFF, Trigger.ESCALATION, AGENT, "triage").allowed
    assert not next_status(S.RESPONDING, Trigger.ACTION_AUTHORIZED, AGENT, "commander").allowed
    # An observer human's message is not a ruling.
    assert not next_status(S.AWAITING_HUMAN, Trigger.HUMAN_RULING, HUMAN, "observer").allowed
    # While awaiting the CISO, the Commander may NOT resolve; the human may.
    res = next_status(S.AWAITING_HUMAN, Trigger.RESOLUTION, AGENT, "commander")
    assert not res.allowed and "only a human" in res.reason
    assert next_status(S.AWAITING_HUMAN, Trigger.RESOLUTION, HUMAN, "ciso").allowed
