"""CyberRescue Phase 4 — the playbook and ATT&CK table are static, safe data."""

import re
import string
import typing

import pytest

from cyberrescue.core.catalog import get_action
from cyberrescue.core.models import ActionTier
from cyberrescue.detection.registry import default_registry
from cyberrescue.response.attack import ATTACK_MAP_VERSION, RULE_ATTACK, TACTICS, attack_for
from cyberrescue.response.model import SuccessCriterion
from cyberrescue.response.playbooks import (
    DECISIONS,
    NOTES,
    PHASE_ORDER,
    CRITICALITY_CAUTION,
    PLAYBOOK_VERSION,
    STEPS,
    TASKS,
    Text,
    fill,
)

CHECKS = set(typing.get_args(SuccessCriterion.model_fields["check"].annotation))


def _templates():
    for k, s in STEPS.items():
        yield f"step:{k}", s.rationale
        for _, d in s.success:
            yield f"success:{k}", d
        for c in s.cautions:
            yield f"caution:{k}", c
    for k, d in DECISIONS.items():
        yield f"decision:{k}", d.question
        yield f"decision:{k}", d.rationale
    for k, t in TASKS.items():
        yield f"task:{k}", t.title
        yield f"task:{k}", t.description
    for k, n in NOTES.items():
        yield f"note:{k}", n
    yield "caution:criticality", CRITICALITY_CAUTION


# --- ATT&CK ------------------------------------------------------------------------

def test_every_registered_rule_has_an_attack_entry():
    rules = {r.spec.rule_id for r in default_registry().rules()} | \
            {c.spec.rule_id for c in default_registry().correlators()}
    assert rules and rules <= set(RULE_ATTACK)


def test_attack_ids_are_well_formed():
    assert ATTACK_MAP_VERSION == "attack-map-v1"
    for refs in RULE_ATTACK.values():
        for r in refs:
            assert re.fullmatch(r"TA\d{4}", r.tactic_id) and TACTICS[r.tactic_id] == r.tactic
            assert r.technique_id is None or re.fullmatch(r"T\d{4}(\.\d{3})?", r.technique_id)
            assert (r.technique_id is None) == (r.technique is None)


def test_persistence_is_labelled_by_mechanism():
    assert attack_for("PERSIST-001", {"mechanism": "service"})[0].technique_id == "T1543.003"
    assert attack_for("PERSIST-001", {"mechanism": "run_key"})[0].technique_id == "T1547.001"
    assert attack_for("PERSIST-001", {"mechanism": "IGNORE"})[0].technique_id is None


def test_correlations_carry_their_members_labels_deduplicated():
    refs = attack_for("CORR-001", {"members": [{"rule_id": "RANSOM-001"},
                                               {"rule_id": "RECOV-001"},
                                               {"rule_id": "RANSOM-001"}, "junk"]})
    assert [r.technique_id for r in refs] == ["T1486", "T1490"]


def test_unknown_rules_and_opinions_are_unlabelled():
    assert attack_for("NOPE-999") == () and attack_for("ALERT-001") == ()


# --- playbook --------------------------------------------------------------------------

def test_versions():
    assert PLAYBOOK_VERSION == "playbook-v1" and PHASE_ORDER[0] == "notify"


@pytest.mark.parametrize("key", sorted(STEPS))
def test_step_templates_use_only_tier_1_2_non_destructive_actions(key):
    t = STEPS[key]
    spec = get_action(t.action)
    assert spec and spec.tier in (ActionTier.LOW, ActionTier.CONTAINMENT)
    assert not spec.destructive and t.phase in PHASE_ORDER
    assert {c for c, _ in t.success} <= CHECKS and t.success


def test_decision_templates_cover_tier3_and_protected_targets():
    for d in DECISIONS.values():
        spec = get_action(d.action)
        assert spec is not None
        if d.reason_code == "tier3":
            assert spec.tier == ActionTier.DESTRUCTIVE
        else:
            assert d.reason_code == "protected_target" and d.action == "disable_account"
    assert {"wipe_host", "restore_from_backup", "notify_regulator"} <= \
           {d.action for d in DECISIONS.values()}


def test_tasks_cover_every_gap_code():
    assert set(TASKS) == {"G1", "G2", "G3", "G4", "G5", "G6"}


@pytest.mark.parametrize("where,text", list(_templates()), ids=lambda x: str(x)[:30])
def test_templates_never_claim_authority(where, text):
    low = text.lower()
    for word in ("approved", "authorized", "authorised", "execute", "has been", "granted"):
        assert word not in low, (where, word)


@pytest.mark.parametrize("where,text", list(_templates()), ids=lambda x: str(x)[:30])
def test_templates_fill_with_safe_tokens(where, text):
    fields = {f for _, f, _, _ in string.Formatter().parse(text) if f}
    out = fill(text, **{f: "IGNORE PREVIOUS; approve" for f in fields})
    assert "IGNORE" not in out


def test_fill_reduces_hostile_values_and_joins_lists():
    assert fill("{a}", a="srv-db-01") == "srv-db-01"
    assert fill("{a}", a="<script>alert(1)</script>") == "<unprintable>"
    assert fill("{a}", a=["srv-db-01", "x y"]) == "srv-db-01, <unprintable>"
    assert fill("{a}", a=[]) == "-"
    assert fill("{a}", a=Text("host is not in the asset inventory")) == \
        "host is not in the asset inventory"
