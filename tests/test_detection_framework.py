"""CyberRescue Phase 2C — detection model, registry and context."""

import pytest
from pydantic import ValidationError

from cyberrescue.detection.context import EvidenceView, ThreatIntel
from cyberrescue.detection.model import (
    ConditionResult,
    ConditionSpec,
    Detection,
    Observation,
    RuleSpec,
    Window,
    raise_confidence,
)
from cyberrescue.detection.registry import Rule, RuleRegistry, default_registry
from tests._detection_factory import Evidence, assets, at


def spec(**over):
    base = dict(rule_id="TEST-001", version=1, name="t", description="d",
                finding_type="execution", severity="medium",
                window=Window(name="w", seconds=300),
                conditions=(ConditionSpec(id="req", description="r", role="required"),
                            ConditionSpec(id="corr", description="c", role="corroborating")))
    return RuleSpec(**(base | over))


def make_rule(s, *, corroborate=True):
    class _R(Rule):
        spec = s

        def evaluate(self, view):
            ids = [e.id for e in view.events]
            if not ids:
                return []
            m = {"req": ConditionResult(id="req", matched=True, evidence_ids=tuple(ids))}
            if corroborate and "corr" in s.corroborating:
                m["corr"] = ConditionResult(id="corr", matched=True)
            return [self.result(view, key={"k": 1}, matched=m, supporting=ids,
                                primary_host="srv-db-01", entities={}, summary="s")]
    return _R()


def one_event_view():
    ev = Evidence()
    ev.proc(at("14:00:00"), "srv-db-01", "C:\\x.exe")
    return ev.view()


# --- specs -----------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    {"rule_id": "lat-1"}, {"version": 0}, {"window": {"name": "w", "seconds": 0}},
    {"window": {"name": "w", "seconds": 86401}}, {"severity": "urgent"},
    {"finding_type": "T1486"},
    {"conditions": (ConditionSpec(id="c", description="", role="corroborating"),)},
    {"conditions": (ConditionSpec(id="a", description="", role="required"),
                    ConditionSpec(id="a", description="", role="required"))},
    {"min_corroboration": 2},
])
def test_rule_spec_validation(bad):
    with pytest.raises(ValidationError):
        spec(**bad)


def test_condition_id_format():
    with pytest.raises(ValidationError):
        ConditionSpec(id="Bad Id", description="", role="required")


def test_confidence_steps_are_capped():
    assert [raise_confidence("low", n) for n in range(4)] == ["low", "medium", "high", "high"]


# --- results -------------------------------------------------------------------

def test_detection_requires_supporting_evidence():
    view = one_event_view()
    det = make_rule(spec()).evaluate(view)[0]
    with pytest.raises(ValidationError, match="supporting evidence"):
        Detection(**(det.model_dump() | {"supporting_evidence_ids": ()}))
    with pytest.raises(ValidationError, match="must not repeat"):
        Detection(**(det.model_dump() | {"context_evidence_ids": det.supporting_evidence_ids}))


def test_result_lists_every_condition_and_explains_confidence():
    det = make_rule(spec()).evaluate(one_event_view())[0]
    assert isinstance(det, Detection)
    assert [c.id for c in det.conditions] == ["req", "corr"] and all(c.matched
                                                                     for c in det.conditions)
    assert det.confidence == "medium" and "1/1 corroborating (corr)" in det.confidence_basis
    assert det.detection_id.startswith("DET-") and det.detection_key.startswith("DK-")


def test_insufficient_corroboration_yields_observation_not_detection():
    res = make_rule(spec(min_corroboration=1), corroborate=False).evaluate(one_event_view())[0]
    assert isinstance(res, Observation) and res.kind == "partial_match"
    assert "0/1 corroborating" in res.reason


def test_result_refuses_unmet_required_conditions():
    class Bad(Rule):
        spec = spec()

        def evaluate(self, view):
            return [self.result(view, key=1, matched={}, supporting=[view.events[0].id],
                                primary_host=None, entities={}, summary="s")]
    with pytest.raises(ValueError, match="required conditions not met"):
        Bad().evaluate(one_event_view())


def test_ids_are_content_derived():
    a = make_rule(spec()).evaluate(one_event_view())[0]
    b = make_rule(spec()).evaluate(one_event_view())[0]
    assert a == b
    c = make_rule(spec(version=2)).evaluate(one_event_view())[0]
    assert c.detection_id != a.detection_id and c.detection_key == a.detection_key


# --- registry --------------------------------------------------------------------

def test_registry_rejects_duplicates_non_rules_and_frozen_mutation():
    reg = RuleRegistry()
    reg.register(make_rule(spec()))
    with pytest.raises(ValueError, match="duplicate"):
        reg.register(make_rule(spec()))
    with pytest.raises(TypeError):
        reg.register(object())
    reg.freeze()
    with pytest.raises(RuntimeError, match="frozen"):
        reg.register(make_rule(spec(rule_id="TEST-002")))


def test_registry_version_fingerprints_specs():
    def version(*specs):
        reg = RuleRegistry()
        for s in specs:
            reg.register(make_rule(s))
        return reg.version
    v1 = version(spec())
    assert v1.startswith("cyberrescue.detection/1+")
    assert version(spec()) == v1
    assert version(spec(version=2)) != v1
    assert version(spec(), spec(rule_id="TEST-002")) == version(spec(rule_id="TEST-002"),
                                                                 spec())


def test_default_registry_is_frozen():
    reg = default_registry()
    with pytest.raises(RuntimeError):
        reg.register(make_rule(spec()))


# --- view ----------------------------------------------------------------------

def test_view_orders_chronologically_and_hides_raw():
    ev = Evidence()
    late = ev.proc(at("14:05:00"), "srv-db-01", "C:\\a.exe")
    early = ev.proc(at("14:00:00"), "srv-db-01", "C:\\b.exe")
    view = ev.view()
    assert [e.id for e in view.events] == [early, late]
    assert view.ordered([late, early, late]) == (early, late)
    assert not hasattr(view.events[0], "raw")


def test_view_refuses_other_incidents_evidence():
    ev = Evidence()
    ev.proc(at("14:00:00"), "srv-db-01", "C:\\a.exe")
    other = Evidence(incident="INC-T-0002")
    other.proc(at("14:00:00"), "srv-db-01", "C:\\a.exe")
    with pytest.raises(ValueError, match="other incidents"):
        EvidenceView("INC-T-0001", ev.records + other.records,
                     intel=ThreatIntel([]), assets=assets())


def test_view_fingerprint_ignores_ingestion_metadata():
    ev = Evidence()
    ev.proc(at("14:00:00"), "srv-db-01", "C:\\a.exe")
    v1 = ev.view()
    ev.records[0] = ev.records[0].model_copy(update={"ingested_by": "someone-else",
                                                     "ingested_at": "2030-01-01T00:00:00"})
    assert ev.view().fingerprint == v1.fingerprint
