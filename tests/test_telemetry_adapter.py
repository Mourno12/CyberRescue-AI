"""CyberRescue Phase 2B — telemetry schema and the telemetry -> Evidence adapter."""

import json

import pytest

from cyberrescue.core.evidence import EvidenceEnvelope
from cyberrescue.telemetry.adapter import (
    ADAPTER_VERSION,
    load_telemetry_jsonl,
    parse_event,
    to_envelope,
    to_envelopes,
)
from cyberrescue.telemetry.schema import TELEMETRY_SCHEMA, TelemetryError, TelemetryEvent


def event(**over):
    base = {"event_id": "scenario-a-000001", "dataset": "scenario-a",
            "timestamp": "2026-06-13T16:01:12+02:00", "sensor": "edr", "vendor": "CrowdFalcon",
            "category": "process", "action": "process_start", "host": "srv-db-01",
            "user": "svc_sqlbackup", "message": "ProcessStart image=C:\\ProgramData\\upd\\bhz.exe",
            "fields": {"process.executable": "C:\\ProgramData\\upd\\bhz.exe",
                       "process.parent.name": "services.exe"}}
    return base | over


def test_event_normalises_timestamp_to_utc():
    ev = TelemetryEvent.model_validate(event())
    assert ev.timestamp == "2026-06-13T14:01:12+00:00"
    assert ev.provenance.value == "synthetic"


@pytest.mark.parametrize("bad", [
    {"timestamp": "2026-06-13T14:01:12"},          # no timezone
    {"category": "approval"},                      # unknown category
    {"sensor": "EDR!"},                            # bad slug
    {"dataset": "x" * 25},                         # slug too long
    {"event_id": "../etc/passwd"},
    {"message": ""},                               # raw line required
    {"vendor": ""},
    {"action": " "},
    {"fields": {"x": float("nan")}},               # not plain JSON
])
def test_event_validation_rejects(bad):
    with pytest.raises(TelemetryError):
        parse_event(event(**bad))


@pytest.mark.parametrize("extra", [
    {"incident_id": "INC-A-2026-0039"}, {"evidence_id": "EV-x"}, {"content_sha256": "0" * 64},
    {"ingested_by": "ciso"}, {"approved": True}, {"label": "malicious"},
])
def test_event_forbids_binding_integrity_and_label_fields(extra):
    with pytest.raises(TelemetryError):
        parse_event(event() | extra)


@pytest.mark.parametrize("fields", [
    {"label": "malicious"}, {"event.labels": ["attack"]}, {"nested": {"Is_Malicious": True}},
    {"gt.stage": "impact"}, {"list": [{"attack_stage": "c2"}]}, {"evaluation_only": True},
])
def test_event_fields_cannot_carry_evaluation_labels(fields):
    with pytest.raises(TelemetryError, match="evaluation labels"):
        parse_event(event(fields=fields))


def test_ground_truth_document_is_refused_as_telemetry():
    with pytest.raises(TelemetryError, match="evaluation-only"):
        parse_event({"evaluation_only": True, "scenario": "A", "malicious_event_ids": []})


def test_to_envelope_maps_every_field():
    env = to_envelope(event())
    assert isinstance(env, EvidenceEnvelope)
    assert env.source == "synthetic.scenario-a.edr"
    assert env.source_ref == "scenario-a-000001"
    assert (env.kind.value, env.event_type) == ("process", "process_start")
    assert env.observed_at == "2026-06-13T14:01:12+00:00"
    assert (env.host, env.user, env.provenance.value) == ("srv-db-01", "svc_sqlbackup",
                                                          "synthetic")
    assert env.raw == event()["message"] and env.data == event()["fields"]
    assert env.metadata == {"adapter": ADAPTER_VERSION, "telemetry_schema": TELEMETRY_SCHEMA,
                            "dataset": "scenario-a", "sensor": "edr", "vendor": "CrowdFalcon",
                            "provenance_note": "SYNTHETIC test data, not real telemetry"}


def test_replayed_provenance_carries_through_without_synthetic_note():
    env = to_envelope(event(provenance="replayed"))
    assert env.source == "replayed.scenario-a.edr" and env.provenance.value == "replayed"
    assert "provenance_note" not in env.metadata


def test_vendor_alert_maps_to_ordinary_alert_evidence():
    env = to_envelope(event(category="alert", action="edr_detection",
                            message="DetectName=Ransomware.BlackHaze Severity=Critical",
                            fields={"rule.name": "Ransomware.BlackHaze"}))
    assert env.kind.value == "alert" and env.event_type == "edr_detection"


def test_adapter_is_pure_and_deterministic():
    raw = event()
    assert to_envelope(raw) == to_envelope(json.loads(json.dumps(raw)))
    assert raw == event()                                  # input not mutated


def test_to_envelopes_is_all_or_nothing():
    with pytest.raises(TelemetryError, match="item 2") as e:
        to_envelopes([event(), event(timestamp="bad"), event(category="nope")])
    assert "item 3" in str(e.value)


def test_load_jsonl_all_or_nothing_with_line_numbers(tmp_path):
    p = tmp_path / "t.jsonl"
    p.write_text("\n".join([json.dumps(event()), "", "{not json",
                            json.dumps(event(event_id="scenario-a-000002", label="x")),
                            json.dumps(event())]), encoding="utf-8")
    with pytest.raises(TelemetryError) as e:
        load_telemetry_jsonl(p)
    msg = str(e.value)
    assert "line 3: invalid JSON" in msg and "line 4" in msg
    assert "line 5: duplicate event_id" in msg


def test_load_jsonl_tolerates_bom(tmp_path):
    p = tmp_path / "t.jsonl"
    p.write_text(json.dumps(event()) + "\n", encoding="utf-8-sig")
    assert [e.event_id for e in load_telemetry_jsonl(p)] == ["scenario-a-000001"]
