"""CyberRescue Phase 2B — deterministic synthetic scenarios and their ground truth."""

import hashlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

from cyberrescue.telemetry.ground_truth import GroundTruth, consistency_errors
from cyberrescue.telemetry.scenarios import SCENARIOS, build, get_scenario
from shared.mock_data import load_alert, load_assets

REPO = Path(__file__).resolve().parent.parent
KEYS = ("A", "B", "C")


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _digest(key: str) -> str:
    events, gt = build(key)
    blob = "\n".join(json.dumps(e.model_dump(mode="json"), sort_keys=True) for e in events)
    return hashlib.sha256((blob + gt.model_dump_json()).encode()).hexdigest()


def test_scenarios_map_to_the_existing_incidents():
    assert {k: (s.incident_alias, s.incident_id) for k, s in SCENARIOS.items()} == {
        "A": ("INC-C", "INC-C-2026-0042"),
        "B": ("INC-B", "INC-B-2026-0041"),
        "C": ("INC-A", "INC-A-2026-0039"),
    }
    for s in SCENARIOS.values():
        assert load_alert(s.incident_alias)["incident_id"] == s.incident_id


@pytest.mark.parametrize("ref", ["a", "A", "scenario-a", "SCENARIO_A"])
def test_get_scenario_accepts_common_spellings(ref):
    assert get_scenario(ref).key == "A"


def test_get_scenario_rejects_unknown():
    with pytest.raises(KeyError):
        get_scenario("D")


@pytest.mark.parametrize("key", KEYS)
def test_build_is_deterministic_in_process(key):
    assert _digest(key) == _digest(key)


def test_build_is_deterministic_across_processes_and_hash_seeds():
    code = ("import sys; sys.path.insert(0, %r)\n"
            "from tests.test_telemetry_scenarios import _digest\n"
            "print(','.join(_digest(k) for k in 'ABC'))") % str(REPO)
    outs = set()
    for seed in ("0", "12345"):
        res = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True,
                             text=True, check=True, env={**__import__("os").environ,
                                                         "PYTHONHASHSEED": seed})
        outs.add(res.stdout.strip())
    assert outs == {",".join(_digest(k) for k in KEYS)}


@pytest.mark.parametrize("key", KEYS)
def test_events_are_time_ordered_with_sequential_neutral_ids(key):
    spec = SCENARIOS[key]
    events, _ = build(key)
    assert [e.event_id for e in events] == [f"{spec.dataset}-{n:06d}"
                                            for n in range(1, len(events) + 1)]
    times = [_ts(e.timestamp) for e in events]
    assert times == sorted(times)
    assert spec.start <= times[0] and times[-1] <= spec.end
    assert {e.dataset for e in events} == {spec.dataset}
    assert {e.provenance.value for e in events} == {"synthetic"}


@pytest.mark.parametrize("key", KEYS)
def test_hosts_come_from_the_asset_inventory(key):
    inventory = {a["asset_id"] for a in load_assets()}
    events, _ = build(key)
    assert {e.host for e in events if e.host} <= inventory


@pytest.mark.parametrize("key", KEYS)
def test_ground_truth_is_consistent_and_evaluation_only(key):
    events, gt = build(key)
    assert isinstance(gt, GroundTruth) and gt.evaluation_only is True
    assert gt.ground_truth_schema == "cyberrescue.ground_truth/v1"
    assert consistency_errors(gt, events) == []
    assert (gt.incident_alias, gt.incident_id) == (SCENARIOS[key].incident_alias,
                                                   SCENARIOS[key].incident_id)


def test_consistency_errors_detect_bad_ground_truth():
    events, gt = build("A")
    bad = gt.model_copy(update={"malicious_event_ids": gt.malicious_event_ids + ["nope"],
                                "event_count": 1})
    errs = consistency_errors(bad, events)
    assert any("unknown event ids" in e for e in errs) and any("event_count" in e for e in errs)
    benign = next(e.event_id for e in events if e.event_id not in gt.malicious_event_ids
                  and e.category.value != "alert")
    errs = consistency_errors(gt.model_copy(update={"vendor_alert_event_ids": [benign]}),
                              events)
    assert any("not an alert" in e for e in errs)


@pytest.mark.parametrize("key", KEYS)
def test_vendor_alert_is_ordinary_telemetry_matching_the_mock_alert(key):
    spec = SCENARIOS[key]
    alert = load_alert(spec.incident_alias)
    events, gt = build(key)
    alerts = [e for e in events if e.category.value == "alert"]
    assert [a.event_id for a in alerts] == gt.vendor_alert_event_ids and len(alerts) == 1
    a = alerts[0]
    assert _ts(a.timestamp) == _ts(alert["detected_utc"])
    assert a.host == alert["asset_id"] and alert["raw_signal"] in a.message
    # The alert is NOT labelled attacker activity: it is a sensor's opinion.
    assert a.event_id not in gt.malicious_event_ids


@pytest.mark.parametrize("key", KEYS)
def test_alert_indicators_are_observable_in_telemetry(key):
    blob = "\n".join(e.message for e in build(key)[0])
    for indicator in load_alert(SCENARIOS[key].incident_alias)["indicators"]:
        assert indicator in blob, indicator


@pytest.mark.parametrize("key", KEYS)
def test_attacker_activity_precedes_detection(key):
    events, gt = build(key)
    detected = _ts(load_alert(SCENARIOS[key].incident_alias)["detected_utc"])
    by_id = {e.event_id: e for e in events}
    assert all(_ts(by_id[i].timestamp) <= detected for i in gt.malicious_event_ids)


@pytest.mark.parametrize("key", KEYS)
def test_events_carry_no_trace_of_ground_truth(key):
    events, gt = build(key)
    blob = "\n".join(json.dumps(e.model_dump(mode="json")) for e in events).lower()
    for marker in ("malicious", "stage:", "explain:", "vendor_alert", "ground_truth",
                   "evaluation_only", "true_positive", "false_positive", "attack_chain"):
        assert marker not in blob, marker
    # Attacker events use the same sensors and shapes as benign ones.
    mal = set(gt.malicious_event_ids)
    assert {e.sensor for e in events if e.event_id in mal} <= \
        {e.sensor for e in events if e.event_id not in mal}


@pytest.mark.parametrize("key", KEYS)
def test_each_scenario_contains_hostile_content(key):
    events, gt = build(key)
    hostile = [e for e in events if e.event_id in gt.hostile_content_event_ids]
    assert hostile and all("IGNORE PREVIOUS INSTRUCTIONS" in e.message for e in hostile)


def test_scenario_a_ransomware_facts():
    events, gt = build("A")
    assert (gt.verdict, gt.category) == ("true_positive", "ransomware")
    assert [s.stage for s in gt.attack_chain] == [
        "execution", "inhibit_recovery", "command_and_control", "lateral_movement_attempt",
        "impact"]
    mal = [e for e in events if e.event_id in gt.malicious_event_ids]
    assert any(e.fields.get("destination.ip") == "185.220.101.47" for e in mal)
    smb = {e.fields["destination.ip"] for e in mal
           if e.sensor == "netflow" and e.fields.get("destination.port") == 445}
    assert smb == {"10.20.2.21", "10.10.0.5"}                      # app + dc
    renames = [e for e in mal if e.action == "file_rename"]
    assert len(renames) >= 20 and all(e.fields["file.path"].endswith(".blackhaze")
                                      for e in renames)
    notes = [e for e in mal if e.action == "file_create"
             and e.fields["file.path"].endswith("RECOVER_YOUR_FILES.txt")]
    assert len(notes) >= 3
    # The benign confounder uses the same service account.
    assert any(e.user == "svc_sqlbackup" and e.event_id not in gt.malicious_event_ids
               for e in events)
    assert len(gt.malicious_event_ids) < len(events) / 2


def test_scenario_b_is_a_false_positive():
    events, gt = build("B")
    assert (gt.verdict, gt.malicious_event_ids, gt.attack_chain) == ("false_positive", [], [])
    assert gt.facts["destinations_allowlisted"] is True
    outbound = {e.fields.get("destination.ip") for e in events
                if e.sensor == "netflow" and e.host == "srv-web-01"}
    assert outbound == {"8.8.8.8", "13.107.4.50"}
    assert not [e for e in events if e.category.value in ("auth", "file")]


def test_scenario_c_has_no_lateral_movement():
    events, gt = build("C")
    assert (gt.verdict, gt.category) == ("true_positive", "malware")
    assert gt.facts["lateral_movement_attempted"] is False
    ws_ip = "10.30.5.114"
    lateral_ports = {445, 135, 139, 3389, 5985, 5986}
    assert not [e for e in events if e.fields.get("source.ip") == ws_ip
                and e.fields.get("destination.port") in lateral_ports]
    blocked = [e for e in events if e.sensor == "proxy" and e.fields["event.action"] == "blocked"]
    assert [e.fields["url.original"] for e in blocked] == ["cdn-pidgin-loader.net:443"]
