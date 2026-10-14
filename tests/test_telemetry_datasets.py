"""CyberRescue Phase 2B — committed datasets are reproducible byte-for-byte."""

import hashlib
import json

import pytest

from cyberrescue.telemetry import datasets
from cyberrescue.telemetry.adapter import load_telemetry_jsonl
from cyberrescue.telemetry.ground_truth import load_ground_truth
from cyberrescue.telemetry.scenarios import SCENARIOS, build
from cyberrescue.telemetry.schema import TelemetryError

ROOT = datasets.DEFAULT_ROOT


def test_committed_datasets_match_a_fresh_render():
    assert datasets.check() == []


def test_committed_files_use_lf_line_endings():
    for p in ROOT.rglob("*.json*"):
        assert b"\r\n" not in p.read_bytes(), p


def test_manifest_hashes_and_counts_match_files():
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["provenance"] == "synthetic"
    assert [s["scenario"] for s in manifest["scenarios"]] == ["A", "B", "C"]
    for entry in manifest["scenarios"]:
        for part in ("telemetry", "ground_truth"):
            data = (ROOT / entry[part]["path"]).read_bytes()
            assert hashlib.sha256(data).hexdigest() == entry[part]["sha256"]
        events = load_telemetry_jsonl(ROOT / entry["telemetry"]["path"])
        assert len(events) == entry["telemetry"]["events"]
        assert sum(entry["telemetry"]["by_category"].values()) == len(events)


def test_manifest_carries_no_labels():
    text = (ROOT / "manifest.json").read_text(encoding="utf-8").lower()
    for marker in ("malicious", "benign", "true_positive", "false_positive", "verdict"):
        assert marker not in text


@pytest.mark.parametrize("key", list(SCENARIOS))
def test_committed_telemetry_round_trips_to_the_built_events(key):
    events, gt = build(key)
    assert load_telemetry_jsonl(datasets.telemetry_path(key)) == events
    assert load_ground_truth(ROOT / datasets.ground_truth_relpath(SCENARIOS[key])) == gt


def test_telemetry_and_ground_truth_live_in_separate_trees():
    tel = {p.name for p in (ROOT / "telemetry").iterdir()}
    gt = {p.name for p in (ROOT / "ground_truth").iterdir()}
    assert tel == {"scenario-a.jsonl", "scenario-b.jsonl", "scenario-c.jsonl"}
    assert gt == {"scenario-a.json", "scenario-b.json", "scenario-c.json"}


@pytest.mark.parametrize("key", list(SCENARIOS))
def test_ground_truth_file_cannot_be_loaded_as_telemetry(key, tmp_path):
    src = ROOT / datasets.ground_truth_relpath(SCENARIOS[key])
    one_line = tmp_path / "gt.jsonl"
    one_line.write_text(json.dumps(json.loads(src.read_text(encoding="utf-8"))) + "\n",
                        encoding="utf-8")
    with pytest.raises(TelemetryError, match="evaluation-only"):
        load_telemetry_jsonl(one_line)
    with pytest.raises(TelemetryError):
        load_telemetry_jsonl(src)                       # pretty-printed: not JSONL at all


def test_write_then_check_in_a_temp_dir_and_detect_tampering(tmp_path):
    written = datasets.write(tmp_path)
    assert len(written) == 7 and datasets.check(tmp_path) == []
    p = tmp_path / "telemetry" / "scenario-b.jsonl"
    p.write_bytes(p.read_bytes().replace(b"8.8.8.8", b"8.8.4.4", 1))
    (tmp_path / "ground_truth" / "scenario-c.json").unlink()
    problems = datasets.check(tmp_path)
    assert any("scenario-b.jsonl: differs" in x for x in problems)
    assert any("scenario-c.json: missing" in x for x in problems)
