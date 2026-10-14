"""CyberRescue Phase 1b — the gate hook inside WarRoom's Commander tools.

Exercises the real ``agents.commander.tools`` callables (the functions the
Anthropic adapter invokes) with the gate in shadow and enforce modes.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agents.commander import tools as cmd
from cyberrescue.core.band_import import open_legacy_incident
from cyberrescue.core.service import CoreService

REPO = Path(__file__).resolve().parent.parent
ORIGINAL_RESULT_KEYS = {"status", "logged_to", "timestamp_utc", "actor", "action",
                        "asset_id", "reason"}


@pytest.fixture
def paths(tmp_path, monkeypatch):
    p = {"db": tmp_path / "core.db", "gate": tmp_path / "gate.jsonl",
         "actions": tmp_path / "actions_log.jsonl"}
    monkeypatch.setenv("CYBERRESCUE_DB_PATH", str(p["db"]))
    monkeypatch.setenv("CYBERRESCUE_GATE_LOG", str(p["gate"]))
    monkeypatch.setenv("ACTIONS_LOG_PATH", str(p["actions"]))
    monkeypatch.setenv("CYBERRESCUE_INCIDENT", "INC-C")   # operator binds the incident
    monkeypatch.delenv("CYBERRESCUE_GATE_MODE", raising=False)
    return p


def _lines(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x] \
        if path.exists() else []


def _wipe():
    return cmd._wipe_host(cmd.wipe_host(asset_id="srv-db-01", reason="eradicate BlackHaze"))


def test_shadow_does_not_block_or_alter_the_commander(paths, monkeypatch):
    result = _wipe()   # default mode: shadow; the Core would NOT allow this wipe
    assert result["status"] == "executed" and set(result) == ORIGINAL_RESULT_KEYS
    assert [r["action"] for r in _lines(paths["actions"])] == ["wipe_host"]
    [gate] = _lines(paths["gate"])
    assert (gate["mode"], gate["verdict"], gate["proceed"]) == ("shadow", "DENY", True)
    assert gate["incident"] == "INC-C-2026-0042" and gate["unmet_rules"] == ["P6", "P8"]

    # Same call with the hook removed entirely = original WarRoom: identical shape.
    monkeypatch.setattr(cmd, "_cyberrescue_gate", lambda action, details: None)
    original = _wipe()
    assert set(original) == set(result)
    assert {k: v for k, v in original.items() if k != "timestamp_utc"} == \
        {k: v for k, v in result.items() if k != "timestamp_utc"}


def test_shadow_proceeds_even_if_the_core_is_broken(paths, monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERRESCUE_DB_PATH", str(tmp_path))   # a directory: Core error
    assert _wipe()["status"] == "executed"
    [gate] = _lines(paths["gate"])
    assert gate["error"] and gate["proceed"] is True


def test_enforce_blocks_a_prohibited_action_in_the_commander(paths, monkeypatch):
    monkeypatch.setenv("CYBERRESCUE_GATE_MODE", "enforce")
    result = _wipe()
    assert result["status"] == "blocked_by_policy"
    assert result["policy_outcome"] == "REQUIRE_APPROVAL" and "P8" in result["reason_blocked"]
    assert _lines(paths["actions"]) == []            # nothing executed
    [gate] = _lines(paths["gate"])
    assert (gate["mode"], gate["blocked"]) == ("enforce", True)


def test_enforce_executes_a_properly_approved_action(paths, monkeypatch):
    svc = CoreService.open(paths["db"])
    svc.seed_assets_from_mock()
    inc = open_legacy_incident(svc, "INC-C")
    ciso = svc.register_actor("human", "ciso", "CISO", "band:ciso")
    ap = svc.grant_approval(inc.id, action="wipe_host", asset_id="srv-db-01",
                            approver_actor_id=ciso.id, overrides_hold=True,
                            reason="CISO accepts evidence risk to stop domain compromise")
    monkeypatch.setenv("CYBERRESCUE_GATE_MODE", "enforce")
    result = _wipe()
    assert result["status"] == "executed" and set(result) == ORIGINAL_RESULT_KEYS
    assert [r["action"] for r in _lines(paths["actions"])] == ["wipe_host"]
    assert svc.store.get_approval(ap.id).consumed_by_request_id is not None
    assert _wipe()["status"] == "blocked_by_policy"   # approval was single-use
    svc.conn.close()


def test_enforce_fails_closed_when_the_core_is_unavailable(paths, monkeypatch):
    monkeypatch.setitem(sys.modules, "cyberrescue.core.gate", None)  # import -> ImportError
    monkeypatch.setenv("CYBERRESCUE_GATE_MODE", "enforce")
    result = _wipe()
    assert result["status"] == "blocked_by_policy" and "unavailable" in result["reason_blocked"]
    monkeypatch.setenv("CYBERRESCUE_GATE_MODE", "shadow")
    assert _wipe()["status"] == "executed"           # shadow: original behaviour


def test_importing_commander_tools_does_not_load_the_core():
    code = ("import sys, agents.commander.tools\n"
            "print(any(m.startswith('cyberrescue') for m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True,
                         text=True, check=True)
    assert out.stdout.strip() == "False"
