"""CyberRescue Phase 2B — telemetry CLI (python -m cyberrescue.telemetry)."""

import re
import subprocess
import sys
from pathlib import Path

import pytest

from cyberrescue.core.cli import main as core_main
from cyberrescue.telemetry.cli import main

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def dbp(tmp_path):
    return str(tmp_path / "core.db")


def _run(capsys, *argv, fn=main):
    code = fn(list(argv))
    out = capsys.readouterr()
    return code, out.out + out.err


def _actor(capsys, dbp, kind, role):
    _, out = _run(capsys, "--db", dbp, "register-actor", "--kind", kind, "--role", role,
                  fn=core_main)
    return re.search(r"actor (\w+)", out).group(1)


def test_list_shows_the_incident_mapping(capsys):
    code, out = _run(capsys, "list")
    assert code == 0
    assert re.search(r"A\s+scenario-a\s+INC-C \(INC-C-2026-0042\)\s+\d+ events", out)
    assert re.search(r"B\s+scenario-b\s+INC-B \(INC-B-2026-0041\)", out)
    assert re.search(r"C\s+scenario-c\s+INC-A \(INC-A-2026-0039\)", out)


def test_show_summarises_without_ground_truth(capsys):
    code, out = _run(capsys, "show", "--scenario", "B")
    assert code == 0 and "scenario B (scenario-b) -> INC-B" in out and "alert=1" in out
    for marker in ("malicious", "false_positive", "verdict", "benign"):
        assert marker not in out.lower()


def test_check_passes_and_generate_reproduces(capsys, tmp_path):
    code, out = _run(capsys, "check")
    assert code == 0 and "OK (byte-identical)" in out
    code, out = _run(capsys, "--root", str(tmp_path), "generate")
    assert code == 0 and out.count("wrote") == 7
    assert _run(capsys, "--root", str(tmp_path), "check")[0] == 0
    (tmp_path / "manifest.json").write_text("{}", encoding="utf-8")
    code, out = _run(capsys, "--root", str(tmp_path), "check")
    assert code == 1 and "manifest.json: differs" in out


def test_open_incident_then_ingest_end_to_end(capsys, dbp):
    code, out = _run(capsys, "--db", dbp, "open-incident", "--scenario", "A")
    assert code == 0 and "opened INC-C-2026-0042 (INC-C) on srv-db-01" in out
    code, out = _run(capsys, "--db", dbp, "open-incident", "--scenario", "A")
    assert code == 0 and "already open" in out and "nothing changed" in out

    col = _actor(capsys, dbp, "system", "collector")
    code, out = _run(capsys, "--db", dbp, "ingest", "--scenario", "A", "--collector", col)
    m = re.search(r"INC-C-2026-0042: (\d+) event\(s\) -> (\d+) evidence record\(s\) "
                  r"ingested, 0 duplicate", out)
    assert code == 0 and m and m.group(1) == m.group(2)
    code, out = _run(capsys, "--db", dbp, "ingest", "--scenario", "A", "--collector", col)
    assert code == 0 and f"0 evidence record(s) ingested, {m.group(1)} duplicate(s)" in out

    code, out = _run(capsys, "--db", dbp, "evidence", "--incident", "INC-C", "--kind",
                     "alert", fn=core_main)
    assert "edr_detection" in out and "[core] 1 evidence record(s)" in out
    code, out = _run(capsys, "--db", dbp, "verify", fn=core_main)
    assert code == 0 and "TAMPERED" not in out and "evidence INC-C-2026-0042: OK" in out


def test_ingest_file_into_explicit_incident(capsys, dbp):
    _run(capsys, "--db", dbp, "open-incident", "--scenario", "C")
    col = _actor(capsys, dbp, "system", "collector")
    f = str(REPO / "datasets" / "cyberrescue" / "synthetic" / "telemetry" / "scenario-c.jsonl")
    code, out = _run(capsys, "--db", dbp, "ingest", "--file", f, "--incident", "INC-A",
                     "--collector", col)
    assert code == 0 and "INC-A-2026-0039:" in out


@pytest.mark.parametrize("argv,needle", [
    (("ingest", "--scenario", "A", "--incident", "INC-B"), "bound to its catalogue"),
    (("ingest", "--file", "x.jsonl"), "--file needs --incident"),
    (("ingest", "--scenario", "Z"), "unknown scenario"),
])
def test_ingest_argument_errors(capsys, dbp, argv, needle):
    col = _actor(capsys, dbp, "system", "collector")
    code, out = _run(capsys, "--db", dbp, *argv, "--collector", col)
    assert code == 2 and needle in out


def test_ingest_refuses_agents_and_missing_incidents(capsys, dbp):
    agent = _actor(capsys, dbp, "agent", "threat_intel")
    col = _actor(capsys, dbp, "system", "collector")
    code, out = _run(capsys, "--db", dbp, "ingest", "--scenario", "B", "--collector", col)
    assert code == 2 and "no Core incident" in out
    _run(capsys, "--db", dbp, "open-incident", "--scenario", "B")
    code, out = _run(capsys, "--db", dbp, "ingest", "--scenario", "B", "--collector", agent)
    assert code == 2 and "may not submit evidence" in out


def test_ingesting_ground_truth_fails(capsys, dbp, tmp_path):
    _run(capsys, "--db", dbp, "open-incident", "--scenario", "A")
    col = _actor(capsys, dbp, "system", "collector")
    gt = REPO / "datasets" / "cyberrescue" / "synthetic" / "ground_truth" / "scenario-a.json"
    code, out = _run(capsys, "--db", dbp, "ingest", "--file", str(gt), "--incident", "INC-C",
                     "--collector", col)
    assert code == 2 and "invalid telemetry file" in out
    code, out = _run(capsys, "--db", dbp, "evidence", "--incident", "INC-C", fn=core_main)
    assert "[core] 0 evidence record(s)" in out


def test_module_entry_point(tmp_path):
    res = subprocess.run([sys.executable, "-m", "cyberrescue.telemetry", "list"], cwd=REPO,
                         capture_output=True, text=True)
    assert res.returncode == 0 and "scenario-a" in res.stdout
