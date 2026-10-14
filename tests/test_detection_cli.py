"""CyberRescue Phase 2C — detection CLI (python -m cyberrescue.detection)."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from cyberrescue.core.cli import main as core_main
from cyberrescue.detection.cli import main
from tests._detection_factory import scenario_core

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def dbp(tmp_path_factory):
    path = tmp_path_factory.mktemp("detcli") / "core.db"
    svc, _ = scenario_core(path)
    svc.conn.close()
    return str(path)


def _run(capsys, *argv, fn=main):
    code = fn(list(argv))
    out = capsys.readouterr()
    return code, out.out + out.err


def _detector(capsys, dbp):
    _, out = _run(capsys, "--db", dbp, "register-actor", "--kind", "system", "--role",
                  "detector", "--name", "engine", fn=core_main)
    return re.search(r"actor (\w+)", out).group(1)


def test_rules_lists_every_rule_with_versions(capsys):
    code, out = _run(capsys, "rules", "-v")
    assert code == 0 and "cyberrescue.detection/1+" in out
    for rid in ("AUTH-001", "LAT-001", "PROC-001", "IOC-002", "RANSOM-001", "CORR-001"):
        assert re.search(rf"^{rid}\s+v1", out, re.M)
    assert "- mass_rename_common_extension (required)" in out


def test_dry_run_text_output(capsys, dbp):
    code, out = _run(capsys, "--db", dbp, "run", "--incident", "INC-B")
    assert code == 0 and "0 finding(s), 4 observation(s)" in out
    assert "OBSERVATION  NET-001" in out and "persisted" not in out
    code, out = _run(capsys, "--db", dbp, "run", "--incident", "INC-C", "--explain")
    assert "10 finding(s)" in out and "[x] mass_rename_common_extension" in out
    assert "confidence: base low + 3/3 corroborating" in out


def test_json_output_is_the_canonical_report(capsys, dbp):
    code, out = _run(capsys, "--db", dbp, "run", "--incident", "INC-A", "--json")
    rep = json.loads(out)
    assert code == 0 and rep["incident_id"] == "INC-A-2026-0039"
    assert sorted(d["rule_id"] for d in rep["detections"]) == [
        "CORR-001", "IOC-001", "IOC-002", "PERSIST-001", "PROC-001"]


def test_persist_requires_a_detector(capsys, dbp):
    code, out = _run(capsys, "--db", dbp, "run", "--incident", "INC-A", "--persist")
    assert code == 2 and "--persist needs --detector" in out
    _, out = _run(capsys, "--db", dbp, "register-actor", "--kind", "system", "--role",
                  "collector", fn=core_main)
    col = re.search(r"actor (\w+)", out).group(1)
    code, out = _run(capsys, "--db", dbp, "run", "--incident", "INC-A", "--persist",
                     "--detector", col)
    assert code == 2 and "role 'detector'" in out


def test_persist_then_list_findings_idempotently(capsys, dbp):
    det = _detector(capsys, dbp)
    code, out = _run(capsys, "--db", dbp, "run", "--incident", "INC-A", "--persist",
                     "--detector", det)
    assert code == 0 and "persisted 5 new finding(s), 0 already recorded" in out
    code, out = _run(capsys, "--db", dbp, "run", "--incident", "INC-A", "--persist",
                     "--detector", det)
    assert "persisted 0 new finding(s), 5 already recorded" in out
    code, out = _run(capsys, "--db", dbp, "findings", "--incident", "INC-A")
    assert code == 0 and "5 detection finding(s)" in out and "CORR-001" in out
    code, out = _run(capsys, "--db", dbp, "verify", fn=core_main)
    assert code == 0 and "TAMPERED" not in out


def test_unknown_incident_is_an_error(capsys, dbp):
    code, out = _run(capsys, "--db", dbp, "run", "--incident", "INC-20990101-0001")
    assert code == 2 and "no Core incident" in out


def test_module_entry_point():
    res = subprocess.run([sys.executable, "-m", "cyberrescue.detection", "rules"], cwd=REPO,
                         capture_output=True, text=True)
    assert res.returncode == 0 and "RANSOM-001" in res.stdout
