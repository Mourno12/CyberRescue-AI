"""CyberRescue Phase 3 — investigation CLI (python -m cyberrescue.investigation)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cyberrescue.investigation.cli import main
from cyberrescue.telemetry.importer import import_events
from tests._detection_factory import investigated_core, scenario_core

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def dbp(tmp_path_factory):
    return str(investigated_core(tmp_path_factory.mktemp("icli") / "core.db"))


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_case_json_to_stdout(capsys, dbp):
    code, out, _ = run(capsys, "--db", dbp, "case", "--incident", "INC-C")
    doc = json.loads(out)
    assert code == 0 and doc["incident_id"] == "INC-C-2026-0042" and doc["case_sha256"]


@pytest.mark.parametrize("fmt", ["md", "html"])
def test_case_out_writes_only_that_file(capsys, dbp, tmp_path, fmt):
    target = tmp_path / f"case.{fmt}"
    code, out, err = run(capsys, "--db", dbp, "case", "--incident", "INC-A", "--format", fmt,
                         "--out", str(target))
    assert code == 0 and out == "" and f"wrote {fmt} case" in err
    assert sorted(p.name for p in tmp_path.iterdir()) == [target.name]
    assert "INC-A-2026-0039" in target.read_text(encoding="utf-8")


def test_include_raw_flag(capsys, dbp):
    _, plain, _ = run(capsys, "--db", dbp, "case", "--incident", "INC-C")
    _, raw, _ = run(capsys, "--db", dbp, "case", "--incident", "INC-C", "--include-raw")
    assert json.loads(plain)["raw_evidence"] == [] and json.loads(raw)["raw_evidence"]


def test_timeline_variants(capsys, dbp):
    code, out, _ = run(capsys, "--db", dbp, "timeline", "--incident", "INC-C", "--cited-only")
    assert code == 0 and "file_rename" in out and "x34" in out
    assert "15 entries for 59/225 evidence records" in out
    _, out, _ = run(capsys, "--db", dbp, "timeline", "--incident", "INC-C", "--host",
                    "srv-dc-01", "--json")
    assert {e["host"] for e in json.loads(out)["entries"]} == {"srv-dc-01"}


def test_scope_and_gaps(capsys, dbp):
    _, out, _ = run(capsys, "--db", dbp, "scope", "--incident", "INC-C")
    assert "compromised  srv-db-01" in out and "not a recommendation" in out
    _, out, _ = run(capsys, "--db", dbp, "gaps", "--incident", "INC-C", "--json")
    assert [g["code"] for g in json.loads(out)] == ["G1", "G4", "G5"]


def test_pivot_entity_path_and_provenance(capsys, dbp):
    _, out, _ = run(capsys, "--db", dbp, "entity", "--incident", "INC-A", "--domain",
                    "CDN-Pidgin-Loader.net")
    assert "http_request" in out and "--requested-->" in out
    evid = out.split()[0]
    code, out, _ = run(capsys, "--db", dbp, "pivot", "--incident", "INC-A", "--evidence", evid,
                       "--by", "domain", "--window", "5m")
    assert code == 0 and "shared: domain:cdn-pidgin-loader.net" in out
    code, out, _ = run(capsys, "--db", dbp, "path", "--incident", "INC-C", "--from",
                       "host:srv-db-01", "--to", "host:srv-app-01")
    assert code == 0 and "--remote_auth-->" in out and "not causation" in out
    code, _, _ = run(capsys, "--db", dbp, "path", "--incident", "INC-C", "--from",
                     "host:srv-db-01", "--to", "host:nowhere")
    assert code == 1
    code, out, _ = run(capsys, "--db", dbp, "provenance", "--evidence", evid, "--json")
    assert code == 0 and json.loads(out)["integrity_ok"] is True


def test_verify_case_exit_codes(capsys, dbp, tmp_path):
    case = tmp_path / "case.json"
    run(capsys, "--db", dbp, "case", "--incident", "INC-B", "--out", str(case))
    code, out, _ = run(capsys, "--db", dbp, "verify-case", str(case))
    assert code == 0 and "VERIFIED" in out
    doc = json.loads(case.read_text(encoding="utf-8"))
    doc["gaps"] = []
    case.write_text(json.dumps(doc), encoding="utf-8")
    code, out, _ = run(capsys, "--db", dbp, "verify-case", str(case))
    assert code == 1 and "DOES NOT VERIFY" in out


@pytest.mark.parametrize("argv,needle", [
    (("--db", "{missing}", "scope", "--incident", "INC-C"), "never creates"),
    (("scope", "--incident", "INC-20990101-0001"), "no Core incident"),
    (("pivot", "--incident", "INC-C", "--evidence", "EV-x"), "not part of this incident"),
    (("pivot", "--incident", "INC-C", "--evidence", "EV-x", "--window", "soon"),
     "invalid window"),
])
def test_errors_exit_2(capsys, dbp, tmp_path, argv, needle):
    argv = [a.replace("{missing}", str(tmp_path / "none.db")) for a in argv]
    if argv[0] != "--db":
        argv = ["--db", dbp, *argv]
    code, _, err = run(capsys, *argv)
    assert code == 2 and needle in err
    assert not (tmp_path / "none.db").exists()


def test_terminal_output_is_sanitised(capsys, tmp_path):
    path = tmp_path / "ansi.db"
    svc, col = scenario_core(path, keys=("B",))
    import_events(svc, "INC-B", [{
        "event_id": "ansi-1", "dataset": "ansi", "timestamp": "2026-06-13T11:30:00Z",
        "sensor": "edr", "vendor": "X", "category": "alert", "action": "edr_detection",
        "host": "srv-web-01", "message": "m",
        "fields": {"rule.name": "\x1b]0;pwned\x07\x1b[2J evil ☃"}}],
        collector_id=col.id)
    svc.conn.close()
    _, out, _ = run(capsys, "--db", str(path), "timeline", "--incident", "INC-B")
    assert "\x1b" not in out and "\x07" not in out and out.isascii()
    assert "evil \\u2603" in out


def test_module_entry_point(dbp):
    res = subprocess.run([sys.executable, "-m", "cyberrescue.investigation", "--db", dbp,
                          "scope", "--incident", "INC-A"], cwd=REPO, capture_output=True,
                         text=True)
    assert res.returncode == 0 and "ws-eng-014" in res.stdout
