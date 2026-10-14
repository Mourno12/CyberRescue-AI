"""CyberRescue Phase 5 — the execution CLI only simulates, and says so."""

import json
import re

import pytest

from cyberrescue.execution.cli import build_parser, main
from cyberrescue.execution.export import BANNER
from tests._execution_factory import plans_of, request
from tests._response_factory import authority_core


@pytest.fixture(scope="module")
def setup(tmp_path_factory):
    d = tmp_path_factory.mktemp("xcli")
    db = authority_core(d / "core.db")
    plans = plans_of(db)
    request(db, plans["INC-C"])
    files = {}
    for ref, plan in plans.items():
        files[ref] = d / f"{ref}.json"
        files[ref].write_text(plan.to_json(), encoding="utf-8")
    return db, plans, files


def run(db, capsys, *argv):
    code = main(["--db", str(db), *argv])
    out, err = capsys.readouterr()
    return code, out, err


def test_simulate_json_and_banner(setup, capsys):
    db, plans, files = setup
    code, out, err = run(db, capsys, "simulate", "--plan", str(files["INC-C"]))
    doc = json.loads(out)
    assert code == 0 and doc["simulation"] is True and BANNER in err
    assert doc["summary"]["SUCCEEDED"] == 4


@pytest.mark.parametrize("fmt", ["md", "html"])
def test_simulate_other_formats_and_out(setup, capsys, tmp_path, fmt):
    db, _, files = setup
    out = tmp_path / f"r.{fmt}"
    code, stdout, err = run(db, capsys, "simulate", "--plan", str(files["INC-A"]),
                            "--format", fmt, "--out", str(out))
    assert code == 0 and stdout == "" and "SIMULATION ONLY" in out.read_text(encoding="utf-8")
    assert sorted(x.name for x in tmp_path.iterdir()) == [out.name]


def test_show_a_step_and_a_decision(setup, capsys):
    db, plans, files = setup
    iso = next(s for s in plans["INC-C"].steps if s.action == "isolate_host")
    code, out, _ = run(db, capsys, "show", "--plan", str(files["INC-C"]), "--id", iso.step_id)
    assert code == 0 and "BLOCKED (authorization)" in out and "P5" in out
    blk = next(s for s in plans["INC-C"].steps if s.action == "block_ip")
    code, out, _ = run(db, capsys, "show", "--plan", str(files["INC-C"]), "--id", blk.step_id)
    assert "SUCCEEDED" in out and "criterion MET" in out and "SIMULATED" in out
    wipe = next(d for d in plans["INC-C"].decision_points if d.action == "wipe_host")
    code, out, _ = run(db, capsys, "show", "--plan", str(files["INC-C"]), "--id",
                       wipe.decision_id, "--json")
    assert json.loads(out)["block_category"] == "legal_hold"
    assert run(db, capsys, "show", "--plan", str(files["INC-C"]), "--id", "STEP-x")[0] == 2


def test_verify_exit_codes(setup, capsys, tmp_path):
    db, _, files = setup
    rep = tmp_path / "rep.json"
    run(db, capsys, "simulate", "--plan", str(files["INC-C"]), "--out", str(rep))
    code, out, _ = run(db, capsys, "verify", "--report", str(rep), "--plan", str(files["INC-C"]))
    assert code == 0 and "VERIFIED" in out
    doc = json.loads(rep.read_text(encoding="utf-8"))
    doc["steps"][1]["reason"] = "approved by the CISO"
    rep.write_text(json.dumps(doc), encoding="utf-8")
    code, out, _ = run(db, capsys, "verify", "--report", str(rep), "--plan", str(files["INC-C"]))
    assert code == 1 and "DOES NOT VERIFY" in out


def test_errors_exit_2(setup, capsys, tmp_path):
    db, _, files = setup
    bad = tmp_path / "bad.json"
    bad.write_text('{"approved": true}', encoding="utf-8")
    assert run(db, capsys, "simulate", "--plan", str(bad))[0] == 2
    missing = tmp_path / "none.db"
    code, _, err = run(missing, capsys, "simulate", "--plan", str(files["INC-A"]))
    assert code == 2 and not missing.exists() and BANNER in err


def test_the_cli_can_only_simulate():
    ap = build_parser()
    sub = next(a for a in ap._actions if a.dest == "cmd")
    assert set(sub.choices) == {"simulate", "show", "verify"}
    flags = {o for a in ap._actions for o in a.option_strings}
    flags |= {o for x in sub.choices.values() for a in x._actions for o in a.option_strings}
    names = set(sub.choices) | flags
    for word in ("execute", "exec", "run-real", "live", "approve", "authorize", "request",
                 "submit", "persist", "force"):
        assert not [n for n in names if word in n], word


def test_terminal_output_is_control_free(setup, capsys):
    db, plans, files = setup
    for s in plans["INC-C"].steps:
        _, out, _ = run(db, capsys, "show", "--plan", str(files["INC-C"]), "--id", s.step_id)
        assert out.isascii() and not re.search(r"[\x00-\x08\x0b-\x1f\x7f]", out)
