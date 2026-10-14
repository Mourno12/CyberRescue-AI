"""CyberRescue Phase 4 — the response CLI is read-only and can only advise."""

import json
import re

import pytest

from cyberrescue.response.cli import build_parser, main
from tests._response_factory import authority_core


@pytest.fixture(scope="module")
def dbp(tmp_path_factory):
    return authority_core(tmp_path_factory.mktemp("rcli") / "core.db")


def run(dbp, capsys, *argv):
    code = main(["--db", str(dbp), *argv])
    out, err = capsys.readouterr()
    return code, out, err


def plan_json(dbp, capsys, ref="INC-C"):
    code, out, _ = run(dbp, capsys, "plan", "--incident", ref)
    assert code == 0
    return json.loads(out)


def test_plan_json_to_stdout(dbp, capsys):
    doc = plan_json(dbp, capsys)
    assert doc["plan_schema"] == "cyberrescue.response-plan/1"
    assert doc["incident_id"] == "INC-C-2026-0042" and doc["steps"]


@pytest.mark.parametrize("fmt,marker", [("md", "# Response plan"), ("html", "<!DOCTYPE html>")])
def test_plan_other_formats(dbp, capsys, fmt, marker):
    code, out, _ = run(dbp, capsys, "plan", "--incident", "INC-A", "--format", fmt)
    assert code == 0 and out.startswith(marker) and "advisory" in out


def test_plan_out_writes_only_that_file(dbp, capsys, tmp_path):
    out = tmp_path / "plan.json"
    code, stdout, err = run(dbp, capsys, "plan", "--incident", "INC-C", "--out", str(out))
    assert code == 0 and stdout == "" and "nothing was requested or authorized" in err
    assert json.loads(out.read_text(encoding="utf-8"))["plan_sha256"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["plan.json"]


def test_verify_plan_exit_codes(dbp, capsys, tmp_path):
    out = tmp_path / "plan.json"
    run(dbp, capsys, "plan", "--incident", "INC-C", "--out", str(out))
    code, text, _ = run(dbp, capsys, "verify-plan", str(out))
    assert code == 0 and "VERIFIED" in text
    doc = json.loads(out.read_text(encoding="utf-8"))
    doc["decision_points"][0]["preview"]["outcome_if_requested"] = "ALLOW"
    out.write_text(json.dumps(doc), encoding="utf-8")
    code, text, _ = run(dbp, capsys, "verify-plan", str(out))
    assert code == 1 and "DOES NOT VERIFY" in text and "edited export" in text


def test_step_explains_a_step_and_a_decision(dbp, capsys):
    doc = plan_json(dbp, capsys)
    sid = next(s["step_id"] for s in doc["steps"] if s["action"] == "isolate_host")
    code, out, _ = run(dbp, capsys, "step", "--incident", "INC-C", "--id", sid)
    assert code == 0 and "preview: REQUIRE_APPROVAL [P5]" in out
    assert "nothing was requested or authorized" in out
    did = next(d["decision_id"] for d in doc["decision_points"] if d["action"] == "wipe_host")
    code, out, _ = run(dbp, capsys, "step", "--incident", "INC-C", "--id", did)
    assert code == 0 and "a human decides" in out and "P8" in out and "more (use --json)" in out
    code, out, _ = run(dbp, capsys, "step", "--incident", "INC-C", "--id", did, "--json")
    assert json.loads(out)["decision_id"] == did


def test_errors_exit_2(dbp, capsys, tmp_path):
    assert run(dbp, capsys, "step", "--incident", "INC-C", "--id", "STEP-nope")[0] == 2
    assert run(dbp, capsys, "plan", "--incident", "INC-Z")[0] == 2
    missing = tmp_path / "missing.db"
    code, _, err = run(missing, capsys, "plan", "--incident", "INC-C")
    assert code == 2 and "no Core database" in err and not missing.exists()
    assert run(dbp, capsys, "verify-plan", str(tmp_path / "none.json"))[0] == 2


def test_custom_protected_accounts_turn_a_step_into_a_decision(dbp, capsys, tmp_path):
    lst = tmp_path / "protected.json"
    lst.write_text(json.dumps({"schema": "cyberrescue.protected-accounts/1",
                               "accounts": ["svc_sqlbackup"]}), encoding="utf-8")
    code, out, _ = run(dbp, capsys, "--protected-accounts", str(lst), "plan",
                       "--incident", "INC-C")
    doc = json.loads(out)
    assert code == 0
    assert not [s for s in doc["steps"] if s["action"] == "disable_account"]
    assert [d["target"]["value"] for d in doc["decision_points"]
            if d["reason_code"] == "protected_target"] == ["svc_sqlbackup"]


def test_the_cli_offers_no_way_to_act():
    ap = build_parser()
    sub = next(a for a in ap._actions if a.dest == "cmd")
    assert set(sub.choices) == {"plan", "verify-plan", "step"}
    flags = {o for a in ap._actions for o in a.option_strings}
    flags |= {o for p in sub.choices.values() for a in p._actions for o in a.option_strings}
    for word in ("submit", "persist", "request", "approve", "execute", "authorize"):
        assert not [f for f in flags if word in f]


def test_terminal_output_is_control_free(dbp, capsys):
    doc = plan_json(dbp, capsys)
    for s in doc["steps"]:
        _, out, _ = run(dbp, capsys, "step", "--incident", "INC-C", "--id", s["step_id"])
        assert out.isascii() and not re.search(r"[\x00-\x08\x0b-\x1f\x7f]", out)
