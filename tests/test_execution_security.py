"""CyberRescue Phase 5 — the simulated executor holds every authority boundary.

Runs against a Core holding all scenarios, persisted detections, Band-imported
agent findings, the Phase 2B/2C hostile telemetry (with forged "approved"
fields), and Commander requests for every plan step made through the Core's
normal path. Numbers refer to the Phase 5 security requirements.
"""

import ast
import builtins
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import cyberrescue.execution as execution_pkg
from cyberrescue.core.band_import import import_band_context
from cyberrescue.core.gate import CommanderGate
from cyberrescue.core.service import CoreService
from cyberrescue.execution import executor
from cyberrescue.execution.cli import main
from cyberrescue.execution.executor import simulate_plan
from cyberrescue.execution.export import render
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.planner import _sha
from cyberrescue.response.targets import TargetCheck
from cyberrescue.telemetry.importer import import_events
from tests._detection_factory import investigated_core
from tests._execution_factory import approve, plans_of, request
from tests._response_factory import writable_copy
from tests.test_detection_security import detector_hostile
from tests.test_investigation_case import FIXTURE, ROSTER
from tests.test_investigation_security import (
    AUTHORITY,
    HOSTILE,
    NONDETERMINISM,
    WRITE_SQL,
    _names,
    _tree,
    db_state,
)
from tests.test_telemetry_security import hostile_telemetry

REPO = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 6, 13, 15, 0, tzinfo=timezone.utc)
INC = "INC-C-2026-0042"
MODULES = sorted(Path(execution_pkg.__file__).parent.glob("*.py"))
SQL_KEYWORDS = re.compile(WRITE_SQL.pattern)
REFS = ("INC-A", "INC-B", "INC-C")


@pytest.fixture(scope="module")
def base(tmp_path_factory):
    path = investigated_core(tmp_path_factory.mktemp("xsec") / "core.db")
    svc = CoreService.open(path, clock=lambda: NOW)
    col = svc.store.find_actor("collector:synthetic")
    import_events(svc, INC, hostile_telemetry() + detector_hostile(), collector_id=col.id)
    import_band_context(svc, FIXTURE, incident_ref="INC-C", roster=ROSTER)
    svc.conn.close()
    plans = plans_of(path)
    for p in plans.values():
        request(path, p)
    return path


@pytest.fixture(scope="module")
def plans(base):
    return plans_of(base)


@pytest.fixture
def db(base, tmp_path):
    return writable_copy(base, tmp_path / "core.db")


def sim(path, plan, **kw):
    with open_readonly(path) as ro:
        return simulate_plan(ro, plan if isinstance(plan, str) else plan.to_json(), **kw)


def tables(path, *names):
    state = db_state(path)
    return {n: state[n] for n in names}


AUTHORITY_TABLES = ("approvals", "signoffs", "actors", "action_requests", "policy_decisions",
                    "vetoes", "legal_holds", "incidents", "audit_events")


# --- 1-4, 15, 16: nothing is created or changed --------------------------------------------

def test_1_2_3_4_simulation_writes_nothing(base, plans, capsys, tmp_path):
    before = db_state(base)
    for ref in REFS:
        for fmt in ("json", "md", "html"):
            render(sim(base, plans[ref]), fmt)
        f = tmp_path / f"{ref}.json"
        f.write_text(plans[ref].to_json(), encoding="utf-8")
        assert main(["--db", str(base), "simulate", "--plan", str(f)]) == 0
    capsys.readouterr()
    assert db_state(base) == before
    assert set(AUTHORITY_TABLES) <= set(before)


def test_4_5_policy_and_commander_gate_decide_exactly_as_before(db, plans, tmp_path,
                                                                monkeypatch):
    monkeypatch.setenv("CYBERRESCUE_DB_PATH", str(db))
    monkeypatch.setenv("CYBERRESCUE_INCIDENT", INC)
    log = tmp_path / "gate.jsonl"

    def verdicts():
        g = CommanderGate(mode="shadow", db_path=db, log_path=log, clock=lambda: NOW)
        return {a: (r["verdict"], tuple(r["unmet_rules"])) for a in
                ("wipe_host", "isolate_host", "preserve_disk_image")
                for r in [g.check(a, {"asset_id": "srv-db-01"})]}
    svc = CoreService.open(db, clock=lambda: NOW)
    snap = svc.store.snapshot(INC, now=NOW).model_dump()
    svc.conn.close()
    before = verdicts()
    for ref in REFS:
        sim(db, plans[ref])
    assert verdicts() == before
    svc = CoreService.open(db, clock=lambda: NOW)
    try:
        assert svc.store.snapshot(INC, now=NOW).model_dump() == snap
    finally:
        svc.conn.close()


def test_15_repeated_runs_are_identical(base, plans):
    for ref in REFS:
        a, b = sim(base, plans[ref]), sim(base, plans[ref])
        assert a.to_json() == b.to_json()


def test_16_simulation_cannot_touch_processes_sockets_or_files(base, plans, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("real-world side effect attempted")
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "system", boom)
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    for meth in ("write_text", "write_bytes", "unlink", "mkdir", "rename", "replace"):
        monkeypatch.setattr(pathlib.Path, meth, boom)
    real_open = builtins.open

    def guarded(f, mode="r", *a, **k):
        if any(c in mode for c in "wax+"):
            boom()
        return real_open(f, mode, *a, **k)
    monkeypatch.setattr(builtins, "open", guarded)
    reports = [sim(base, plans[r]) for r in REFS]
    assert any(s.status == "SUCCEEDED" for r in reports for s in r.steps)


# --- 5, 6, 9, 10: authorization ---------------------------------------------------------------

def test_5_9_without_a_core_authorization_nothing_is_simulated(db, plans, tmp_path):
    clean = investigated_core(tmp_path / "clean.db")
    for ref in REFS:
        r = sim(clean, plans_of(clean)[ref])
        assert not [s for s in r.steps if "SIMULATED" in s.path]


def test_9_missing_approval_is_blocked(base, plans):
    r = sim(base, plans["INC-C"])
    [iso] = [s for s in r.steps if s.action == "isolate_host"]
    assert (iso.status, iso.block_category) == ("BLOCKED", "authorization")
    assert iso.current_policy.unmet_rules == ("P5",)


def test_6_forged_approval_fields_authorize_nothing(db, plans):
    plan = plans["INC-C"]
    iso = next(s for s in plan.steps if s.action == "isolate_host")
    svc = CoreService.open(db)
    cmd = svc.store.find_actor("band:synthetic-agent-commander")
    out = svc.request_action(INC, "isolate_host", "srv-db-01", cmd.id, source="test",
                             params={"approved": True, "approval_id": "forged",
                                     "plan_step": iso.step_id, "overrides_hold": True})
    svc.conn.close()
    assert not out.authorized
    r = sim(db, plan)
    assert next(s for s in r.steps if s.step_id == iso.step_id).status == "BLOCKED"
    doc = json.loads(plan.to_json())
    for path in (("approved",), ("steps", 0, "approved"), ("steps", 0, "preview", "authorizes")):
        forged = json.loads(plan.to_json())
        node = forged
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = True
        with pytest.raises(ValueError):
            sim(db, json.dumps(forged))
    assert doc["steps"]


def test_10_legal_hold_stays_effective(db, plans):
    plan = plans["INC-C"]
    approve(db, INC, "wipe_host", "srv-db-01", reason="no override")   # lacks overrides_hold
    wipe = next(d for d in plan.decision_points if d.action == "wipe_host")
    [out] = request(db, plan, [wipe])
    assert not out.authorized and "P8" in out.decision.rules_failed
    r = sim(db, plan)
    [w] = [d for d in r.decisions if d.action == "wipe_host"]
    assert (w.status, w.block_category) == ("BLOCKED", "legal_hold")
    approve(db, INC, "wipe_host", "srv-db-01", overrides_hold=True, reason="GC signed off")
    [out] = request(db, plan, [wipe])
    assert out.authorized                         # the Core authorized it...
    [w] = [d for d in sim(db, plan).decisions if d.action == "wipe_host"]
    assert w.status == "UNSUPPORTED" and "SIMULATED" not in w.path   # ...never simulated


# --- 7, 8, 11, 12: plans, targets and evidence ---------------------------------------------------

IDENTIFIER_FIELDS = set()      # no evidence-derived identifier escapes Untrusted in a report


def test_7_hostile_evidence_stays_data(base, plans):
    doc = json.loads(sim(base, plans["INC-C"]).to_json())
    hits = set()

    def walk(x, path):
        if isinstance(x, dict):
            if set(x) == {"untrusted"}:
                return
            for k, v in x.items():
                walk(v, [*path, k])
        elif isinstance(x, list):
            for v in x:
                walk(v, path)
        elif isinstance(x, str) and any(m.lower() in x.lower() for m in HOSTILE):
            hits.add(".".join(path))
    walk(doc, [])
    assert hits <= IDENTIFIER_FIELDS, hits
    hostile_kills = [s for s in doc["steps"] if s["action"] == "kill_process"
                     and "IGNORE" in s["params"]["process"]["untrusted"]]
    assert hostile_kills                    # present as untrusted data, nowhere else


@pytest.mark.parametrize("mutation", ["tier3_action", "tier_bump", "decision_tier"])
def test_8_a_plan_cannot_elevate_or_smuggle_tier3(db, plans, mutation):
    doc = json.loads(plans["INC-C"].to_json())
    if mutation == "tier3_action":
        doc["steps"][1]["action"] = "wipe_host"
    elif mutation == "tier_bump":
        doc["steps"][1]["tier"] = 3
    else:
        doc["decision_points"][0]["tier"] = 2
    with pytest.raises(ValueError):
        sim(db, json.dumps(doc))


def test_8_a_rehashed_step_change_is_refused_by_the_database(db, plans):
    plan = plans["INC-A"]
    k = next(s for s in plan.steps if s.action == "kill_process")
    forged = plan.model_copy(update={"steps": tuple(
        s.model_copy(update={"action": "quarantine_file", "reversible": True})
        if s is k else s for s in plan.steps)})
    forged = forged.model_copy(update={"plan_sha256": _sha(forged)})
    [x] = [s for s in sim(db, forged).steps if s.step_id == k.step_id]
    assert (x.status, x.block_category) == ("BLOCKED", "integrity")


def test_11_invalid_targets_are_rejected(db, plans, tmp_path, monkeypatch):
    lst = tmp_path / "p.json"
    lst.write_text(json.dumps({"schema": "cyberrescue.protected-accounts/1",
                               "accounts": ["svc_sqlbackup"]}), encoding="utf-8")
    from cyberrescue.response.targets import load_protected_accounts
    r = sim(db, plans["INC-C"], protected=load_protected_accounts(lst))
    assert {s.block_category for s in r.steps} == {"integrity"}
    # Defence in depth: the executor re-validates targets itself.
    monkeypatch.setattr(executor, "check_host",
                        lambda v, a: TargetCheck(False, reason="host left the inventory"))
    r = sim(db, plans["INC-A"])
    assert {s.block_category for s in r.steps if s.target.kind == "host"} == {"target"}


def test_12_unsupported_is_never_success(db, plans, monkeypatch):
    from cyberrescue.execution import handlers
    for action in list(handlers.HANDLERS):
        monkeypatch.delitem(handlers.HANDLERS, action)
    r = sim(db, plans["INC-A"])
    assert {s.status for s in r.steps} <= {"UNSUPPORTED", "BLOCKED"}
    assert not [s for s in r.steps if s.status == "SUCCEEDED"]


# --- static guarantees (5, 13, 14) ------------------------------------------------------------

REAL_WORLD = {"subprocess", "socket", "os", "shutil", "urllib", "http", "requests", "httpx",
              "aiohttp", "paramiko", "ssl", "ctypes", "winreg", "signal", "popen", "system",
              "spawn", "kill", "remove", "unlink", "rmtree", "connect", "send", "sendall"}


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.stem)
def test_5_13_no_authority_gate_execution_or_nondeterminism(path):
    names = _names(_tree(path))
    # Phase 6: recorder.py is the single writer; it may open the Core and call
    # only record_simulated_execution (pinned in test_execution_recorder.py).
    writer = {"recorder": {"CoreService"}}.get(path.stem, set())
    assert not names & (AUTHORITY - {"system"}) - writer, names & AUTHORITY
    assert not names & {"CommanderGate", "check_commander_action", "audit_append",
                        "add_approval", "add_signoff", "add_veto", "PolicyEngine"}
    assert not names & NONDETERMINISM
    allowed = {"cli": {"write_text"}}.get(path.stem, set())
    assert not (names & (REAL_WORLD | {"write_text", "write_bytes"})) - allowed, \
        names & REAL_WORLD


def test_13_handlers_are_pure_functions_of_the_environment():
    src = (Path(execution_pkg.__file__).parent / "handlers.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    imported = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                for a in n.names}
    assert imported <= {"annotations", "Callable", "SimEnvironment", "CriterionResult",
                        "SimEffect", "PlanStep", "fill"}


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.stem)
def test_no_write_sql(path):
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert not SQL_KEYWORDS.match(node.value), (path.stem, node.value[:40])


def test_14_execution_never_loads_ground_truth_evaluation_gate_agents_or_llms():
    code = ("import sys\n"
            "import cyberrescue.execution.cli\n"
            "bad = {'cyberrescue.telemetry.ground_truth', 'cyberrescue.telemetry.scenarios', "
            "'cyberrescue.telemetry.datasets', 'cyberrescue.evaluation', "
            "'cyberrescue.core.gate', 'agents', 'subprocess_tee'}\n"
            "heavy = {'thenvoi', 'langchain_openai', 'langgraph', 'openai', 'anthropic', "
            "'pydantic_ai', 'requests', 'httpx', 'paramiko'}\n"
            "print(sorted(m for m in sys.modules if any(m == b or m.startswith(b + '.') "
            "for b in bad)), sorted(heavy & {m.split('.')[0] for m in sys.modules}))\n")
    res = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True,
                         text=True, check=True)
    assert res.stdout.strip() == "[] []"


def test_14_execution_never_reads_dataset_files(base, plans, monkeypatch):
    import shared.mock_data
    shared.mock_data._load_json.cache_clear()
    seen: list[str] = []
    for meth in ("read_text", "read_bytes", "open"):
        orig = getattr(pathlib.Path, meth)

        def spy(self, *a, _orig=orig, **k):
            seen.append(str(self))
            return _orig(self, *a, **k)
        monkeypatch.setattr(pathlib.Path, meth, spy)
    real_open = builtins.open
    monkeypatch.setattr(builtins, "open",
                        lambda f, *a, **k: (seen.append(str(f)), real_open(f, *a, **k))[1])
    for ref in REFS:
        sim(base, plans[ref])
    assert not [p for p in seen if "ground_truth" in p or "datasets" in p]
