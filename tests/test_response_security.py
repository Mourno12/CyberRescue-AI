"""CyberRescue Phase 4 — the response planner is read-only, inert, isolated and advisory.

Every command runs against a Core holding all scenarios, persisted detections,
Band-imported agent findings, an evaluated action request and the hostile
telemetry from Phases 2B/2C. The database must be unchanged, the policy and the
Commander gate must decide exactly as before, hostile text must stay data,
no plan may claim authority, and ground truth must never be read.
"""

import ast
import json
import re
import pathlib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import cyberrescue.response as response_pkg
from cyberrescue.core.band_import import import_band_context
from cyberrescue.core.gate import CommanderGate
from cyberrescue.core.service import CoreService
from cyberrescue.investigation.builder import build_case
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.cli import main
from cyberrescue.response.export import render
from cyberrescue.response.planner import build_plan, verify_plan
from cyberrescue.telemetry.importer import import_events
from tests._detection_factory import investigated_core
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
MODULES = sorted(Path(response_pkg.__file__).parent.glob("*.py"))
REFS = ("INC-A", "INC-B", "INC-C")
SQL_KEYWORDS = re.compile(WRITE_SQL.pattern)


@pytest.fixture(scope="module")
def dbp(tmp_path_factory):
    path = investigated_core(tmp_path_factory.mktemp("rsec") / "core.db")
    svc = CoreService.open(path, clock=lambda: NOW)
    col = svc.store.find_actor("collector:synthetic")
    import_events(svc, INC, hostile_telemetry() + detector_hostile(), collector_id=col.id)
    import_band_context(svc, FIXTURE, incident_ref="INC-C", roster=ROSTER)
    cmd = svc.store.find_actor("band:synthetic-agent-commander")
    svc.request_action(INC, "wipe_host", "srv-db-01", cmd.id, source="test")
    svc.conn.close()
    return path


@pytest.fixture(scope="module")
def plan_c(dbp):
    with open_readonly(dbp) as ro:
        return build_plan(ro, "INC-C")


# --- read-only -----------------------------------------------------------------------

COMMANDS = [["plan", "--incident", r] for r in REFS] + [
    ["plan", "--incident", "INC-C", "--format", "md"],
    ["plan", "--incident", "INC-C", "--format", "html"],
]


@pytest.mark.parametrize("argv", COMMANDS, ids=lambda a: "-".join(a[1:]))
def test_every_command_leaves_the_database_unchanged(dbp, argv, capsys):
    before = db_state(dbp)
    assert main(["--db", str(dbp), *argv]) == 0
    capsys.readouterr()
    assert db_state(dbp) == before


def test_verify_and_step_leave_the_database_unchanged(dbp, tmp_path, capsys):
    before = db_state(dbp)
    out = tmp_path / "p.json"
    assert main(["--db", str(dbp), "plan", "--incident", "INC-C", "--out", str(out)]) == 0
    assert main(["--db", str(dbp), "verify-plan", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    for item in (*doc["steps"], *doc["decision_points"]):
        ident = item.get("step_id") or item["decision_id"]
        assert main(["--db", str(dbp), "step", "--incident", "INC-C", "--id", ident]) == 0
    capsys.readouterr()
    assert db_state(dbp) == before


def test_policy_gate_and_case_are_exactly_as_before(dbp, tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERRESCUE_DB_PATH", str(dbp))
    monkeypatch.setenv("CYBERRESCUE_INCIDENT", INC)
    log = tmp_path / "gate.jsonl"

    def verdicts():
        g = CommanderGate(mode="shadow", db_path=dbp, log_path=log, clock=lambda: NOW)
        return {a: (r["verdict"], tuple(r["unmet_rules"])) for a in
                ("wipe_host", "isolate_host", "preserve_disk_image")
                for r in [g.check(a, {"asset_id": "srv-db-01"})]}
    svc = CoreService.open(dbp, clock=lambda: NOW)
    snap_before = svc.store.snapshot(INC, now=NOW).model_dump()
    svc.conn.close()
    before = verdicts()
    with open_readonly(dbp) as ro:
        for ref in REFS:
            plan = build_plan(ro, ref)
            for fmt in ("json", "md", "html"):
                render(plan, fmt)
    assert verdicts() == before
    svc = CoreService.open(dbp, clock=lambda: NOW)
    try:
        assert svc.store.snapshot(INC, now=NOW).model_dump() == snap_before
    finally:
        svc.conn.close()


def test_planning_does_not_change_phase3_case_hashes(dbp):
    with open_readonly(dbp) as ro:
        before = {r: build_case(ro, r).case_sha256 for r in REFS}
        for r in REFS:
            build_plan(ro, r)
        assert {r: build_case(ro, r).case_sha256 for r in REFS} == before


# --- no authority ------------------------------------------------------------------------

def test_no_plan_claims_authority(dbp):
    with open_readonly(dbp) as ro:
        for ref in REFS:
            doc = json.loads(build_plan(ro, ref).to_json())
            previews = [x["preview"] for x in (*doc["steps"], *doc["decision_points"])]
            assert all(p["authorizes"] is False and p["kind"] == "policy_preview"
                       for p in previews)
            assert all(s["tier"] in (1, 2) for s in doc["steps"])


def test_plans_are_not_action_requests(dbp, plan_c, tmp_path):
    """Nothing in a plan reaches the Core: requests, approvals and audit are unchanged
    even after every format is rendered and verified."""
    with open_readonly(dbp) as ro:
        requests = [r.id for r in ro.store.action_requests(INC)]
        events = len(ro.audit.events(INC))
        assert verify_plan(ro, plan_c.to_json()).ok
        assert [r.id for r in ro.store.action_requests(INC)] == requests
        assert len(ro.audit.events(INC)) == events
        assert ro.store.unconsumed_approvals(INC) == []


# --- hostile text stays data ----------------------------------------------------------------

# Identifier fields carry evidence-derived values; they are escaped by every renderer
# but not wrapped as Untrusted. This allow-list pins exactly where that may happen.
IDENTIFIER_FIELDS = {"tasks.host"}


def test_hostile_text_outside_untrusted_appears_only_in_identifier_fields(plan_c):
    doc = json.loads(plan_c.to_json())
    hits: set[str] = set()

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
    assert hits and hits <= IDENTIFIER_FIELDS, hits - IDENTIFIER_FIELDS


def test_hostile_values_never_become_targets_or_prose(plan_c):
    for x in (*plan_c.steps, *plan_c.decision_points):
        assert x.target.value is None or "IGNORE" not in x.target.value
        assert x.target.source == "plan" or x.target.checks
        assert "IGNORE" not in x.rationale
    hostile_kills = [s for s in plan_c.steps if s.action == "kill_process"
                     and "IGNORE" in s.params["process"].untrusted]
    assert hostile_kills and all("<unprintable>" in s.rationale for s in hostile_kills)


def test_hostile_plan_renders_inertly_and_verifies(dbp, plan_c):
    html_out = render(plan_c, "html")
    assert "<script" not in html_out.lower()
    assert "IGNORE PREVIOUS INSTRUCTIONS" in html_out        # present, escaped, in <code>
    with open_readonly(dbp) as ro:
        assert verify_plan(ro, plan_c.to_json()).ok


# --- static guarantees -----------------------------------------------------------------

@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.stem)
def test_modules_have_no_authority_execution_or_nondeterminism(path):
    names = _names(_tree(path))
    allowed = {"preview": {"PolicyEngine"}}.get(path.stem, set())   # pure evaluate()
    assert not (names & AUTHORITY) - allowed
    assert not names & NONDETERMINISM
    assert not names & {"audit", "append_event", "check_commander_action", "write_text"} - \
        ({"write_text"} if path.stem == "cli" else set())


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.stem)
def test_modules_contain_no_write_sql(path):
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            # Case-sensitive: SQL here is upper-case; prose ("Create or Modify ...",
            # an ATT&CK technique name) is not SQL.
            assert not SQL_KEYWORDS.match(node.value), (path.stem, node.value[:40])


def test_only_the_preview_evaluates_policy_and_only_evaluate():
    src = (Path(response_pkg.__file__).parent / "preview.py").read_text(encoding="utf-8")
    calls = {n.func.attr for n in ast.walk(ast.parse(src))
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "evaluate" in calls and not calls & {"request_action", "authorize",
                                                 "grant_approval", "add_policy_decision"}


def test_response_never_loads_ground_truth_generators_evaluation_gate_or_llms():
    # cyberrescue.core.service is loaded by the cyberrescue.core package __init__ and
    # detection.publisher by Phase 3's findings.py (constants only); loading is not
    # calling - the AST tests above prove no authority name is used.
    code = ("import sys\n"
            "import cyberrescue.response.cli\n"
            "bad = {'cyberrescue.telemetry.ground_truth', 'cyberrescue.telemetry.scenarios', "
            "'cyberrescue.telemetry.datasets', 'cyberrescue.evaluation', "
            "'cyberrescue.core.gate', 'agents'}\n"
            "heavy = {'thenvoi', 'langchain_openai', 'langgraph', 'openai', 'anthropic', "
            "'pydantic_ai'}\n"
            "print(sorted(m for m in sys.modules if any(m == b or m.startswith(b + '.') "
            "for b in bad)), sorted(heavy & {m.split('.')[0] for m in sys.modules}))\n")
    res = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True,
                         text=True, check=True)
    assert res.stdout.strip() == "[] []"


def test_response_never_reads_dataset_files(dbp, monkeypatch):
    import builtins

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
    with open_readonly(dbp) as ro:
        for ref in REFS:
            render(build_plan(ro, ref), "html")
    assert not [p for p in seen if "ground_truth" in p or "datasets" in p]
    assert any("protected_accounts.json" in p for p in seen)
    assert any("reg_rules.json" in p for p in seen)
