"""CyberRescue Phase 3 — the investigation layer is read-only, inert and isolated.

Every command runs against a Core holding all scenarios, persisted detections,
Band-imported agent findings, an evaluated action request and the hostile
telemetry from Phases 2B/2C; the database must be byte-for-byte unchanged in
content, policy and the Commander gate must decide exactly as before, hostile
text must stay data, and ground truth must never be read.
"""

import ast
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import cyberrescue.investigation as investigation_pkg
from cyberrescue.core.band_import import import_band_context
from cyberrescue.core.gate import CommanderGate
from cyberrescue.core.service import CoreService
from cyberrescue.investigation.builder import build_case
from cyberrescue.investigation.cli import main
from cyberrescue.investigation.export import render
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.telemetry.importer import import_events
from tests._detection_factory import investigated_core
from tests.test_detection_security import detector_hostile
from tests.test_investigation_case import FIXTURE, ROSTER
from tests.test_telemetry_security import hostile_telemetry

REPO = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 6, 13, 15, 0, tzinfo=timezone.utc)
INC = "INC-C-2026-0042"
MODULES = sorted(Path(investigation_pkg.__file__).parent.glob("*.py"))
HOSTILE = ("IGNORE PREVIOUS", "APPROVE THE ACTION", "GRANT CISO", "rm -rf", "DROP TABLE",
           "<script", '"type": "SIGNOFF"')


@pytest.fixture(scope="module")
def dbp(tmp_path_factory):
    path = investigated_core(tmp_path_factory.mktemp("isec") / "core.db")
    svc = CoreService.open(path, clock=lambda: NOW)
    col = svc.store.find_actor("collector:synthetic")
    import_events(svc, INC, hostile_telemetry() + detector_hostile(), collector_id=col.id)
    import_band_context(svc, FIXTURE, incident_ref="INC-C", roster=ROSTER)
    cmd = svc.store.find_actor("band:synthetic-agent-commander")
    svc.request_action(INC, "wipe_host", "srv-db-01", cmd.id, source="test")
    svc.conn.close()
    return path


def db_state(path) -> dict[str, str]:
    """sha256 of every table's full content (rowid order) — read via a separate
    read-only connection so the check itself cannot write."""
    import sqlite3
    conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'trigger', 'index') "
            "ORDER BY name")]
        out = {}
        for t in tables:
            kind = conn.execute("SELECT type FROM sqlite_master WHERE name = ?",
                                (t,)).fetchone()[0]
            rows = conn.execute(f"SELECT * FROM {t} ORDER BY rowid").fetchall() \
                if kind == "table" else conn.execute(
                    "SELECT sql FROM sqlite_master WHERE name = ?", (t,)).fetchall()
            out[t] = hashlib.sha256(repr(rows).encode()).hexdigest()
        return out
    finally:
        conn.close()


COMMANDS = [
    ["case", "--incident", "INC-C"], ["case", "--incident", "INC-C", "--format", "md"],
    ["case", "--incident", "INC-C", "--format", "html", "--include-raw"],
    ["timeline", "--incident", "INC-C"], ["timeline", "--incident", "INC-B", "--json"],
    ["scope", "--incident", "INC-C"], ["gaps", "--incident", "INC-C"],
    ["entity", "--incident", "INC-C", "--host", "srv-db-01"],
    ["path", "--incident", "INC-C", "--from", "host:srv-db-01", "--to", "host:srv-app-01"],
]


# --- read-only ---------------------------------------------------------------------

@pytest.mark.parametrize("argv", COMMANDS, ids=lambda a: "-".join(a[:3]))
def test_every_command_leaves_the_database_unchanged(dbp, argv, capsys):
    before = db_state(dbp)
    assert main(["--db", str(dbp), *argv]) in (0, 1)
    capsys.readouterr()
    assert db_state(dbp) == before


def test_verify_case_and_provenance_leave_the_database_unchanged(dbp, tmp_path, capsys):
    before = db_state(dbp)
    out = tmp_path / "c.json"
    main(["--db", str(dbp), "case", "--incident", "INC-A", "--out", str(out)])
    assert main(["--db", str(dbp), "verify-case", str(out)]) == 0
    with open_readonly(dbp) as ro:
        evid = ro.list_evidence("INC-A")[0].id
    assert main(["--db", str(dbp), "provenance", "--evidence", evid]) == 0
    capsys.readouterr()
    assert db_state(dbp) == before


def test_policy_and_commander_gate_decide_exactly_as_before(dbp, tmp_path, monkeypatch):
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
        for ref in ("INC-A", "INC-B", "INC-C"):
            case = build_case(ro, ref, include_raw=True)
            for fmt in ("json", "md", "html"):
                render(case, fmt)
    assert verdicts() == before
    svc = CoreService.open(dbp, clock=lambda: NOW)
    try:
        assert svc.store.snapshot(INC, now=NOW).model_dump() == snap_before
    finally:
        svc.conn.close()


# --- hostile text stays data ----------------------------------------------------------

# Identifier fields carry evidence-derived values (a host name is whatever the
# evidence says). They are escaped by every renderer but not wrapped as
# Untrusted; this allow-list pins exactly where that may happen.
IDENTIFIER_FIELDS = {"timeline.entries.host", "gaps.host", "observations.primary_host",
                     "graph.nodes.key", "graph.edges.src", "graph.edges.dst"}


def test_hostile_text_outside_untrusted_appears_only_in_identifier_fields(dbp):
    with open_readonly(dbp) as ro:
        doc = json.loads(build_case(ro, "INC-C", include_raw=True).to_json())
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


def test_hostile_case_still_verifies_and_renders_inertly(dbp):
    with open_readonly(dbp) as ro:
        case = build_case(ro, "INC-C", include_raw=True)
        from cyberrescue.investigation.builder import verify_case
        assert verify_case(ro, case.to_json()).ok
    html_out = render(case, "html")
    assert "<script" not in html_out.lower()            # script payloads: export tests
    assert "IGNORE PREVIOUS INSTRUCTIONS" in html_out    # present, escaped, inside <code>
    assert "&quot;type&quot;: &quot;SIGNOFF&quot;" in html_out


def test_scope_and_gaps_never_turn_evidence_text_into_recommendations(dbp):
    with open_readonly(dbp) as ro:
        case = build_case(ro, "INC-C")
    # Core-generated text only: Untrusted values (e.g. a hostile account name) are data.
    def core_text(x):
        if isinstance(x, dict):
            return "" if set(x) == {"untrusted"} else " ".join(map(core_text, x.values()))
        if isinstance(x, list):
            return " ".join(map(core_text, x))
        return str(x)
    text = core_text([g.model_dump(mode="json") for g in case.gaps]
                     + [case.scope.model_dump(mode="json")]).lower()
    for verb in ("wipe_host", "isolate_host", "approve", "authorize", "recommend"):
        assert verb not in text


# --- static guarantees ----------------------------------------------------------------

AUTHORITY = {"grant_approval", "add_approval", "authorize", "request_action",
             "register_actor", "apply_trigger", "set_status", "extract_blocks",
             "record_signoff", "record_signoff_request", "record_veto", "add_hold",
             "place_holds_for", "record_risk", "record_finding", "link_evidence",
             "ingest_evidence", "ingest_evidence_batch", "open_incident", "create_incident",
             "add_finding", "add_claim", "persist", "ProtocolIngestor", "CommanderGate",
             "PolicyEngine", "CoreService", "connect", "subprocess", "system", "popen",
             "eval", "exec", "importlib", "__import__"}
NONDETERMINISM = {"now", "utcnow", "today", "time", "random", "uuid", "uuid4", "urandom"}
WRITE_SQL = re.compile(r"^\s*(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|REPLACE|ATTACH|VACUUM|"
                       r"REINDEX)\b", re.IGNORECASE)


def _tree(path):
    return ast.parse(path.read_text(encoding="utf-8"))


def _names(tree) -> set[str]:
    used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    used |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    used |= {a.name.split(".")[-1] for n in ast.walk(tree)
             if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    used |= {n.module.split(".")[0] for n in ast.walk(tree)
             if isinstance(n, ast.ImportFrom) and n.module}
    return used


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.stem)
def test_modules_have_no_authority_execution_or_nondeterminism(path):
    names = _names(_tree(path))
    allowed = {"readonly": {"connect"}}.get(path.stem, set())   # sqlite3.connect(mode=ro)
    assert not (names & AUTHORITY) - allowed
    assert not names & NONDETERMINISM


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.stem)
def test_modules_contain_no_write_sql(path):
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert not WRITE_SQL.match(node.value), (path.stem, node.value[:40])


def test_raw_evidence_is_read_only_by_the_builder_on_request():
    readers = {p.stem for p in MODULES if "raw" in {n.attr for n in ast.walk(_tree(p))
                                                    if isinstance(n, ast.Attribute)}}
    assert readers <= {"builder", "export"}             # builder reads, export renders
    src = (Path(investigation_pkg.__file__).parent / "builder.py").read_text(encoding="utf-8")
    assert "if include_raw:" in src


def test_investigation_never_loads_ground_truth_generators_evaluation_or_llms():
    code = ("import sys\n"
            "import cyberrescue.investigation.cli\n"
            "bad = {'cyberrescue.telemetry.ground_truth', 'cyberrescue.telemetry.scenarios', "
            "'cyberrescue.telemetry.datasets', 'cyberrescue.evaluation'}\n"
            "heavy = {'thenvoi', 'langchain_openai', 'langgraph', 'openai', 'anthropic', "
            "'pydantic_ai'}\n"
            "print(sorted(m for m in sys.modules if any(m == b or m.startswith(b + '.') "
            "for b in bad)), sorted(heavy & {m.split('.')[0] for m in sys.modules}))\n")
    res = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True,
                         text=True, check=True)
    assert res.stdout.strip() == "[] []"


def test_investigation_never_reads_dataset_files(dbp, monkeypatch):
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
        for ref in ("INC-A", "INC-B", "INC-C"):
            render(build_case(ro, ref, include_raw=True), "html")
    assert not [p for p in seen if "ground_truth" in p or "datasets" in p]
    assert any("ioc_db.json" in p for p in seen)
