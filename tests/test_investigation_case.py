"""CyberRescue Phase 3 — claims, provenance, policy view, case build and verification."""

import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from cyberrescue.core.band_import import Roster, import_band_context
from cyberrescue.core.models import IncidentStatus
from cyberrescue.core.service import CoreService
from cyberrescue.investigation.builder import build_case, verify_case
from cyberrescue.investigation.claims import reconcile_claims
from cyberrescue.investigation.findings import collect_findings
from cyberrescue.investigation.provenance import provenance_records
from cyberrescue.investigation.readonly import ReadOnlyError, open_readonly
from tests._detection_factory import investigated_core, scenario_core

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cyberrescue" / "inc_c_transcript.json"
ROSTER = Roster(agents={"synthetic-agent-commander": "commander",
                        "synthetic-agent-compliance": "compliance",
                        "synthetic-agent-threat-intel": "threat_intel",
                        "synthetic-agent-triage": "triage"},
                humans={"synthetic-human-ciso": "ciso"})
INC = "INC-C-2026-0042"


@pytest.fixture(scope="module")
def dbp(tmp_path_factory):
    """Scenarios + persisted detections, plus WarRoom agent findings and authority
    state on INC-C (written through the normal Core APIs before reading)."""
    path = investigated_core(tmp_path_factory.mktemp("case") / "core.db")
    svc = CoreService.open(path)
    import_band_context(svc, FIXTURE, incident_ref="INC-C", roster=ROSTER)
    ev = [e.id for e in svc.list_evidence(INC)]
    intel = svc.register_actor("agent", "threat_intel", "ti2", "test:ti2")
    comp = svc.register_actor("agent", "compliance", "co2", "test:co2")
    svc.record_finding(INC, intel, "C2 contact observed", claims=["flow to C2"],
                       evidence_ids=ev[:2])
    partial = svc.record_finding(INC, comp, "PII host affected", evidence_ids=ev[2:3])
    svc.cite_evidence_from_message(partial, comp, ["EV-hallucinated"])
    cmd = svc.store.find_actor("band:synthetic-agent-commander")
    svc.request_action(INC, "wipe_host", "srv-db-01", cmd.id, source="test")
    svc.conn.close()
    return path


@pytest.fixture
def ro(dbp):
    core = open_readonly(dbp)
    yield core
    core.close()


def writable_copy(dbp, tmp_path):
    target = tmp_path / "copy.db"
    shutil.copy(dbp, target)
    return target


# --- claims ------------------------------------------------------------------------

def test_agent_findings_are_reconciled_by_citation_coverage(ro):
    recs = collect_findings(ro, INC)
    claims = {c.summary.untrusted: c for c in reconcile_claims(ro, INC, recs)}
    assert claims["C2 contact observed"].status == "evidence-backed"
    assert claims["PII host affected"].status == "partially backed"
    assert claims["PII host affected"].rejected_citations == 1
    band = [c for c in claims.values() if c.author_role in ("threat_intel", "compliance",
                                                             "commander", "triage")
            and c.summary.untrusted not in ("C2 contact observed", "PII host affected")]
    assert band and all(c.status == "unsupported" for c in band)
    assert all(c.author_kind == "agent" for c in claims.values())


def test_detector_findings_are_not_reconciled(ro):
    recs = collect_findings(ro, INC)
    assert {r.origin for r in recs} >= {"detection", "agent"}
    ids = {c.finding_id for c in reconcile_claims(ro, INC, recs)}
    assert not ids & {r.finding.id for r in recs if r.origin == "detection"}


# --- provenance ----------------------------------------------------------------------

def test_provenance_fields(ro):
    bhz = next(e for e in ro.list_evidence(INC) if e.data.get("process.name") == "bhz.exe"
               and e.event_type == "process_start")
    [p] = provenance_records(ro, [bhz.id])
    assert (p.source, p.provenance, p.sensor.untrusted, p.vendor.untrusted) == (
        "synthetic.scenario-a.edr", "synthetic", "edr", "CrowdFalcon")
    assert p.adapter.untrusted == "cyberrescue.telemetry.adapter/v1"
    assert p.ingested_by["kind"] == "system" and p.ingested_by["role"] == "collector"
    assert p.integrity_ok and p.content_sha256 == bhz.content_sha256
    with pytest.raises(ReadOnlyError):
        provenance_records(ro, ["EV-nope"])


def test_tampered_evidence_is_reported(dbp, tmp_path):
    copy = writable_copy(dbp, tmp_path)
    conn = sqlite3.connect(copy)
    conn.execute("DROP TRIGGER evidence_no_update")
    target = conn.execute("SELECT id FROM evidence WHERE incident_id = ? LIMIT 1",
                          (INC,)).fetchone()[0]
    conn.execute("UPDATE evidence SET raw = 'forged' WHERE id = ?", (target,))
    conn.commit()
    conn.close()
    with open_readonly(copy) as ro:
        [p] = provenance_records(ro, [target])
        assert not p.integrity_ok and p.integrity_errors
        assert build_case(ro, "INC-C").integrity["evidence_ok"] is False


# --- policy view ---------------------------------------------------------------------

def test_policy_view_shows_holds_and_pending_requests(ro):
    pol = build_case(ro, "INC-C").policy
    [hold] = pol.holds
    assert hold["asset_id"] == "srv-db-01" and hold["requires_human_authorization"]
    decided = [r for r in pol.action_requests if r["latest_outcome"]]
    undecided = [r for r in pol.action_requests if not r["latest_outcome"]]
    [req] = decided                                     # the request evaluated by policy
    assert (req["action"], req["latest_outcome"], req["unmet_rules"]) == (
        "wipe_host", "REQUIRE_APPROVAL", ["P6", "P8"])
    # Agent proposals imported from the Band transcript: recorded, never decided.
    assert undecided and all(r["status"] == "proposed" for r in undecided)
    assert pol.approvals == ()


# --- case ---------------------------------------------------------------------------

def test_case_sections_and_persisted_mapping(ro):
    case = build_case(ro, "INC-C")
    assert case.case_id.startswith("CASE-") and case.incident_id == INC
    assert case.aliases == ("INC-C",)
    assert {d.rule_id for d in case.detections} >= {"RANSOM-001", "CORR-001"}
    assert all(d.persisted_finding_id for d in case.detections)
    origins = {f.origin for f in case.findings}
    assert origins == {"detection", "agent"}
    assert [g.code for g in case.gaps].count("G6") >= 1
    assert case.as_of == ro.audit.events(INC)[-1].ts
    assert case.integrity["audit_chain_ok"] and case.integrity["evidence_ok"]


def test_case_is_byte_identical_for_the_same_database(ro):
    a, b = build_case(ro, "INC-A"), build_case(ro, "INC-A")
    assert a.to_json() == b.to_json() and a.case_sha256 == b.case_sha256


def test_analysis_is_identical_on_an_independently_ingested_core(ro, tmp_path):
    svc, _ = scenario_core(tmp_path / "other.db", keys=("C",))
    svc.conn.close()
    with open_readonly(tmp_path / "other.db") as other:
        mine, theirs = build_case(ro, "INC-A"), build_case(other, "INC-A")
    # Core-assigned values differ (finding ids, ingestion times, audit hashes);
    # the evidence-derived analysis does not.
    # (The timeline differs by design: persisted citations are part of its
    # condensation key, and the other Core has no persisted findings.)
    for part in ("graph", "scope", "gaps", "observations"):
        assert getattr(mine, part) == getattr(theirs, part)
    assert [d.detection_id for d in mine.detections] == \
        [d.detection_id for d in theirs.detections]
    assert mine.case_sha256 != theirs.case_sha256      # Core-assigned values differ


def test_raw_is_excluded_by_default_and_untrusted_when_included(ro):
    plain = build_case(ro, "INC-C")
    assert plain.raw_evidence == () and plain.integrity["options"] == {"include_raw": False}
    with_raw = build_case(ro, "INC-C", include_raw=True)
    cited = {p.evidence_id for p in with_raw.provenance}
    assert {r.evidence_id for r in with_raw.raw_evidence} == cited
    note = next(r for r in with_raw.raw_evidence if "IGNORE PREVIOUS" in r.raw.untrusted)
    assert note.raw.model_dump()["untrusted"].startswith("2026-06-13T14:07:21Z")
    assert with_raw.case_sha256 != plain.case_sha256


def test_closed_incident_is_readable(dbp, tmp_path):
    copy = writable_copy(dbp, tmp_path)
    svc = CoreService.open(copy)
    svc.store.set_status("INC-A-2026-0039", IncidentStatus.RESOLVED, trigger="test",
                         actor_id=None, cause_uid=None)
    svc.conn.close()
    with open_readonly(copy) as ro:
        assert build_case(ro, "INC-A").policy.status == "RESOLVED"


def test_unknown_incident(ro):
    with pytest.raises(ReadOnlyError, match="no Core incident"):
        build_case(ro, "INC-20990101-0001")


# --- verify -------------------------------------------------------------------------

def test_verify_accepts_an_untouched_case(ro):
    for raw in (False, True):
        assert verify_case(ro, build_case(ro, "INC-B", include_raw=raw).to_json()).ok


def test_verify_detects_an_edited_export(ro):
    doc = json.loads(build_case(ro, "INC-C").to_json())
    doc["scope"]["compromised_hosts"] = []
    res = verify_case(ro, json.dumps(doc))
    assert not res.ok and any("edited export" in e for e in res.errors)


def test_verify_detects_a_changed_database(dbp, tmp_path):
    copy = writable_copy(dbp, tmp_path)
    with open_readonly(copy) as ro:
        doc = build_case(ro, "INC-A").to_json()
    svc = CoreService.open(copy)
    det = svc.store.find_actor("detector:test")
    svc.record_finding("INC-A-2026-0039", det, "late finding")
    svc.conn.close()
    with open_readonly(copy) as ro:
        res = verify_case(ro, doc)
    assert not res.ok and any("no longer produces" in e for e in res.errors)


def test_verify_rejects_garbage(ro):
    assert not verify_case(ro, "{not json").ok
    assert not verify_case(ro, json.dumps({"case_id": "x"})).ok
