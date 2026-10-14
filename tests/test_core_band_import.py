"""CyberRescue Core — offline Band history import (cyberrescue/core/band_import.py)."""

from pathlib import Path

import pytest

from cyberrescue.core import db
from cyberrescue.core.band_import import Roster, import_band_context
from cyberrescue.core.ingest import IngestedMessage, ProtocolIngestor
from cyberrescue.core.models import (
    ActionStatus,
    ActorKind,
    EventType,
    IncidentStatus,
    PolicyOutcome,
)
from cyberrescue.core.policy import PolicyConfig
from cyberrescue.core.service import CoreService

REPO = Path(__file__).resolve().parent.parent
SAMPLE = REPO / "shared" / "sample_message.json"
FIXTURE = REPO / "tests" / "fixtures" / "cyberrescue" / "inc_c_transcript.json"

SYN_ROSTER = Roster.from_mapping({
    "agents": {
        "synthetic-agent-triage": "triage",
        "synthetic-agent-threat-intel": "threat_intel",
        "synthetic-agent-compliance": "compliance",
        "synthetic-agent-commander": "commander",
    },
    "humans": {"synthetic-human-ciso": "ciso"},
})


@pytest.fixture
def svc(tmp_path):
    s = CoreService(db.connect(tmp_path / "core.db"), config=PolicyConfig())
    yield s
    s.conn.close()


def test_real_band_sample_shape_imports(svc):
    # shared/sample_message.json: a real Band context response (UTF-8 BOM,
    # 2 text + 2 tool messages). Nobody is on the roster.
    rep = import_band_context(svc, SAMPLE, incident_ref="INC-B", roster=Roster())
    assert (rep.imported, rep.skipped_non_text, rep.human, rep.unstructured) == (2, 2, 1, 1)
    types = [e.event_type for e in svc.audit.events(rep.incident_id)]
    assert "HUMAN_MESSAGE" in types and "UNSTRUCTURED_MESSAGE" in types


def test_unrostered_senders_get_powerless_roles(svc):
    import_band_context(svc, SAMPLE, incident_ref="INC-B", roster=Roster())
    human = svc.store.find_actor("band:45101ead-d0e6-4dff-aba3-6aabb9298a42")
    agent = svc.store.find_actor("band:e7fffea0-aa9c-4291-96d0-531a612806d8")
    assert (human.kind.value, human.role) == ("human", "observer")
    assert (agent.kind.value, agent.role) == ("agent", "unknown")


def test_legacy_incident_opened_with_warroom_triage_roster(svc):
    rep = import_band_context(svc, FIXTURE, incident_ref="INC-C", roster=SYN_ROSTER)
    inc = svc.store.get_incident(rep.incident_id)
    assert inc.id == "INC-C-2026-0042" and svc.store.aliases_of(inc.id) == ["INC-C"]
    assert set(inc.recruited_roles) == {"threat_intel", "compliance", "commander"}
    assert inc.severity == "critical" and inc.primary_asset_id == "srv-db-01"
    assert svc.store.active_holds("srv-db-01")[0].requires_human_authorization


def test_synthetic_inc_c_run_through_the_gate(svc):
    rep = import_band_context(svc, FIXTURE, incident_ref="INC-C", roster=SYN_ROSTER)
    iid = rep.incident_id
    assert (rep.imported, rep.skipped_non_text, rep.duplicates) == (14, 1, 0)
    assert rep.protocol_valid == 11 and rep.unstructured == 1 and rep.human == 2

    # Lifecycle: BRIEF -> SIGNOFF_REQUEST -> ESCALATION -> CISO ruling.
    assert svc.store.get_incident(iid).status == IncidentStatus.RESPONDING
    # The adversarial messages changed nothing that matters:
    assert svc.store.unconsumed_approvals(iid) == []                 # "approved": true x2
    assert [s.actor_role for s in svc.store.signoffs_for(
        svc.store.latest_signoff_request(iid).event_uid)] == ["threat_intel"]  # triage rejected
    assert [v.action for v in svc.store.active_vetoes(iid)] == ["wipe_host"]    # rogue rejected
    types = [e.event_type for e in svc.audit.events(iid)]
    assert types.count("CLAIM_REJECTED") == 2
    assert types.count("AGENT_ACTION_CLAIM") == 1 and "ACTION_AUTHORIZED" not in types
    assert types.count("INCIDENT_REF_MISMATCH") == 1
    assert {r.action: r.status for r in svc.store.action_requests(iid)} == {
        "isolate_host": ActionStatus.PROPOSED, "preserve_disk_image": ActionStatus.PROPOSED,
        "wipe_host": ActionStatus.PROPOSED}

    # Now the Commander actually asks the Core.
    cmd = svc.store.find_actor("band:synthetic-agent-commander")
    ciso = svc.store.find_actor("band:synthetic-human-ciso")
    assert svc.request_action(iid, "preserve_disk_image", "srv-db-01", cmd).authorized
    iso = svc.request_action(iid, "isolate_host", "srv-db-01", cmd)
    assert iso.decision.rules_failed == ["P4", "P5"]    # compliance vetoed, not signed; critical
    wipe = svc.request_action(iid, "wipe_host", "srv-db-01", cmd)
    assert wipe.decision.outcome == PolicyOutcome.REQUIRE_APPROVAL
    assert wipe.decision.rules_failed == ["P6", "P7", "P8"]

    svc.grant_approval(iid, action="isolate_host", asset_id="srv-db-01",
                       approver_actor_id=ciso.id, reason="contain the spread")
    # policy-v2: the CISO approval covers P5, but cannot stand in for the
    # missing Compliance sign-off (P4) — isolation stays blocked.
    still = svc.request_action(iid, "isolate_host", "srv-db-01", cmd)
    assert not still.authorized and still.decision.rules_failed == ["P4"]
    ProtocolIngestor(svc).ingest(IngestedMessage(
        incident_ref=iid, sender_ref="synthetic-agent-compliance",
        sender_kind=ActorKind.AGENT, sender_role="compliance", source="band",
        external_id="syn-inc-c-extra-signoff",
        content='```json\n{"type": "SIGNOFF", "incident": "INC-C", '
                '"summary": "Isolation is fine."}\n```'))
    assert svc.request_action(iid, "isolate_host", "srv-db-01", cmd).authorized
    svc.grant_approval(iid, action="wipe_host", asset_id="srv-db-01",
                       approver_actor_id=ciso.id, overrides_hold=True, overrides_veto=True,
                       reason="Accept evidence/legal risk to stop domain-wide compromise; "
                              "forensic image already preserved.")
    final = svc.request_action(iid, "wipe_host", "srv-db-01", cmd)
    assert final.authorized and final.decision.approval_id

    assert svc.verify_audit(iid).ok
    assert svc.audit.events(iid, event_type=EventType.ACTION_AUTHORIZED)[-1].payload[
        "action"] == "wipe_host"


def test_reimport_is_idempotent(svc):
    import_band_context(svc, FIXTURE, incident_ref="INC-C", roster=SYN_ROSTER)
    before = len(svc.audit.events("INC-C-2026-0042"))
    rep = import_band_context(svc, FIXTURE, incident_ref="INC-C", roster=SYN_ROSTER)
    assert (rep.imported, rep.duplicates) == (0, 14)
    assert len(svc.audit.events("INC-C-2026-0042")) == before
