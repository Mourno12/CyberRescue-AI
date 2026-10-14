"""CyberRescue Phase 6 — the Core records SIMULATED executions, and nothing else changes."""

from datetime import datetime, timedelta, timezone

import pytest

from cyberrescue.core.models import ActionStatus, EventType, LinkRelation
from cyberrescue.core.service import CoreService
from cyberrescue.detection.engine import load_view
from tests._detection_factory import scenario_core
from tests.test_investigation_security import db_state

INC = "INC-C-2026-0042"
T0 = datetime(2026, 6, 13, 15, 0, tzinfo=timezone.utc)
HEX = "a" * 64


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now


def kwargs(svc, **kw):
    base = {"action": "preserve_disk_image", "asset_id": "srv-db-01",
            "plan_id": "PLAN-" + "1" * 16, "plan_sha256": HEX, "step_id": "STEP-" + "2" * 12,
            "step_sha256": HEX, "report_sha256": HEX,
            "evidence_fingerprint": svc.store.evidence_fingerprint(INC),
            "environment_sha256": HEX, "outcome": "succeeded",
            "criteria": [{"check": "image_recorded", "satisfied": True}]}
    return {**base, **kw}


@pytest.fixture
def env(tmp_path):
    clock = Clock()
    svc, _ = scenario_core(tmp_path / "core.db", keys=("A",), clock=clock)
    cmd = svc.register_actor("agent", "commander", "c", "test:commander")
    executor = svc.register_actor("system", "executor", "simulated executor", "test:executor")
    out = svc.request_action(INC, "preserve_disk_image", "srv-db-01", cmd.id, source="test")
    assert out.authorized
    yield svc, clock, cmd, executor, out
    svc.conn.close()


def test_recording_a_simulated_execution(env):
    svc, clock, _, executor, out = env
    clock.now += timedelta(minutes=5)
    rec = svc.record_simulated_execution(INC, request_id=out.request.id,
                                         recorder_actor_id=executor.id, **kwargs(svc))
    assert rec.mode == "simulated" and rec.outcome == "succeeded"
    assert rec.action_request_id == out.request.id and rec.asset_id == "srv-db-01"
    assert rec.authorized_event_uid == out.authorization_event_uid
    assert svc.execution_records("INC-C") == [rec]
    assert svc.store.execution_record_for(out.request.id) == rec


def test_events_are_linked_into_the_audit_chain(env):
    svc, _, _, executor, out = env
    head = svc.store.chain_head(INC)
    rec = svc.record_simulated_execution(INC, request_id=out.request.id,
                                         recorder_actor_id=executor.id, **kwargs(svc))
    executed = svc.audit.get(rec.executed_event_uid)
    verified = svc.audit.get(rec.verified_event_uid)
    assert executed.event_type == EventType.ACTION_EXECUTED.value
    assert verified.event_type == EventType.ACTION_VERIFIED.value
    assert executed.payload["mode"] == verified.payload["mode"] == "simulated"
    assert [(LinkRelation(lk.relation), lk.target_uid) for lk in executed.links] == \
        [(LinkRelation.EXECUTES, out.authorization_event_uid)]
    assert [(LinkRelation(lk.relation), lk.target_uid) for lk in verified.links] == \
        [(LinkRelation.VERIFIES, executed.uid)]
    assert executed.payload["audit_head_hash"] == rec.audit_head_hash == head
    assert verified.payload["criteria"] == rec.criteria
    assert executed.actor_id == verified.actor_id == executor.id
    assert svc.verify_audit(INC).ok


def test_request_incident_and_authority_tables_are_untouched(env):
    svc, _, _, executor, out = env
    path = svc.conn.execute("PRAGMA database_list").fetchone()["file"]
    status = svc.store.get_incident(INC).status
    before = db_state(path)
    svc.record_simulated_execution(INC, request_id=out.request.id,
                                   recorder_actor_id=executor.id,
                                   **kwargs(svc, outcome="failed", criteria=[
                                       {"check": "image_recorded", "satisfied": False}]))
    after = db_state(path)
    changed = {k for k in before if before[k] != after[k]}
    assert changed == {"audit_events", "event_links", "execution_records"}
    assert svc.store.get_action_request(out.request.id).status == ActionStatus.AUTHORIZED
    assert svc.store.get_incident(INC).status == status


def test_core_evidence_fingerprint_matches_the_detection_view(env):
    svc = env[0]
    assert svc.store.evidence_fingerprint(INC) == load_view(svc, INC).fingerprint


def test_failed_outcomes_are_recorded_too(env):
    svc, _, _, executor, out = env
    rec = svc.record_simulated_execution(
        INC, request_id=out.request.id, recorder_actor_id=executor.id,
        **kwargs(svc, outcome="failed", criteria=[{"check": "image_recorded",
                                                   "satisfied": False}]))
    assert rec.outcome == "failed" and rec.criteria == [{"check": "image_recorded",
                                                         "satisfied": False}]


def test_service_is_the_only_writer_in_the_core():
    import ast
    from pathlib import Path

    import cyberrescue.core as core_pkg
    root = Path(core_pkg.__file__).parent
    callers = {p.stem for p in root.glob("*.py")
               if "add_execution_record" in {n.attr for n in ast.walk(ast.parse(
                   p.read_text(encoding="utf-8"))) if isinstance(n, ast.Attribute)}}
    assert callers == {"service"}
    assert CoreService.record_simulated_execution.__doc__.startswith("THE ONLY WAY")
