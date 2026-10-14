"""LIVE, read-only: a real Band incident room -> JSON export -> Core import.

Proves (on real data) that a live run's messages can be captured and that the
Core's protocol ingestion and audit chain accept them. It does not by itself
prove the agents collaborated well -- read the export for that.
"""

import os
from pathlib import Path

import pytest

from cyberrescue.core.band_import import Roster, import_band_context
from cyberrescue.core.db import REPO_ROOT
from cyberrescue.core.service import CoreService
from cyberrescue.live.band_export import collect_room, real_clients, write_export
from cyberrescue.live.preflight import load_agent_config, run_preflight
from cyberrescue.live.roster import build_roster


def _room() -> str:
    room = os.getenv("CYBERRESCUE_LIVE_ROOM")
    if not room:
        pytest.skip("set CYBERRESCUE_LIVE_ROOM to the incident room id")
    return room


def test_preflight_passes():
    rep = run_preflight(REPO_ROOT)
    assert rep.ok(), [c for c in rep.failures]


def test_room_exports_and_imports_into_a_fresh_core(tmp_path):
    room = _room()
    clients, skipped = real_clients()
    assert clients, "no agent credentials"
    doc = collect_room(clients, room)
    write_export(tmp_path / "export.json", doc)
    failed = {r: v for r, v in doc["views"].items() if not v["ok"]}
    assert not failed and not skipped, (failed, skipped)
    assert doc["message_count"] > 0

    humans = {}
    if os.getenv("CYBERRESCUE_LIVE_CISO_ID"):
        humans[os.environ["CYBERRESCUE_LIVE_CISO_ID"]] = "ciso"
    roster = Roster.from_mapping(build_roster(load_agent_config(
        REPO_ROOT / "agent_config.yaml"), humans))
    svc = CoreService.open(Path(os.environ["CYBERRESCUE_DB_PATH"]))
    try:
        rep = import_band_context(svc, tmp_path / "export.json",
                                  incident_ref=os.getenv("CYBERRESCUE_INCIDENT", "INC-C"),
                                  roster=roster)
        assert rep.imported > 0 and rep.protocol_valid > 0
        assert svc.verify_audit(rep.incident_id).ok
        again = import_band_context(svc, tmp_path / "export.json",
                                    incident_ref=rep.incident_id, roster=roster)
        assert again.imported == 0                                  # idempotent
    finally:
        svc.conn.close()


def test_single_sync_poll_into_a_fresh_core(tmp_path):
    """LIVE, read-only: one `live sync` poll of the real room into a throw-away Core."""
    from cyberrescue.live.sync import EXIT_OK, LiveSync, SyncSettings
    room = _room()
    clients, skipped = real_clients()
    assert clients and not skipped, skipped
    roster = Roster.from_mapping(build_roster(load_agent_config(REPO_ROOT / "agent_config.yaml")))
    db = tmp_path / "sync.db"
    s = LiveSync(SyncSettings(room_id=room, incident_ref=os.getenv("CYBERRESCUE_INCIDENT", "INC-C"),
                              max_polls=1), roster,
                 open_core=lambda: CoreService.open(db),
                 collect=lambda: collect_room(clients, room),
                 log_path=tmp_path / "sync.jsonl", lock_path=tmp_path / "sync.lock")
    summary = s.run()
    assert summary.exit_code == EXIT_OK, summary.halt
    assert summary.imported > 0
