"""CyberRescue Phase 5 — the simulated environment is built from evidence and lives in memory."""

import pytest

from cyberrescue.execution.environment import SimEnvironment
from tests._detection_factory import Evidence, at

INVENTORY = ["srv-db-01", "srv-app-01", "ws-eng-014"]


@pytest.fixture(scope="module")
def env():
    ev = Evidence()
    ev.proc(at("10:00:00"), "srv-db-01", "C:\\ProgramData\\upd\\bhz.exe", user="svc_sqlbackup")
    ev.file(at("10:00:05"), "srv-db-01", "rename", "D:\\a\\1", target="D:\\a\\1.blackhaze")
    ev.service(at("10:00:06"), "srv-db-01", "UpdSvc", "C:\\ProgramData\\upd\\bhz.exe")
    ev.runkey(at("10:00:07"), "ws-eng-014", "HKCU\\...\\Run\\X", "C:\\Users\\a\\x.exe")
    ev.connect(at("10:00:10"), "srv-db-01", "185.220.101.47", 443, process="bhz.exe")
    ev.auth(at("10:00:20"), "srv-app-01", 4624, "svc_sqlbackup", "srv-db-01")
    return SimEnvironment.from_view(ev.view(), INVENTORY)


def test_world_is_built_from_structured_evidence(env):
    assert env.hosts == frozenset(INVENTORY)
    assert ("srv-db-01", "bhz.exe") in env.processes
    assert ("srv-db-01", "c:\\programdata\\upd\\bhz.exe") in env.files
    assert ("srv-db-01", "d:\\a\\1.blackhaze") in env.files
    assert ("ws-eng-014", "c:\\users\\a\\x.exe") in env.files
    assert "185.220.101.47" in env.indicators
    assert {"svc_sqlbackup", "system"} <= set(env.accounts)


def test_every_fact_cites_evidence(env):
    for table in (env.processes, env.files, env.indicators, env.accounts):
        assert table and all(ids and all(i.startswith("EV-") for i in ids)
                             for ids in table.values())


def test_changes_are_copy_on_write(env):
    after = env.with_(killed=env.killed | {("srv-db-01", "bhz.exe")},
                      quarantined=frozenset({("srv-db-01", "c:\\programdata\\upd\\bhz.exe")}))
    assert env.process_running("srv-db-01", "BHZ.EXE")
    assert not after.process_running("srv-db-01", "bhz.exe")
    assert env.file_present("srv-db-01", "C:\\ProgramData\\upd\\bhz.exe")
    assert not after.file_present("srv-db-01", "C:\\ProgramData\\upd\\bhz.exe")
    with pytest.raises(Exception):
        env.isolated = frozenset({"srv-db-01"})      # frozen


def test_unobserved_things_are_absent(env):
    assert not env.process_running("srv-db-01", "notepad.exe")
    assert not env.file_present("srv-app-01", "C:\\ProgramData\\upd\\bhz.exe")


def test_fingerprint_is_deterministic_and_ignores_simulated_changes(env):
    again = SimEnvironment.from_view(Evidence().view(), INVENTORY)
    assert env.fingerprint() == env.with_(isolated=frozenset({"srv-db-01"})).fingerprint()
    assert env.fingerprint() != again.fingerprint() and len(env.fingerprint()) == 64
