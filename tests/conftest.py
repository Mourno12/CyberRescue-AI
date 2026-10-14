"""Test-session isolation for CyberRescue Core side effects.

Since Phase 1b the Commander's action tools consult the CyberRescue gate
(default mode: shadow), so even the original WarRoom test that calls those
tools evaluates a policy decision. Point the Core database and gate log at a
session temp dir so no test writes into the repository, and clear any gate
settings inherited from the developer's shell. No assertion is affected.
"""

import pytest


@pytest.fixture(autouse=True, scope="session")
def _cyberrescue_isolated_paths(tmp_path_factory):
    d = tmp_path_factory.mktemp("cyberrescue")
    mp = pytest.MonkeyPatch()
    mp.setenv("CYBERRESCUE_DB_PATH", str(d / "session.db"))
    mp.setenv("CYBERRESCUE_GATE_LOG", str(d / "gate_log.jsonl"))
    for var in ("CYBERRESCUE_GATE_MODE", "CYBERRESCUE_INCIDENT", "CYBERRESCUE_COMMANDER_REF",
                "CYBERRESCUE_APPROVAL_TTL_MINUTES"):
        mp.delenv(var, raising=False)
    yield
    mp.undo()
