"""LIVE integration tests -- separate from the offline suite in tests/.

They talk to the real Band service (read-only) and are skipped unless the
operator opts in explicitly:

    $env:CYBERRESCUE_LIVE_TESTS = "1"
    $env:CYBERRESCUE_LIVE_ROOM  = "<incident room id from the live run>"
    .venv313\\Scripts\\python.exe -m pytest tests_live -q -p no:cacheprovider -rs

No test here calls an LLM, posts a message, or creates a room.
"""

import os

import pytest


def pytest_collection_modifyitems(config, items):
    if os.getenv("CYBERRESCUE_LIVE_TESTS") == "1":
        return
    skip = pytest.mark.skip(reason="LIVE test: set CYBERRESCUE_LIVE_TESTS=1 to run "
                                   "(needs agent_config.yaml + network)")
    for item in items:
        item.add_marker(skip)


@pytest.fixture(autouse=True)
def _isolated_core(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERRESCUE_DB_PATH", str(tmp_path / "live.db"))
    monkeypatch.setenv("CYBERRESCUE_GATE_LOG", str(tmp_path / "gate.jsonl"))
