"""Tests for the regulatory clock (Phase 5.3): persisted deadline + live T-minus.

Uses REG_CLOCK_PATH pointed at a temp file so tests don't touch the real store.
``now`` is injected so the countdown is deterministic.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture()
def clock_file(tmp_path, monkeypatch):
    path = tmp_path / "clocks.json"
    monkeypatch.setenv("REG_CLOCK_PATH", str(path))
    return path


def _t(h=0, m=0):
    return datetime(2026, 6, 14, 9, 0, tzinfo=timezone.utc) + timedelta(hours=h, minutes=m)


def test_format_tminus_counts_down_and_breaches():
    from shared import reg_clock
    deadline = _t(72)  # 72h after the base time
    assert reg_clock.format_tminus(deadline.isoformat(), now=_t(0)) == "T-minus 3d 0h 0m"
    assert reg_clock.format_tminus(deadline.isoformat(), now=_t(1, 18)) == "T-minus 2d 22h 42m"
    out = reg_clock.format_tminus(deadline.isoformat(), now=_t(73))
    assert out.startswith("BREACHED")


def test_start_clock_is_idempotent(clock_file):
    from shared import reg_clock
    deadline = _t(72).isoformat()
    a = reg_clock.start_clock("INC-C", "GDPR-ART-33", "GDPR Art. 33", deadline,
                              "72 hours", now=_t(0))
    # A later call must NOT move the deadline; T-minus reflects the new 'now'.
    b = reg_clock.start_clock("INC-C", "GDPR-ART-33", "GDPR Art. 33",
                              _t(99).isoformat(), "72 hours", now=_t(2))
    assert a["deadline_utc"] == b["deadline_utc"] == deadline  # fixed
    assert a["started_utc"] == b["started_utc"]                # not restarted
    assert b["t_minus"] == "T-minus 2d 22h 0m"                 # counts down


def test_clock_status_lists_running_clocks(clock_file):
    from shared import reg_clock
    reg_clock.start_clock("INC-C", "GDPR-ART-33", "GDPR Art. 33", _t(72).isoformat(),
                          "72 hours", now=_t(0))
    reg_clock.start_clock("INC-C", "SEC-8K-1.05", "SEC 8-K", _t(96).isoformat(),
                          "4 business_days", now=_t(0))
    reg_clock.start_clock("INC-A", "OTHER", "Other", _t(48).isoformat(),
                          "48 hours", now=_t(0))
    status = reg_clock.clock_status("INC-C", now=_t(1))
    regs = sorted(c["regulation"] for c in status)
    assert regs == ["GDPR-ART-33", "SEC-8K-1.05"]   # only INC-C's clocks
    assert all(not c["breached"] for c in status)


def test_start_notification_clock_persists_and_normalizes_incident(clock_file):
    from agents.compliance.tools import regulatory_clock_status, start_notification_clock
    # Pass a decorated incident id; the clock key normalizes to the INC alias.
    r = start_notification_clock("GDPR-ART-33", "INC-C-2026-0042", now=_t(0))
    assert r["started"] and r["incident"] == "INC-C"
    assert "t_minus" in r
    # Status by the bare alias finds the same clock (stable key).
    st = regulatory_clock_status("INC-C", now=_t(0, 30))
    assert any(c["regulation"] == "GDPR-ART-33" for c in st["clocks"])
    assert "GDPR-ART-33" in st["summary"]
