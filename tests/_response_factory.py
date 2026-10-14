"""Shared Core builders for the Phase 4 response-planning tests."""

from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path

from cyberrescue.core.band_import import import_band_context
from cyberrescue.core.service import CoreService
from tests._detection_factory import investigated_core
from tests.test_investigation_case import FIXTURE, ROSTER

INC = "INC-C-2026-0042"


def authority_core(path: Path) -> Path:
    """Scenarios + persisted detections, plus the WarRoom INC-C transcript (agent
    findings, sign-off request, sign-offs, Compliance veto, holds) imported
    through the normal Core APIs. Closed so it can be opened read-only."""
    investigated_core(path)
    svc = CoreService.open(path)
    import_band_context(svc, FIXTURE, incident_ref="INC-C", roster=ROSTER)
    svc.conn.close()
    return path


def writable_copy(src: Path, target: Path) -> Path:
    shutil.copy(src, target)
    return target


def at(iso: str):
    return lambda: datetime.fromisoformat(iso)
