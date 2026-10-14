"""Loaders for the WarRoom mock environment (``shared/mock_env/``).

Pure Python, no Band/framework dependency — this is the data substrate the
Phase 3 agent tools read from. Everything is read-only and cached; the JSON
files are the single source of truth for the demo's domain facts.

The design rule (implementation plan §2): all domain tools are mocks reading
from here. Asymmetric knowledge across these files — IOCs only Threat Intel
queries, data_classes only Compliance reasons about — is what forces the
agents to talk.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

MOCK_ENV_DIR = Path(__file__).resolve().parent / "mock_env"
ALERTS_DIR = MOCK_ENV_DIR / "alerts"


@lru_cache(maxsize=None)
def _load_json(path: str) -> Any:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"mock_env file not found: {p}")
    with p.open(encoding="utf-8") as f:
        return json.load(f)


# --- Indicator-of-compromise database -------------------------------------

def load_iocs() -> list[dict[str, Any]]:
    """All threat-intel indicators."""
    return _load_json(str(MOCK_ENV_DIR / "ioc_db.json"))["indicators"]


# --- Asset inventory -------------------------------------------------------

def load_assets() -> list[dict[str, Any]]:
    """All hosts/workstations in the mock estate."""
    return _load_json(str(MOCK_ENV_DIR / "asset_inventory.json"))["assets"]


def get_asset(asset_id: str) -> dict[str, Any] | None:
    """One asset by id, or None if unknown."""
    for asset in load_assets():
        if asset["asset_id"] == asset_id:
            return asset
    return None


# --- Regulatory rules ------------------------------------------------------

def load_reg_rules() -> list[dict[str, Any]]:
    """All machine-readable regulatory rules."""
    return _load_json(str(MOCK_ENV_DIR / "reg_rules.json"))["rules"]


# --- Alerts ----------------------------------------------------------------

# Friendly aliases so callers can say "INC-C" without knowing the filename or
# the full incident id.
_ALERT_FILES = {
    "INC-A": "INC-A-malware-clean.json",
    "INC-B": "INC-B-false-positive.json",
    "INC-C": "INC-C-ransomware-pii.json",
}


def list_alerts() -> list[str]:
    """Available alert filenames (sorted)."""
    return sorted(p.name for p in ALERTS_DIR.glob("*.json"))


def load_alert(incident: str) -> dict[str, Any]:
    """Load an alert by alias ("INC-C"), incident_id ("INC-C-2026-0042"),
    or filename. Raises KeyError/FileNotFoundError if not found."""
    # Alias (case-insensitive prefix like "INC-C")
    key = incident.strip().upper()
    if key in _ALERT_FILES:
        return _load_json(str(ALERTS_DIR / _ALERT_FILES[key]))

    # Exact filename
    if incident.endswith(".json"):
        return _load_json(str(ALERTS_DIR / incident))

    # incident_id match (scan files)
    for fname in list_alerts():
        data = _load_json(str(ALERTS_DIR / fname))
        if data.get("incident_id", "").upper() == key:
            return data

    # Fallback: extract an embedded alias. LLMs often pass a decorated id like
    # "INC-C-2026-0042" or "INC-C-2026-[BlackHaze-srv-db-01]" instead of the bare
    # alias; recover the "INC-A/B/C" token so the tool doesn't hard-fail.
    m = re.search(r"INC-[ABC]", key)
    if m and m.group(0) in _ALERT_FILES:
        return _load_json(str(ALERTS_DIR / _ALERT_FILES[m.group(0)]))

    raise KeyError(
        f"unknown alert '{incident}'. Aliases: {list(_ALERT_FILES)}; "
        f"files: {list_alerts()}"
    )
