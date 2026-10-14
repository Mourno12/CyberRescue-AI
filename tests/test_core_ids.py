"""CyberRescue Core — incident identity (cyberrescue/core/ids.py)."""

import re
from datetime import datetime, timezone

import pytest

from cyberrescue.core.ids import (
    LEGACY_ALIASES,
    generate_incident_id,
    is_generated_id,
    is_valid_incident_id,
    legacy_alias_for,
    parse_incident_ref,
)
from shared.mock_data import load_alert

# The exact pattern WarRoom modules use (mock_data, compliance tools,
# sdk_patches, export_report).
WARROOM_LEGACY_RE = re.compile(r"INC-[ABC]", re.IGNORECASE)


def test_legacy_aliases_match_mock_alerts():
    for alias, full in LEGACY_ALIASES.items():
        assert load_alert(alias)["incident_id"] == full
        assert parse_incident_ref(alias) == full
        assert parse_incident_ref(alias.lower()) == full
        assert parse_incident_ref(full) == full
        assert legacy_alias_for(full) == alias


def test_decorated_legacy_refs_resolve_like_mock_data():
    assert parse_incident_ref("INC-C-2026-[BlackHaze-srv-db-01]") == "INC-C-2026-0042"
    assert parse_incident_ref("  incident inc-a please ") == "INC-A-2026-0039"


def test_generated_id_format():
    now = datetime(2026, 9, 27, 23, 59, tzinfo=timezone.utc)
    iid = generate_incident_id(7, now=now)
    assert iid == "INC-20260927-0007"
    assert is_generated_id(iid) and is_valid_incident_id(iid)
    assert legacy_alias_for(iid) is None


def test_generated_ids_never_match_the_warroom_legacy_regex():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for seq in (1, 42, 9999):
        assert WARROOM_LEGACY_RE.search(generate_incident_id(seq, now=now)) is None


def test_general_ids_accepted_and_embedded_ids_extracted():
    assert parse_incident_ref("INC-PHISH-2026-0001") == "INC-PHISH-2026-0001"
    assert parse_incident_ref("see INC-20260927-0003 now") == "INC-20260927-0003"
    # Stricter than WarRoom: "INC-BRUTE..." is NOT the legacy INC-B.
    assert parse_incident_ref("INC-BRUTE-01") == "INC-BRUTE-01"


def test_invalid_refs_rejected():
    for bad in ("", "   ", "srv-db-01", "INC-", "incident c", "INC_A"):
        assert parse_incident_ref(bad) is None
    assert not is_valid_incident_id("INC-c-lower")
    assert not is_valid_incident_id("INC--X")


def test_generate_rejects_out_of_range_sequence():
    with pytest.raises(ValueError):
        generate_incident_id(0)
    with pytest.raises(ValueError):
        generate_incident_id(10000)
