"""CyberRescue Core — deterministic legal holds (cyberrescue/core/holds.py)."""

from agents.compliance.tools import evidence_preservation_requirements
from cyberrescue.core.holds import assess_holds
from shared.mock_data import get_asset, load_assets


def test_customer_db_hold_requires_human_authorization():
    h = assess_holds(get_asset("srv-db-01"))
    assert h.preservation_required and h.requires_human_authorization
    assert h.hold_rule_ids == ("FORENSIC-RETENTION",)
    assert set(h.preservation_rule_ids) == {"GDPR-ART-33", "SEC-8K-1.05", "FORENSIC-RETENTION"}


def test_engineering_workstation_has_no_hold():
    h = assess_holds(get_asset("ws-eng-014"))
    assert not h.preservation_required and not h.requires_human_authorization
    assert h.hold_rule_ids == () and h.preservation_rule_ids == ()


def test_parity_with_the_warroom_compliance_tool_for_every_asset():
    for asset in load_assets():
        core = assess_holds(asset)
        tool = evidence_preservation_requirements(asset["asset_id"])
        assert core.preservation_required == tool["preservation_required"], asset["asset_id"]
        assert core.requires_human_authorization == \
            tool["requires_human_authorization_to_destroy"], asset["asset_id"]
        assert list(core.hold_rule_ids) == [r["rule_id"] for r in tool["hold_rules"]]
        assert list(core.preservation_rule_ids) == \
            [r["rule_id"] for r in tool["triggering_rules"]]
