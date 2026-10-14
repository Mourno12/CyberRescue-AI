"""Deterministic legal-hold derivation.

WarRoom's Compliance *agent* learns about holds from its tool
``evidence_preservation_requirements`` and then (hopefully) posts a VETO. The
Core derives the same facts itself, from the same data
(``shared/mock_env/reg_rules.json`` + the asset's data classes), so a hold
binds even if the LLM never mentions it.

The logic intentionally mirrors ``agents/compliance/tools.py``; a parity test
(tests/test_core_holds.py) keeps the two in lock-step for every mock asset.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cyberrescue.core.models import Asset
from shared.mock_data import load_reg_rules


@dataclass(frozen=True)
class HoldAssessment:
    asset_id: str
    preservation_required: bool
    requires_human_authorization: bool      # image does NOT release the hold
    preservation_rule_ids: tuple[str, ...]
    hold_rule_ids: tuple[str, ...]


def assess_holds(asset: Asset | dict[str, Any],
                 rules: list[dict[str, Any]] | None = None) -> HoldAssessment:
    a = asset if isinstance(asset, Asset) else Asset(**{
        k: v for k, v in asset.items() if k in Asset.model_fields})
    rules = rules if rules is not None else load_reg_rules()
    classes = set(a.data_classes)

    def fires(rule: dict[str, Any]) -> bool:
        return bool(classes & set(rule.get("trigger", {}).get("data_classes", [])))

    preservation = tuple(r["rule_id"] for r in rules
                         if r.get("evidence_preservation_required") and fires(r))
    holds = tuple(r["rule_id"] for r in rules
                  if r.get("requires_human_authorization_to_destroy") and fires(r))
    return HoldAssessment(
        asset_id=a.asset_id,
        preservation_required=bool(preservation),
        requires_human_authorization=bool(holds),
        preservation_rule_ids=preservation,
        hold_rule_ids=holds,
    )
