"""Scenario ground truth — EVALUATION ONLY.

Ground truth records what really happened in a synthetic scenario (which
events are attacker activity, the attack chain, the expected conclusions) so a
later phase can *measure* an investigation. It must never become operational
evidence:

* it is a separate model in a separate file (``ground_truth/<dataset>.json``),
  marked ``"evaluation_only": true``;
* the telemetry schema forbids label keys, and the adapter refuses any object
  carrying ``evaluation_only`` — so a ground-truth file cannot be ingested;
* the adapter and the importer never import this module (AST-tested);
* ground truth references telemetry by ``event_id`` only; it is joined to
  evidence by ``source_ref`` at evaluation time, outside the Core.

Stage names are plain descriptive labels, not an ATT&CK mapping.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from cyberrescue.telemetry.schema import TelemetryEvent

GROUND_TRUTH_SCHEMA = "cyberrescue.ground_truth/v1"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AttackStep(_Model):
    stage: str
    description: str
    event_ids: list[str]


class BenignExplanation(_Model):
    explanation: str
    event_ids: list[str]


class GroundTruth(_Model):
    ground_truth_schema: Literal["cyberrescue.ground_truth/v1"] = GROUND_TRUTH_SCHEMA
    evaluation_only: Literal[True] = True
    scenario: str
    dataset: str
    incident_alias: str
    incident_id: str
    verdict: Literal["true_positive", "false_positive"]
    category: str
    summary: str
    event_count: int
    malicious_event_ids: list[str] = Field(default_factory=list)
    vendor_alert_event_ids: list[str] = Field(default_factory=list)
    hostile_content_event_ids: list[str] = Field(default_factory=list)
    attack_chain: list[AttackStep] = Field(default_factory=list)
    benign_explanations: list[BenignExplanation] = Field(default_factory=list)
    facts: dict[str, Any] = Field(default_factory=dict)


def load_ground_truth(path: str | Path) -> GroundTruth:
    return GroundTruth.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))


def consistency_errors(gt: GroundTruth, events: Iterable[TelemetryEvent]) -> list[str]:
    """Check that ground truth refers to real events of its own dataset."""
    by_id = {e.event_id: e for e in events}
    errors: list[str] = []
    if gt.event_count != len(by_id):
        errors.append(f"event_count {gt.event_count} != {len(by_id)} telemetry events")
    if any(e.dataset != gt.dataset for e in by_id.values()):
        errors.append(f"telemetry contains events from a dataset other than {gt.dataset}")
    groups: dict[str, list[str]] = {
        "malicious_event_ids": gt.malicious_event_ids,
        "vendor_alert_event_ids": gt.vendor_alert_event_ids,
        "hostile_content_event_ids": gt.hostile_content_event_ids,
        **{f"attack_chain[{s.stage}]": s.event_ids for s in gt.attack_chain},
        **{f"benign_explanations[{i}]": b.event_ids
           for i, b in enumerate(gt.benign_explanations)},
    }
    for name, ids in groups.items():
        missing = [i for i in ids if i not in by_id]
        if missing:
            errors.append(f"{name}: unknown event ids {missing[:5]}")
        if len(set(ids)) != len(ids):
            errors.append(f"{name}: duplicate event ids")
    malicious = set(gt.malicious_event_ids)
    for step in gt.attack_chain:
        if not step.event_ids:
            errors.append(f"attack_chain[{step.stage}]: no events")
        if not set(step.event_ids) <= malicious:
            errors.append(f"attack_chain[{step.stage}]: cites non-malicious events")
    if gt.verdict == "false_positive" and (malicious or gt.attack_chain):
        errors.append("a false positive has no malicious events or attack chain")
    for i in gt.vendor_alert_event_ids:
        if i in by_id and by_id[i].category.value != "alert":
            errors.append(f"vendor alert {i} is not an alert event")
    for b in gt.benign_explanations:
        if set(b.event_ids) & malicious:
            errors.append("benign explanation covers malicious events")
    return errors
