"""Join a detection report with ground truth and compute per-scenario metrics.

Definitions (supporting evidence only, unless stated):

* stage detected   — >= 1 finding's supporting evidence overlaps the stage's events
* expected finding — its supporting evidence includes >= 1 malicious event
* unexpected       — its supporting evidence includes NO malicious event
* evidence coverage  (per stage) — stage events cited as support / stage events
* evidence precision (per finding) — malicious supporting / all supporting
* fact check       — ground-truth ``facts`` vs the value derived from the report

Ratios are kept as integer pairs, so results are exact and deterministic.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from cyberrescue.evaluation.expectations import (
    CASE_FACT_EXTRACTORS,
    FACT_EXTRACTORS,
    STAGE_TYPES,
)
from cyberrescue.evaluation.harness import ScenarioRun


@dataclass(frozen=True)
class StageResult:
    stage: str
    events: int
    supported: int
    context_only: int
    detected: bool
    rules: list[str]
    type_agreement: bool


@dataclass(frozen=True)
class FindingResult:
    rule_id: str
    detection_id: str
    finding_type: str
    severity: str
    confidence: str
    supporting: int
    malicious_supporting: int
    expected: bool


@dataclass(frozen=True)
class FactResult:
    fact: str
    expected: Any
    observed: Any
    status: str                     # match | mismatch | not_evaluated


@dataclass
class ScenarioEvaluation:
    scenario: str
    incident_id: str
    verdict: str
    events: int
    malicious_events: int
    malicious_supported: int
    malicious_cited_any: int
    findings: list[FindingResult] = field(default_factory=list)
    unexpected_findings: list[str] = field(default_factory=list)
    stages: list[StageResult] = field(default_factory=list)
    missed_stages: list[str] = field(default_factory=list)
    observations: list[tuple[str, str]] = field(default_factory=list)
    facts: list[FactResult] = field(default_factory=list)
    rule_matrix: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def evaluate(run: ScenarioRun) -> ScenarioEvaluation:
    gt, rep, refs = run.ground_truth, run.report, run.source_refs
    malicious = set(gt.malicious_event_ids)
    sup_of = {d.detection_id: {refs[i] for i in d.supporting_evidence_ids}
              for d in rep.detections}
    ctx_of = {d.detection_id: {refs[i] for i in d.context_evidence_ids}
              for d in rep.detections}
    supported = set().union(*sup_of.values()) if sup_of else set()
    cited = supported | (set().union(*ctx_of.values()) if ctx_of else set())

    ev = ScenarioEvaluation(
        scenario=gt.scenario, incident_id=gt.incident_id, verdict=gt.verdict,
        events=gt.event_count, malicious_events=len(malicious),
        malicious_supported=len(supported & malicious),
        malicious_cited_any=len(cited & malicious))
    for d in rep.detections:
        n_mal = len(sup_of[d.detection_id] & malicious)
        ev.findings.append(FindingResult(
            rule_id=d.rule_id, detection_id=d.detection_id, finding_type=d.finding_type,
            severity=d.severity, confidence=d.confidence,
            supporting=len(sup_of[d.detection_id]), malicious_supporting=n_mal,
            expected=n_mal > 0))
        if n_mal == 0:
            ev.unexpected_findings.append(d.rule_id)
        ev.rule_matrix[d.rule_id] = ev.rule_matrix.get(d.rule_id, 0) + 1
    for step in gt.attack_chain:
        ids = set(step.event_ids)
        hits = [d for d in rep.detections if sup_of[d.detection_id] & ids]
        ctx_only = (set().union(*ctx_of.values()) if ctx_of else set()) & ids - supported
        detected = bool(hits)
        ev.stages.append(StageResult(
            stage=step.stage, events=len(ids), supported=len(supported & ids),
            context_only=len(ctx_only), detected=detected,
            rules=sorted({d.rule_id for d in hits}),
            type_agreement=any(d.finding_type in STAGE_TYPES.get(step.stage, set())
                               for d in hits)))
        if not detected:
            ev.missed_stages.append(step.stage)
    ev.observations = sorted((o.rule_id, o.kind) for o in rep.observations)
    for name, expected in sorted(gt.facts.items()):
        extractor = FACT_EXTRACTORS.get(name)
        if extractor is not None:
            observed = extractor(rep, run.data_classes)
        elif name in CASE_FACT_EXTRACTORS:
            observed = CASE_FACT_EXTRACTORS[name](run)
        else:
            ev.facts.append(FactResult(name, expected, None, "not_evaluated"))
            continue
        ev.facts.append(FactResult(name, expected, observed,
                                   "match" if observed == expected else "mismatch"))
    return ev
