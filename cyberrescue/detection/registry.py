"""Rules, correlators and the registry that versions them.

A rule is a class with a declarative ``RuleSpec`` and an ``evaluate(view)``
method. ``Rule.result`` is the single place where a rule's condition results
become a ``Detection`` (all required matched, enough corroboration) or an
``Observation`` (not enough corroboration): every rule follows the same
explainability and confidence policy.

The registry rejects duplicate rule ids and frozen-registry mutation; its
``version`` fingerprints every spec, so any rule change is visible in results.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any, ClassVar

from cyberrescue.core.audit import canonical_json
from cyberrescue.detection.context import EvidenceView
from cyberrescue.detection.model import (
    RULESET_SCHEMA,
    ConditionResult,
    Detection,
    Observation,
    ObservationKind,
    RuleSpec,
    WindowSpan,
    digest,
    raise_confidence,
)


def _iso(at: datetime) -> str:
    return at.isoformat()


class Rule(ABC):
    """Base class for Layer-1 rules (evidence -> detections/observations)."""

    spec: ClassVar[RuleSpec]

    @abstractmethod
    def evaluate(self, view: EvidenceView) -> list[Detection | Observation]:
        ...

    # --- helpers shared by every rule ------------------------------------------
    def conditions(self, matched: Mapping[str, ConditionResult]) -> tuple[ConditionResult, ...]:
        """Every declared condition, in declaration order (unmatched if absent)."""
        unknown = set(matched) - {c.id for c in self.spec.conditions}
        if unknown:
            raise ValueError(f"{self.spec.rule_id}: undeclared conditions {sorted(unknown)}")
        return tuple(matched.get(c.id) or ConditionResult(id=c.id, matched=False)
                     for c in self.spec.conditions)

    def span(self, view: EvidenceView, ids: Iterable[str]) -> WindowSpan:
        times = [view.get(i).at for i in ids]
        start = min(times)
        return WindowSpan(name=self.spec.window.name, seconds=self.spec.window.seconds,
                          start=_iso(start), end=_iso(max(times)))

    def within(self, start: datetime, at: datetime) -> bool:
        return start <= at <= start + timedelta(seconds=self.spec.window.seconds)

    def observation(self, view: EvidenceView, *, kind: ObservationKind, key: Any,
                    reason: str, evidence_ids: Iterable[str], primary_host: str | None = None,
                    entities: dict[str, Any] | None = None,
                    matched: Mapping[str, ConditionResult] | None = None) -> Observation:
        ids = view.ordered(evidence_ids)
        if not ids:
            raise ValueError(f"{self.spec.rule_id}: an observation needs evidence")
        return Observation(
            observation_id="OBS-" + digest(self.spec.rule_id, str(self.spec.version),
                                           view.incident_id, kind, canonical_json(key))[:24],
            rule_id=self.spec.rule_id, rule_version=self.spec.version, kind=kind,
            incident_id=view.incident_id, primary_host=primary_host, reason=reason,
            entities=entities or {}, evidence_ids=ids,
            conditions=self.conditions(matched) if matched is not None else ())

    def result(self, view: EvidenceView, *, key: Any, matched: Mapping[str, ConditionResult],
               supporting: Iterable[str], context: Iterable[str] = (),
               primary_host: str | None, entities: dict[str, Any], summary: str,
               severity: str | None = None, confidence: str | None = None,
               confidence_basis: str | None = None) -> Detection | Observation:
        """Build the result for one candidate whose required conditions are given."""
        spec = self.spec
        conds = self.conditions(matched)
        by_id = {c.id: c for c in conds}
        missing = [c for c in spec.required if not by_id[c].matched]
        if missing:
            raise ValueError(f"{spec.rule_id}: required conditions not met: {missing}")
        corroborated = [c for c in spec.corroborating if by_id[c].matched]
        sup = view.ordered(supporting)
        ctx = tuple(i for i in view.ordered(context) if i not in set(sup))
        if len(corroborated) < spec.min_corroboration:
            return self.observation(
                view, kind="partial_match", key=key, primary_host=primary_host,
                entities=entities, matched=matched, evidence_ids=(*sup, *ctx),
                reason=f"{spec.rule_id}: required conditions met but only "
                       f"{len(corroborated)}/{spec.min_corroboration} corroborating "
                       "condition(s) matched - not a finding")
        if confidence is None:
            confidence = raise_confidence(spec.base_confidence, len(corroborated))
            confidence_basis = (f"base {spec.base_confidence} + {len(corroborated)}/"
                                f"{len(spec.corroborating)} corroborating "
                                f"({', '.join(corroborated) or 'none'}) -> {confidence}")
        return Detection(
            detection_id="DET-" + digest(spec.rule_id, str(spec.version), view.incident_id,
                                         *sup)[:24],
            detection_key="DK-" + digest(spec.rule_id, view.incident_id,
                                         canonical_json(key))[:24],
            rule_id=spec.rule_id, rule_version=spec.version,
            finding_type=spec.finding_type, severity=severity or spec.severity,
            confidence=confidence, confidence_basis=confidence_basis or "",
            incident_id=view.incident_id, primary_host=primary_host, entities=entities,
            window=self.span(view, sup), conditions=conds, supporting_evidence_ids=sup,
            context_evidence_ids=ctx, summary=summary)


class Correlator(Rule):
    """Layer-2 rule: consumes Layer-1 detections (and the view)."""

    def evaluate(self, view: EvidenceView) -> list[Detection | Observation]:
        return []

    @abstractmethod
    def correlate(self, view: EvidenceView,
                  detections: list[Detection]) -> list[Detection | Observation]:
        ...


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}
        self._frozen = False

    def register(self, rule: Rule) -> Rule:
        if self._frozen:
            raise RuntimeError("registry is frozen")
        if not isinstance(rule, Rule):
            raise TypeError(f"not a Rule: {rule!r}")
        spec = getattr(type(rule), "spec", None)
        if not isinstance(spec, RuleSpec):
            raise TypeError(f"{type(rule).__name__} has no RuleSpec")
        if spec.rule_id in self._rules:
            raise ValueError(f"duplicate rule id {spec.rule_id}")
        self._rules[spec.rule_id] = rule
        return rule

    def freeze(self) -> RuleRegistry:
        self._frozen = True
        return self

    def get(self, rule_id: str) -> Rule:
        return self._rules[rule_id]

    def rules(self) -> tuple[Rule, ...]:
        return tuple(r for _, r in sorted(self._rules.items())
                     if not isinstance(r, Correlator))

    def correlators(self) -> tuple[Correlator, ...]:
        return tuple(r for _, r in sorted(self._rules.items()) if isinstance(r, Correlator))

    def specs(self) -> list[RuleSpec]:
        return [r.spec for _, r in sorted(self._rules.items())]

    @property
    def version(self) -> str:
        specs = canonical_json([s.model_dump(mode="json") for s in self.specs()])
        return f"{RULESET_SCHEMA}+{hashlib.sha256(specs.encode()).hexdigest()[:16]}"


def default_registry() -> RuleRegistry:
    """A fresh, frozen registry holding every shipped rule."""
    from cyberrescue.detection.rules import ALL_RULES
    reg = RuleRegistry()
    for cls in ALL_RULES:
        reg.register(cls())
    return reg.freeze()
