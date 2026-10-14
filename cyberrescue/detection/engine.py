"""The detection engine: rules (Layer 1), then correlators (Layer 2).

``DetectionEngine.run`` is a pure function of the view: no I/O, no clock, no
randomness. Results are stamped with the registry version and sorted by
(window start, rule id, id), so identical evidence gives a byte-identical
``DetectionReport.to_json()``. ``load_view`` / ``detect`` read the Core
(evidence, assets) and the mock IOC database — and nothing else.
"""

from __future__ import annotations

from cyberrescue.detection.context import AssetContext, EvidenceView, ThreatIntel
from cyberrescue.detection.model import Detection, DetectionReport, Observation
from cyberrescue.detection.registry import RuleRegistry, default_registry


class DetectionEngine:
    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self.registry = registry or default_registry()

    def run(self, view: EvidenceView) -> DetectionReport:
        version = self.registry.version
        detections: list[Detection] = []
        observations: list[Observation] = []

        def take(results) -> None:
            for r in results:
                if isinstance(r, Detection):
                    detections.append(r)
                elif isinstance(r, Observation):
                    observations.append(r)
                else:
                    raise TypeError(f"rule returned {type(r).__name__}")

        for rule in self.registry.rules():
            take(rule.evaluate(view))
        for correlator in self.registry.correlators():
            take(correlator.correlate(view, list(detections)))

        ids = [d.detection_id for d in detections]
        if len(set(ids)) != len(ids):
            raise RuntimeError("duplicate detection ids in one run")
        detections = sorted((d.model_copy(update={"ruleset_version": version})
                             for d in detections),
                            key=lambda d: (d.window.start, d.rule_id, d.detection_id))
        observations = sorted((o.model_copy(update={"ruleset_version": version})
                               for o in observations),
                              key=lambda o: (view.get(o.evidence_ids[0]).observed_at,
                                             o.rule_id, o.observation_id))
        return DetectionReport(
            incident_id=view.incident_id, ruleset_version=version,
            inputs={"evidence_count": len(view.events),
                    "evidence_fingerprint": view.fingerprint,
                    "threat_intel_sha256": view.intel.fingerprint,
                    "unresolved_addresses": view.addresses.ambiguous()},
            detections=tuple(detections), observations=tuple(observations))


def load_view(svc, incident_ref: str, *, intel: ThreatIntel | None = None) -> EvidenceView:
    """The incident's evidence as stored in the Core (binding from the Core row)."""
    from cyberrescue.core.service import CoreError
    iid = svc.store.resolve_incident(incident_ref)
    if iid is None:
        raise CoreError(f"no Core incident for {incident_ref!r}")
    return EvidenceView(iid, svc.list_evidence(iid), intel=intel or ThreatIntel.from_mock(),
                        assets=AssetContext(svc.store.list_assets()))


def detect(svc, incident_ref: str, *, registry: RuleRegistry | None = None,
           intel: ThreatIntel | None = None) -> DetectionReport:
    """Dry run: read the incident's evidence and return the report. Writes nothing."""
    return DetectionEngine(registry).run(load_view(svc, incident_ref, intel=intel))
