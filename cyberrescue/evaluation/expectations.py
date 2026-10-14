"""Evaluation-only interpretation of detection output.

* ``STAGE_TYPES`` — which detection ``finding_type``s are a *type match* for a
  ground-truth attack-chain stage. Used only for the secondary "type agreement"
  column; stage coverage itself is decided by evidence overlap.
* ``FACT_EXTRACTORS`` — derive the value of a ground-truth ``facts`` key from a
  detection report, so the facts can be checked. Keys without an extractor are
  reported as "not evaluated", never silently passed.
* ``CASE_FACT_EXTRACTORS`` - facts derived from a ``ScenarioRun``'s
  investigation results (scope, gaps) rather than the detection report.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cyberrescue.detection.model import DetectionReport

STAGE_TYPES: dict[str, set[str]] = {
    "initial_access": {"execution"},
    "execution": {"execution", "persistence"},
    "persistence": {"persistence"},
    "inhibit_recovery": {"recovery_inhibition"},
    "command_and_control": {"command_and_control", "beaconing"},
    "lateral_movement_attempt": {"lateral_movement", "credential_access"},
    "impact": {"impact"},
}


def _det(rep: DetectionReport, rule_id: str):
    return [d for d in rep.detections if d.rule_id == rule_id]


def _first(rep, rule_id, key, default=None):
    ds = _det(rep, rule_id)
    return ds[0].entities.get(key, default) if ds else default


def _c2(rep, kind: str) -> list[str]:
    return sorted({d.entities["indicator"] for d in _det(rep, "IOC-002")
                   if d.entities.get("indicator_type") == kind})


def _outcomes(rep) -> set[str]:
    return {d.entities.get("outcome") for d in _det(rep, "IOC-002")}


def _net(rep) -> list:
    return [*_det(rep, "NET-001"), *(o for o in rep.observations if o.rule_id == "NET-001")]


def _pii(rep, classes) -> bool:
    return any("customer_pii" in classes.get(d.primary_host or "", [])
               for d in rep.detections)


FactExtractor = Callable[[DetectionReport, dict[str, list[str]]], Any]

FACT_EXTRACTORS: dict[str, FactExtractor] = {
    "patient_zero": lambda r, c: _first(r, "CORR-001", "host"),
    "compromised_hosts": lambda r, c: sorted({d.primary_host for d in _det(r, "CORR-001")}),
    "malware_sha256": lambda r, c: _first(r, "IOC-001", "indicator"),
    "malware_family": lambda r, c: _first(r, "IOC-001", "malware_family"),
    "malware_path": lambda r, c: _first(r, "PROC-001", "executable"),
    "abused_account": lambda r, c: _first(r, "LAT-001", "user"),
    "c2_ips": lambda r, c: _c2(r, "ip"),
    "c2_domains": lambda r, c: _c2(r, "domain"),
    "c2_contact": lambda r, c: "established" in _outcomes(r),
    "c2_blocked_by_proxy": lambda r, c: _outcomes(r) == {"blocked"},
    "lateral_auth_targets": lambda r, c: _first(r, "LAT-001", "destinations", []),
    "lateral_auth_succeeded": lambda r, c: _first(r, "LAT-001", "succeeded_hosts", []),
    "lateral_movement_attempted": lambda r, c: bool(_det(r, "LAT-001")),
    "encryption_observed": lambda r, c: bool(_det(r, "RANSOM-001")),
    "encrypted_extension": lambda r, c: ("." + _first(r, "RANSOM-001", "extension"))
    if _det(r, "RANSOM-001") else None,
    "ransom_note": lambda r, c: _first(r, "RANSOM-001", "ransom_note"),
    "shadow_copies_deleted": lambda r, c: bool(_det(r, "RECOV-001")),
    "pii_host_affected": _pii,
    "malware_observed": lambda r, c: bool(_det(r, "IOC-001") or _det(r, "PROC-001")),
    "suspicious_file_changes": lambda r, c: bool(_det(r, "RANSOM-001")),
    "credential_activity": lambda r, c: any(d.finding_type in ("credential_access",
                                                                "lateral_movement")
                                            for d in r.detections),
    "beacon_destinations": lambda r, c: sorted(
        x.entities.get("allowlisted_as") or x.entities["destination_ip"] for x in _net(r)),
    "destinations_allowlisted": lambda r, c: bool(_net(r)) and all(
        getattr(x, "kind", None) == "suppressed" for x in _net(r)),
    "beacon_period_seconds": lambda r, c: sorted(x.entities["period_seconds"]
                                                 for x in _net(r)),
    "initial_vector": lambda r, c: "phishing_attachment" if any(
        cond.id == "delivery_context" and cond.matched
        for d in _det(r, "CORR-001") for cond in d.conditions) else None,
}


# Facts that need the investigation layer (scope + gaps), not just the report.
# Phase 3 (Q6): lateral code execution is "observed" only if some accessed host
# lacks a G1 gap, i.e. activity by the account there IS in the evidence.
def _lateral_code_execution(run) -> bool:
    from cyberrescue.evaluation.investigation import lateral_code_execution_observed
    return lateral_code_execution_observed(run.accessed_hosts, list(run.gaps))


CASE_FACT_EXTRACTORS: dict[str, Callable[[Any], Any]] = {
    "lateral_code_execution_observed": _lateral_code_execution,
}
