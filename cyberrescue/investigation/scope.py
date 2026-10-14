"""Scope: what the evidence shows is affected. A description, never a
recommendation - no actions are proposed.

* compromised - primary host of an execution / persistence / recovery-inhibition /
  impact / multi-stage detection
* accessed    - successful remote authentication (LAT-001 succeeded hosts,
  AUTH-001 targets), not already compromised
* targeted    - remote authentication attempts that never succeeded
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from cyberrescue.core.models import LegalHold
from cyberrescue.detection.context import EvidenceView
from cyberrescue.detection.model import DetectionReport
from cyberrescue.investigation.model import Infrastructure, Scope, untrusted

COMPROMISE_TYPES = frozenset({"execution", "persistence", "recovery_inhibition", "impact",
                              "multi_stage"})


def derive_scope(view: EvidenceView, report: DetectionReport,
                 holds: Iterable[LegalHold] = ()) -> Scope:
    basis: dict[str, set[str]] = defaultdict(set)
    compromised: set[str] = set()
    accessed: set[str] = set()
    targeted: set[str] = set()
    accounts: set[str] = set()
    infra: dict[tuple[str, str], dict] = {}
    for d in report.detections:
        ent = d.entities
        if d.finding_type in COMPROMISE_TYPES and d.primary_host:
            compromised.add(d.primary_host)
            basis[d.primary_host].add(d.rule_id)
        if d.rule_id == "LAT-001":
            for h in ent.get("succeeded_hosts", []):
                accessed.add(h)
                basis[h].add(d.rule_id)
            for h in ent.get("failed_only_hosts", []):
                targeted.add(h)
                basis[h].add(d.rule_id)
        elif d.rule_id == "AUTH-001":
            accessed.add(ent["target_host"])
            basis[ent["target_host"]].add(d.rule_id)
        elif d.rule_id == "AUTH-002":
            targeted.add(ent["target_host"])
            basis[ent["target_host"]].add(d.rule_id)
        if ent.get("user"):
            accounts.add(str(ent["user"]).lower())
        if d.rule_id == "IOC-002":
            key = (ent["indicator"], ent["indicator_type"])
            item = infra.setdefault(key, {"outcomes": set(), "hosts": set(),
                                          "family": ent.get("malware_family", "")})
            item["outcomes"].add(ent["outcome"])
            item["hosts"].add(d.primary_host)
    accessed -= compromised
    targeted -= compromised | accessed
    in_scope = compromised | accessed | targeted
    classes = sorted({c for h in compromised | accessed for c in view.assets.data_classes(h)})
    held = sorted({h.asset_id for h in holds if h.asset_id in in_scope})
    return Scope(
        compromised_hosts=tuple(sorted(compromised)), accessed_hosts=tuple(sorted(accessed)),
        targeted_hosts=tuple(sorted(targeted)),
        accounts=tuple(untrusted(a) for a in sorted(accounts)),
        infrastructure=tuple(Infrastructure(
            indicator=k[0], type=k[1], malware_family=v["family"],
            outcome="established" if "established" in v["outcomes"] else
            "blocked" if "blocked" in v["outcomes"] else "attempted",
            hosts=tuple(sorted(v["hosts"]))) for k, v in sorted(infra.items())),
        data_classes_at_risk=tuple(classes), hosts_under_hold=tuple(held),
        basis={h: tuple(sorted(r)) for h, r in sorted(basis.items()) if h in in_scope})
