"""Layer-2 correlation over Layer-1 detections.

CORR-001 (host chain): >= 3 distinct finding types attributed to one host whose
detections start within 60 minutes. Attribution is each detection's
``primary_host`` — for lateral movement, the SOURCE host. The chain cites the
union of its members' evidence; a delivered e-mail with an archive attachment
to one of the chain's users in the 30 minutes before is cited as context.
Data: Scenario A's stages span 6 m 12 s, Scenario C's 6 m 34 s.

ALERT-001: a vendor alert that no detection cites (as support or context) is
reported as an *uncorroborated alert* Observation — alerts are evidence, never
findings on their own.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from cyberrescue.detection.context import EvidenceView
from cyberrescue.detection.matchers import ARCHIVE_EXTENSIONS, safe_token
from cyberrescue.detection.model import (
    ConditionResult,
    ConditionSpec,
    Detection,
    RuleSpec,
    Window,
    max_severity,
)
from cyberrescue.detection.registry import Correlator

DELIVERY_LOOKBACK = timedelta(minutes=30)


def _start(d: Detection) -> datetime:
    return datetime.fromisoformat(d.window.start)


class HostChain(Correlator):
    MIN_TYPES = 3
    spec = RuleSpec(
        rule_id="CORR-001", version=1, name="Multi-stage activity on one host",
        description=">=3 distinct detection types attributed to one host within 60 minutes "
                    "(lateral movement is attributed to its source host).",
        finding_type="multi_stage", severity="high", base_confidence="medium",
        window=Window(name="host_chain", seconds=3600),
        conditions=(
            ConditionSpec(id="multiple_stages_same_host", role="required",
                          description=">=3 distinct finding types on one host in the window"),
            ConditionSpec(id="delivery_context", role="corroborating",
                          description="an archive attachment was delivered to a chain user "
                                      "in the 30 minutes before (context)")))

    def correlate(self, view: EvidenceView, detections: list[Detection]) -> list:
        by_host: dict[str, list[Detection]] = defaultdict(list)
        for d in detections:
            if d.primary_host and d.finding_type != "multi_stage":
                by_host[d.primary_host].append(d)
        out = []
        for host, ds in sorted(by_host.items()):
            ds.sort(key=lambda d: (d.window.start, d.rule_id, d.detection_id))
            i = 0
            while i < len(ds):
                group = [d for d in ds[i:] if self.within(_start(ds[i]), _start(d))]
                if len({d.finding_type for d in group}) < self.MIN_TYPES:
                    i += 1
                    continue
                out.append(self._chain(view, host, group))
                i += len(group)
        return out

    def _chain(self, view: EvidenceView, host: str, group: list[Detection]) -> Detection:
        types = sorted({d.finding_type for d in group})
        users = sorted({str(d.entities["user"]).lower() for d in group
                        if d.entities.get("user")})
        first = min(_start(d) for d in group)
        mails = [m for m in view.of_type("message_delivered")
                 if (m.user or "").lower() in users and first - DELIVERY_LOOKBACK <= m.at <= first
                 and any(a.lower().rsplit(".", 1)[-1] in ARCHIVE_EXTENSIONS
                         for a in m.strings("email.attachments.file.name"))]
        conf = "high" if len(types) >= self.MIN_TYPES + 1 else "medium"
        supporting = [i for d in group for i in d.supporting_evidence_ids]
        return self.result(
            view, key=[host, group[0].detection_id],
            matched={
                "multiple_stages_same_host": ConditionResult(
                    id="multiple_stages_same_host", matched=True,
                    detail={"finding_types": types,
                            "members": [d.detection_id for d in group]}),
                "delivery_context": ConditionResult(
                    id="delivery_context", matched=bool(mails),
                    evidence_ids=tuple(m.id for m in mails))},
            supporting=supporting,
            context=[*(i for d in group for i in d.context_evidence_ids),
                     *(m.id for m in mails)],
            primary_host=host, severity=max_severity([d.severity for d in group]),
            confidence=conf,
            confidence_basis=f"{len(types)} distinct stages (>= {self.MIN_TYPES + 1} -> high, "
                             f"{self.MIN_TYPES} -> medium)",
            entities={"host": host, "stages": types, "users": users,
                      "members": [{"rule_id": d.rule_id, "detection_id": d.detection_id,
                                   "finding_type": d.finding_type} for d in group]},
            summary=f"{len(types)} correlated stages on {safe_token(host)}: "
                    f"{', '.join(types)}.")


class UncorroboratedAlert(Correlator):
    spec = RuleSpec(
        rule_id="ALERT-001", version=1, name="Uncorroborated vendor alert",
        description="A vendor (EDR/IDS) alert that no detection cites. Reported as an "
                    "Observation only: an alert is a sensor's opinion, not a finding.",
        finding_type="vendor_alert", severity="low",
        window=Window(name="corroboration", seconds=1800),
        conditions=(ConditionSpec(id="alert_present", role="required",
                                  description="a kind=alert evidence record"),))

    def correlate(self, view: EvidenceView, detections: list[Detection]) -> list:
        cited = {i for d in detections
                 for i in (*d.supporting_evidence_ids, *d.context_evidence_ids)}
        return [self.observation(
            view, kind="uncorroborated_alert", key=[a.id], primary_host=a.host,
            evidence_ids=[a.id],
            entities={"host": a.host, "alert": a.s("rule.name"), "event_type": a.event_type},
            reason=f"vendor alert {safe_token(a.s('rule.name'))} on {safe_token(a.host)} is "
                   "not corroborated by any detection - evidence, not a finding")
            for a in view.of_kind("alert") if a.id not in cited]
