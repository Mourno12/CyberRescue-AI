"""Data exfiltration from a sensitive asset.

A finding needs a large transfer (>= 50 MB within 15 minutes) from an asset
holding customer PII, financial data or credentials to an EXTERNAL
destination. The 50 MB threshold is a policy assumption: the Phase 2B scenarios
contain no exfiltration (decision D1 = a), only a legitimate ~115 MB/min backup
to an INTERNAL vault and a 48 KB C2 session, both of which must not fire.

A database dump followed by a small external transfer is a partial chain and
yields an Observation, never a finding.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from cyberrescue.detection.context import Ev, EvidenceView
from cyberrescue.detection.matchers import (
    DB_DUMP_TOOLS,
    SENSITIVE_DATA_CLASSES,
    basename,
    is_external,
    normalize_ip,
    safe_token,
)
from cyberrescue.detection.model import ConditionResult, ConditionSpec, RuleSpec, Window
from cyberrescue.detection.registry import Rule

MIN_BYTES = 50 * 1024 * 1024
DUMP_LOOKBACK = timedelta(hours=1)


class SensitiveAssetExfiltration(Rule):
    spec = RuleSpec(
        rule_id="DATA-001", version=1, name="Large external transfer from a sensitive asset",
        description=">= 50 MB sent within 15 minutes from an asset holding customer PII, "
                    "financial data or credentials to one external destination; "
                    "corroborated by a database dump on that host in the hour before.",
        finding_type="exfiltration", severity="critical", base_confidence="medium",
        window=Window(name="exfiltration", seconds=900),
        conditions=(
            ConditionSpec(id="sensitive_asset", role="required",
                          description="the source host's inventory data classes include "
                                      "customer_pii, financial or credentials"),
            ConditionSpec(id="large_external_transfer", role="required",
                          description=">= 50 MB to one external destination in the window"),
            ConditionSpec(id="database_dump_before", role="corroborating",
                          description="a database dump tool ran on the host in the hour "
                                      "before")))

    def evaluate(self, view: EvidenceView) -> list:
        out = []
        for host in sorted({e.host for e in view.of_type("flow") if e.host}):
            classes = sorted(set(view.assets.data_classes(host)) & SENSITIVE_DATA_CLASSES)
            if not classes:
                continue
            flows: dict[str, list[Ev]] = defaultdict(list)
            for f in view.of_type("flow"):
                dst = normalize_ip(f.s("destination.ip"))
                if f.host == host and dst and is_external(dst):
                    flows[dst].append(f)
            dumps = [p for p in view.of_type("process_start") if p.host == host
                     and basename(p.s("process.executable") or "").lower() in DB_DUMP_TOOLS]
            fired = False
            for dst, fs in sorted(flows.items()):
                for i, first in enumerate(fs):
                    window = [f for f in fs[i:] if self.within(first.at, f.at)]
                    total = sum(f.i("source.bytes") or 0 for f in window)
                    if total < MIN_BYTES:
                        continue
                    before = [p for p in dumps if first.at - DUMP_LOOKBACK <= p.at <= first.at]
                    out.append(self.result(
                        view, key=[host, dst, first.id],
                        matched={
                            "sensitive_asset": ConditionResult(
                                id="sensitive_asset", matched=True,
                                detail={"data_classes": classes}),
                            "large_external_transfer": ConditionResult(
                                id="large_external_transfer", matched=True,
                                evidence_ids=tuple(f.id for f in window),
                                detail={"bytes": total, "destination": dst}),
                            "database_dump_before": ConditionResult(
                                id="database_dump_before", matched=bool(before),
                                evidence_ids=tuple(p.id for p in before))},
                        supporting=[*(p.id for p in before), *(f.id for f in window)],
                        primary_host=host,
                        entities={"host": host, "destination_ip": dst, "bytes": total,
                                  "data_classes": classes},
                        summary=f"{safe_token(host)} ({', '.join(classes)}) sent {total} bytes "
                                f"to external {safe_token(dst)} within 15 minutes."))
                    fired = True
                    break
            if not fired:
                out += self._partial(view, host, classes, dumps, flows)
        return out

    def _partial(self, view, host, classes, dumps, flows) -> list:
        out = []
        for p in dumps:
            later = [f for fs in flows.values() for f in fs
                     if p.at <= f.at <= p.at + DUMP_LOOKBACK]
            if not later:
                continue
            total = sum(f.i("source.bytes") or 0 for f in later)
            out.append(self.observation(
                view, kind="partial_match", key=[host, p.id], primary_host=host,
                evidence_ids=[p.id, *(f.id for f in later)],
                entities={"host": host, "data_classes": classes, "external_bytes": total,
                          "destinations": sorted({f.s("destination.ip") or "?"
                                                  for f in later})},
                reason=f"database dump on sensitive asset {host} followed by only {total} "
                       f"bytes to external destinations within an hour (< {MIN_BYTES} "
                       "bytes) - incomplete exfiltration chain, not a finding"))
        return out
