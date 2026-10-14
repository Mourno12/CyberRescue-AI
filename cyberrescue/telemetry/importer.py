"""Import telemetry into the Core through the existing Phase 2A evidence path.

    telemetry JSONL -> load_telemetry_jsonl -> to_envelopes
        -> CoreService.ingest_evidence_batch(incident_ref, ..., collector_id)

Nothing here is new authority: the Core still decides who may submit evidence
(registered SYSTEM collectors and human operators only), rejects unknown and
closed incidents, validates, seals and audits every record, and keeps batches
all-or-nothing. Re-importing a dataset is idempotent (content-derived ids).

The incident binding comes from the caller: an explicit ``incident_ref`` for a
file, or the catalogue's scenario -> incident mapping for a scenario. Telemetry
content (``host``, ``fields``, ``message`` ...) is never consulted for it. This
module imports neither the scenario generators nor the ground truth.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cyberrescue.core.service import CoreService
from cyberrescue.telemetry.adapter import load_telemetry_jsonl, to_envelopes
from cyberrescue.telemetry.catalog import scenario_info, telemetry_path
from cyberrescue.telemetry.schema import TelemetryError, TelemetryEvent

AUDIT_SOURCE = "telemetry"


@dataclass(frozen=True)
class TelemetryImportReport:
    incident_id: str
    events: int
    ingested: list[str]
    duplicates: list[str]
    dataset: str | None = None


def import_events(svc: CoreService, incident_ref: str,
                  events: Iterable[TelemetryEvent | dict[str, Any]], *,
                  collector_id: str) -> TelemetryImportReport:
    """Adapt and ingest telemetry events as evidence of ``incident_ref``."""
    envelopes = to_envelopes(events)
    rep = svc.ingest_evidence_batch(incident_ref, envelopes, collector_id=collector_id,
                                    source=AUDIT_SOURCE)
    return TelemetryImportReport(incident_id=rep.incident_id, events=len(envelopes),
                                 ingested=rep.ingested, duplicates=rep.duplicates)


def import_file(svc: CoreService, path: str | Path, incident_ref: str, *,
                collector_id: str) -> TelemetryImportReport:
    return import_events(svc, incident_ref, load_telemetry_jsonl(path),
                         collector_id=collector_id)


def import_scenario(svc: CoreService, key: str, *, collector_id: str,
                    root: str | Path | None = None) -> TelemetryImportReport:
    """Ingest a committed scenario into the incident the catalogue maps it to."""
    info = scenario_info(key)
    events = load_telemetry_jsonl(telemetry_path(info.key, root))
    foreign = sorted({e.dataset for e in events} - {info.dataset})
    if foreign:
        raise TelemetryError(f"scenario {info.key} file contains other datasets: {foreign}")
    rep = import_events(svc, info.incident_alias, events, collector_id=collector_id)
    return TelemetryImportReport(incident_id=rep.incident_id, events=rep.events,
                                 ingested=rep.ingested, duplicates=rep.duplicates,
                                 dataset=info.dataset)
