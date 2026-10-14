"""Telemetry -> Evidence adapter (pure field mapping).

    TelemetryEvent            EvidenceEnvelope (Phase 2A)
    ------------------------  ------------------------------------------
    provenance.dataset.sensor source       e.g. synthetic.scenario-a.edr
    event_id                  source_ref
    category                  kind
    action                    event_type
    timestamp                 observed_at
    host, user                host, user   (data only)
    message                   raw          (verbatim)
    fields                    data         (verbatim)
    vendor, sensor, dataset   metadata     (+ adapter / schema versions)
    provenance                provenance

The adapter never binds an incident, never computes hashes and never talks to
the Core: binding comes from the caller's context at ingestion, integrity from
``cyberrescue.core.evidence.prepare_record``. It reads telemetry files only —
never ground truth.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from cyberrescue.core.evidence import EvidenceEnvelope
from cyberrescue.core.models import Provenance
from cyberrescue.telemetry.schema import TELEMETRY_SCHEMA, TelemetryError, TelemetryEvent

ADAPTER_VERSION = "cyberrescue.telemetry.adapter/v1"
MAX_EVENTS_PER_FILE = 50_000


def parse_event(obj: TelemetryEvent | dict[str, Any]) -> TelemetryEvent:
    if isinstance(obj, TelemetryEvent):
        return obj
    if not isinstance(obj, dict):
        raise TelemetryError(f"telemetry must be a JSON object, got {type(obj).__name__}")
    if "evaluation_only" in obj:
        raise TelemetryError("this is evaluation-only ground truth, not telemetry; "
                             "it can never be ingested as evidence")
    try:
        return TelemetryEvent.model_validate(obj)
    except ValidationError as e:
        msgs = "; ".join(f"{'.'.join(str(p) for p in err['loc']) or 'event'}: {err['msg']}"
                         for err in e.errors())
        raise TelemetryError(msgs) from None


def to_envelope(event: TelemetryEvent | dict[str, Any]) -> EvidenceEnvelope:
    """Map one telemetry event onto the Phase 2A evidence envelope."""
    ev = parse_event(event)
    metadata: dict[str, Any] = {
        "adapter": ADAPTER_VERSION,
        "telemetry_schema": TELEMETRY_SCHEMA,
        "dataset": ev.dataset,
        "sensor": ev.sensor,
        "vendor": ev.vendor,
    }
    if ev.provenance == Provenance.SYNTHETIC:
        metadata["provenance_note"] = "SYNTHETIC test data, not real telemetry"
    return EvidenceEnvelope(
        source=f"{ev.provenance.value}.{ev.dataset}.{ev.sensor}",
        source_ref=ev.event_id,
        kind=ev.category,
        event_type=ev.action,
        observed_at=ev.timestamp,
        provenance=ev.provenance,
        host=ev.host,
        user=ev.user,
        raw=ev.message,
        data=dict(ev.fields),
        metadata=metadata,
    )


def to_envelopes(events: Iterable[TelemetryEvent | dict[str, Any]]) -> list[EvidenceEnvelope]:
    """All-or-nothing: raises ``TelemetryError`` listing every bad item."""
    out: list[EvidenceEnvelope] = []
    errors: list[str] = []
    for i, ev in enumerate(events, start=1):
        try:
            out.append(to_envelope(ev))
        except (TelemetryError, ValidationError, ValueError) as e:
            errors.append(f"item {i}: {e}")
    if errors:
        raise TelemetryError("telemetry rejected: " + " | ".join(errors[:20]))
    return out


def load_telemetry_jsonl(path: str | Path) -> list[TelemetryEvent]:
    """One event per line (UTF-8, BOM tolerated, blank lines skipped).
    All-or-nothing: raises ``TelemetryError`` listing every bad line."""
    events: list[TelemetryEvent] = []
    errors: list[str] = []
    seen: set[str] = set()
    text = Path(path).read_text(encoding="utf-8-sig")
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if len(events) >= MAX_EVENTS_PER_FILE:
            raise TelemetryError(f"telemetry file exceeds {MAX_EVENTS_PER_FILE} events")
        try:
            ev = parse_event(json.loads(line))
        except json.JSONDecodeError as e:
            errors.append(f"line {n}: invalid JSON ({e.msg})")
            continue
        except TelemetryError as e:
            errors.append(f"line {n}: {e}")
            continue
        if ev.event_id in seen:
            errors.append(f"line {n}: duplicate event_id {ev.event_id!r}")
        seen.add(ev.event_id)
        events.append(ev)
    if errors:
        shown = errors[:20] + ([f"... {len(errors) - 20} more"] if len(errors) > 20 else [])
        raise TelemetryError("invalid telemetry file: " + " | ".join(shown))
    return events
