"""CyberRescue Telemetry — synthetic security telemetry and its Evidence adapter.

Phase 2B connects telemetry to the Phase 2A Evidence Core without widening
any trust boundary:

    Synthetic telemetry (TelemetryEvent, JSONL)
        -> adapter.to_envelope            (pure, field mapping only)
        -> EvidenceEnvelope               (Phase 2A input shape, unchanged)
        -> CoreService.ingest_evidence_batch
        -> Evidence store                 (sealed, immutable, audited)

Telemetry is *data*. Nothing in this package can create an approval or
sign-off, register or modify an actor, change incident state, alter policy,
authorize an action or reach the Commander gate. An EDR or IDS vendor alert
is ordinary telemetry (``category = "alert"``): it never becomes a finding.

Each scenario's **ground truth** is evaluation-only. It lives in a separate
file with a separate model (``ground_truth.py``), the adapter and importer
never read it, and the telemetry schema cannot carry labels.
"""

from cyberrescue.telemetry.adapter import (
    ADAPTER_VERSION,
    load_telemetry_jsonl,
    to_envelope,
    to_envelopes,
)
from cyberrescue.telemetry.schema import TELEMETRY_SCHEMA, TelemetryError, TelemetryEvent

__all__ = [
    "ADAPTER_VERSION",
    "TELEMETRY_SCHEMA",
    "TelemetryError",
    "TelemetryEvent",
    "load_telemetry_jsonl",
    "to_envelope",
    "to_envelopes",
]
