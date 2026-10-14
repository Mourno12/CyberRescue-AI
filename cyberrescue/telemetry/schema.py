"""The telemetry record: one vendor-neutral shape for synthetic sensor events.

A ``TelemetryEvent`` is what a sensor (EDR, Sysmon, Windows Security log,
NetFlow, DNS, proxy, IDS, mail gateway, web server) *observed*. It is the
input to the Evidence adapter and nothing else:

    event_id   record id within its dataset (-> evidence ``source_ref``)
    dataset    dataset slug, e.g. ``scenario-a`` (-> part of evidence ``source``)
    timestamp  ISO-8601 with timezone, normalised to UTC
    sensor     sensor type, e.g. ``edr``, ``winevt-security``, ``netflow``
    vendor     product name as reported (data only)
    category   process | file | network | auth | log | alert | ioc | other
    action     sensor-specific event type, e.g. ``process_start``, ``4625``
    host/user  data only — never actors, never an incident binding
    message    the raw line exactly as the sensor emitted it
    fields     normalised ECS-style fields (``source.ip``, ``process.name``)

Like the Phase 2A envelope, the model **forbids extra fields**: an event can
never carry an incident id, evidence id, hashes or ingestion metadata. It also
refuses evaluation-label keys anywhere in ``fields``, so ground truth cannot be
smuggled into operational telemetry.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cyberrescue.core.evidence import (
    MAX_EVENT_TYPE_CHARS,
    MAX_FIELD_CHARS,
    MAX_RAW_BYTES,
    _check_plain_json,
    normalize_timestamp,
)
from cyberrescue.core.models import EvidenceKind, Provenance

TELEMETRY_SCHEMA = "cyberrescue.telemetry/v1"
MAX_VENDOR_CHARS = 64
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")
_EVENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")

# Keys that belong to evaluation ground truth, never to observed telemetry.
# Matched case-insensitively against every dotted segment of every key in
# ``fields`` (at any nesting depth).
LABEL_KEYS = frozenset({"ground_truth", "groundtruth", "gt", "label", "labels",
                        "is_malicious", "attack_stage", "evaluation_only"})


class TelemetryError(ValueError):
    """Invalid telemetry input (validation, size, format)."""


def _label_keys(value: Any, path: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            here = f"{path}.{k}" if path else str(k)
            if any(seg.lower() in LABEL_KEYS for seg in str(k).split(".")):
                found.append(here)
            found += _label_keys(v, here)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            found += _label_keys(v, f"{path}[{i}]")
    return found


class TelemetryEvent(BaseModel):
    """One observed sensor event (synthetic in Phase 2B)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    dataset: str
    timestamp: str
    sensor: str
    vendor: str
    category: EvidenceKind
    action: str
    message: str
    host: str | None = None
    user: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance = Provenance.SYNTHETIC

    @field_validator("event_id")
    @classmethod
    def _event_id(cls, v: str) -> str:
        if not _EVENT_ID_RE.match(v):
            raise ValueError("event_id must match ^[a-z0-9][a-z0-9-]{0,63}$")
        return v

    @field_validator("dataset", "sensor")
    @classmethod
    def _slug(cls, v: str) -> str:
        if not _SLUG_RE.match(v):
            raise ValueError("must match ^[a-z0-9][a-z0-9-]{0,23}$")
        return v

    @field_validator("timestamp")
    @classmethod
    def _timestamp(cls, v: str) -> str:
        return normalize_timestamp(v)

    @field_validator("vendor")
    @classmethod
    def _vendor(cls, v: str) -> str:
        if not v.strip() or len(v) > MAX_VENDOR_CHARS:
            raise ValueError(f"vendor must be 1..{MAX_VENDOR_CHARS} characters")
        return v

    @field_validator("action")
    @classmethod
    def _action(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > MAX_EVENT_TYPE_CHARS:
            raise ValueError(f"action must be 1..{MAX_EVENT_TYPE_CHARS} characters")
        return v

    @field_validator("message")
    @classmethod
    def _message(cls, v: str) -> str:
        if not v:
            raise ValueError("message (the raw sensor line) is required")
        if len(v.encode("utf-8")) > MAX_RAW_BYTES:
            raise ValueError(f"message exceeds {MAX_RAW_BYTES} bytes")
        return v

    @field_validator("host", "user")
    @classmethod
    def _short(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if len(v) > MAX_FIELD_CHARS:
            raise ValueError(f"longer than {MAX_FIELD_CHARS} characters")
        return v

    @field_validator("fields")
    @classmethod
    def _fields(cls, v: dict[str, Any]) -> dict[str, Any]:
        _check_plain_json(v, "fields")
        labels = _label_keys(v)
        if labels:
            raise ValueError("evaluation labels are not telemetry; remove "
                             + ", ".join(labels[:5]))
        return v
