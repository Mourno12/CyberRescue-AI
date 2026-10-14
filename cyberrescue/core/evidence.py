"""Evidence envelopes: validation, canonicalisation and hashing (pure).

**Evidence** is externally observed security data — a log line, an EDR event,
a network connection, an alert — submitted by a collector or a human
operator. It is distinct from a **finding claim** (a statement an analyst
wrote) and a **finding** (an analytic conclusion that *cites* evidence).

Every source is converted into one ``EvidenceEnvelope`` shape. Future
collectors (Windows Event Log, syslog, firewall, IDS, EDR, threat-intel
indicators) only need to emit envelopes; the Core never learns their formats:

    raw        the original record exactly as received (EVTX XML, a syslog
               line, a firewall line, an alert JSON string ...)
    data       normalised fields (ECS-style dotted keys recommended, e.g.
               "source.ip", "destination.port", "process.name", "file.path")
    kind       coarse category: process | file | network | auth | log |
               alert | ioc | other
    event_type source-specific type (e.g. "4625", "smb_auth", "file_rename")
    source_ref the record's id within its source (EventRecordID, line no.)

An envelope may NOT carry an incident id, an evidence id, hashes, or who
ingested it (``extra="forbid"``): binding and integrity data are assigned by
the Core, never supplied by the data itself.

Integrity (see ``prepare_record``):
    content_sha256 = sha256(raw as UTF-8)                 -> raw is unchanged
    record_sha256  = sha256(canonical_json(SEALED_FIELDS)) -> the row is unchanged
    id = "EV-" + sha256(incident ␟ source ␟ source_ref ␟ content_sha256)[:24]
The id is content-derived, so it is stable and re-ingesting a file is
idempotent. Both hashes are also written into the EVIDENCE_INGESTED audit
event, which the hash-chained audit log protects.

Hashing proves evidence is unchanged SINCE INGESTION. It does not prove the
collector reported the truth (that needs signed source logs — future work).
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, \
    model_validator

from cyberrescue.core.audit import canonical_json
from cyberrescue.core.models import EvidenceKind, Provenance

MAX_RAW_BYTES = 64 * 1024
MAX_STRUCT_BYTES = 64 * 1024
MAX_FIELD_CHARS = 256
MAX_EVENT_TYPE_CHARS = 128
MAX_FUTURE_SKEW = timedelta(hours=24)
ID_PREFIX = "EV-"
_SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")
_SEP = "\x1f"

# Every stored field sealed by record_sha256 (all columns except the hash
# itself and the audit event uid, which is assigned after sealing).
SEALED_FIELDS = (
    "id", "incident_id", "source", "source_ref", "kind", "event_type", "observed_at",
    "ingested_at", "host", "asset_id", "user", "raw", "data", "metadata", "provenance",
    "content_sha256", "ingested_by",
)


class EvidenceError(ValueError):
    """Invalid evidence input (validation, size, time, format)."""


def _check_plain_json(value: Any, what: str) -> None:
    try:
        text = json.dumps(value, allow_nan=False, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"))
    except (TypeError, ValueError) as e:
        raise ValueError(f"{what} must be plain JSON: {e}") from None
    if len(text.encode("utf-8")) > MAX_STRUCT_BYTES:
        raise ValueError(f"{what} exceeds {MAX_STRUCT_BYTES} bytes")


def normalize_timestamp(value: str) -> str:
    """ISO-8601 with an explicit timezone -> canonical UTC ISO string."""
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"not an ISO-8601 timestamp: {value!r}") from None
    if dt.tzinfo is None:
        raise ValueError(f"timestamp must include a timezone: {value!r}")
    return dt.astimezone(timezone.utc).isoformat()


class EvidenceEnvelope(BaseModel):
    """The single input shape for evidence, whatever its source."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str
    source_ref: str = ""
    kind: EvidenceKind
    event_type: str
    observed_at: str
    provenance: Provenance
    host: str | None = None
    user: str | None = None
    raw: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source")
    @classmethod
    def _source(cls, v: str) -> str:
        if not _SOURCE_RE.match(v):
            raise ValueError("source must match ^[a-z0-9][a-z0-9_.:-]{0,63}$")
        return v

    @field_validator("source_ref")
    @classmethod
    def _source_ref(cls, v: str) -> str:
        if len(v) > MAX_FIELD_CHARS:
            raise ValueError(f"source_ref longer than {MAX_FIELD_CHARS} characters")
        return v

    @field_validator("event_type")
    @classmethod
    def _event_type(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > MAX_EVENT_TYPE_CHARS:
            raise ValueError(f"event_type must be 1..{MAX_EVENT_TYPE_CHARS} characters")
        return v

    @field_validator("observed_at")
    @classmethod
    def _observed_at(cls, v: str) -> str:
        return normalize_timestamp(v)

    @field_validator("host", "user")
    @classmethod
    def _short(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if len(v) > MAX_FIELD_CHARS:
            raise ValueError(f"longer than {MAX_FIELD_CHARS} characters")
        return v

    @field_validator("raw")
    @classmethod
    def _raw(cls, v: str | None) -> str | None:
        if v is not None and len(v.encode("utf-8")) > MAX_RAW_BYTES:
            raise ValueError(f"raw exceeds {MAX_RAW_BYTES} bytes")
        return v

    @field_validator("data", "metadata")
    @classmethod
    def _plain(cls, v: dict[str, Any], info) -> dict[str, Any]:
        _check_plain_json(v, info.field_name)
        return v

    @model_validator(mode="after")
    def _content_present(self) -> EvidenceEnvelope:
        if self.raw is None and not self.data:
            raise ValueError("evidence needs 'raw' content or non-empty 'data'")
        return self


def parse_envelope(obj: EvidenceEnvelope | dict[str, Any]) -> EvidenceEnvelope:
    if isinstance(obj, EvidenceEnvelope):
        return obj
    if not isinstance(obj, dict):
        raise EvidenceError(f"evidence must be a JSON object, got {type(obj).__name__}")
    try:
        return EvidenceEnvelope.model_validate(obj)
    except ValidationError as e:
        msgs = "; ".join(f"{'.'.join(str(p) for p in err['loc']) or 'envelope'}: {err['msg']}"
                         for err in e.errors())
        raise EvidenceError(msgs) from None


# --- hashing ---------------------------------------------------------------------

def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def evidence_id(incident_id: str, source: str, source_ref: str, content_sha256: str) -> str:
    digest = sha256_hex(_SEP.join((incident_id, source, source_ref, content_sha256)))
    return ID_PREFIX + digest[:24]


def record_sha256(fields: dict[str, Any]) -> str:
    return sha256_hex(canonical_json({k: fields[k] for k in SEALED_FIELDS}))


def prepare_record(envelope: EvidenceEnvelope, *, incident_id: str, ingested_by: str,
                   ingested_at: datetime, asset_id: str | None) -> dict[str, Any]:
    """Validate timing, materialise ``raw``, compute both hashes and the id.

    Returns every stored field except ``event_uid`` (assigned by the store).
    """
    observed = datetime.fromisoformat(envelope.observed_at)
    if observed > ingested_at + MAX_FUTURE_SKEW:
        raise EvidenceError(f"observed_at {envelope.observed_at} is more than "
                            f"{MAX_FUTURE_SKEW} in the future")
    metadata = dict(envelope.metadata)
    raw = envelope.raw
    if raw is None:
        raw = canonical_json(envelope.data)
        metadata["raw_synthesized"] = True
    content = sha256_hex(raw)
    fields: dict[str, Any] = {
        "id": evidence_id(incident_id, envelope.source, envelope.source_ref, content),
        "incident_id": incident_id,
        "source": envelope.source,
        "source_ref": envelope.source_ref,
        "kind": EvidenceKind(envelope.kind).value,
        "event_type": envelope.event_type,
        "observed_at": envelope.observed_at,
        "ingested_at": ingested_at.astimezone(timezone.utc).isoformat(),
        "host": envelope.host,
        "asset_id": asset_id,
        "user": envelope.user,
        "raw": raw,
        "data": dict(envelope.data),
        "metadata": metadata,
        "provenance": Provenance(envelope.provenance).value,
        "content_sha256": content,
        "ingested_by": ingested_by,
    }
    fields["record_sha256"] = record_sha256(fields)
    return fields


def integrity_errors(fields: dict[str, Any]) -> list[str]:
    """Recompute both hashes for a stored record; list any mismatch."""
    errors = []
    if sha256_hex(fields["raw"]) != fields["content_sha256"]:
        errors.append("content_sha256 does not match raw content")
    if record_sha256(fields) != fields["record_sha256"]:
        errors.append("record_sha256 does not match the stored record")
    return errors


# --- file input ------------------------------------------------------------------

def load_envelopes_jsonl(path: str | Path) -> list[EvidenceEnvelope]:
    """One envelope per line (UTF-8, BOM tolerated, blank lines skipped).
    All-or-nothing: raises ``EvidenceError`` listing every bad line."""
    envelopes: list[EvidenceEnvelope] = []
    errors: list[str] = []
    text = Path(path).read_text(encoding="utf-8-sig")
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            envelopes.append(parse_envelope(json.loads(line)))
        except json.JSONDecodeError as e:
            errors.append(f"line {n}: invalid JSON ({e.msg})")
        except EvidenceError as e:
            errors.append(f"line {n}: {e}")
    if errors:
        shown = errors[:20] + ([f"... {len(errors) - 20} more"] if len(errors) > 20 else [])
        raise EvidenceError("invalid evidence file: " + " | ".join(shown))
    return envelopes
