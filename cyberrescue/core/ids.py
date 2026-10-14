"""Incident identity: general IDs plus the WarRoom demo aliases.

WarRoom hard-codes three demo incidents and recovers them with
``re.search(r"INC-[ABC]", ...)`` in four modules. CyberRescue needs arbitrary
incidents, so:

* **General format** — ``INC-<token>(-<token>)*``, tokens of A-Z/0-9, e.g.
  ``INC-C-2026-0042`` (legacy) or ``INC-20260927-0001`` (generated).
* **Generated IDs** are ``INC-YYYYMMDD-NNNN``. They deliberately start with a
  *digit*: the legacy ``INC-[ABC]`` search would misread an ID like
  ``INC-BRUTE-...`` as ``INC-B``, but can never match ``INC-2...``.
* **Legacy aliases** ``INC-A/B/C`` map to the full IDs in the mock alerts.

The legacy regexes in WarRoom modules are untouched in Phase 1.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

# Alias -> full incident id, as in shared/mock_env/alerts/*.json.
LEGACY_ALIASES: dict[str, str] = {
    "INC-A": "INC-A-2026-0039",
    "INC-B": "INC-B-2026-0041",
    "INC-C": "INC-C-2026-0042",
}
_LEGACY_BY_FULL = {v: k for k, v in LEGACY_ALIASES.items()}

_ID_RE = re.compile(r"^INC-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
_GENERATED_RE = re.compile(r"^INC-\d{8}-\d{4}$")
# An embedded legacy alias must end at a token boundary so "INC-BRUTE" is NOT
# read as INC-B (stricter than the WarRoom regex, on purpose).
_LEGACY_EMBED_RE = re.compile(r"INC-([ABC])(?![A-Z0-9])")
_EMBEDDED_ID_RE = re.compile(r"INC-[A-Z0-9]+(?:-[A-Z0-9]+)*")


def is_valid_incident_id(value: str) -> bool:
    """True if ``value`` is a well-formed incident id (legacy or generated)."""
    return bool(_ID_RE.match(value or ""))


def is_generated_id(value: str) -> bool:
    return bool(_GENERATED_RE.match(value or ""))


def generate_incident_id(seq: int, now: datetime | None = None) -> str:
    """``INC-YYYYMMDD-NNNN`` for the ``seq``-th incident created that UTC day."""
    if not 1 <= seq <= 9999:
        raise ValueError(f"incident sequence out of range: {seq}")
    now = now or datetime.now(timezone.utc)
    return f"INC-{now.astimezone(timezone.utc):%Y%m%d}-{seq:04d}"


def legacy_alias_for(incident_id: str) -> str | None:
    """``INC-C`` for ``INC-C-2026-0042``; None for non-demo incidents."""
    return _LEGACY_BY_FULL.get((incident_id or "").upper())


def parse_incident_ref(text: str) -> str | None:
    """Resolve a (possibly decorated) incident reference to a canonical id.

    Order: exact legacy alias -> well-formed id -> embedded legacy alias ->
    embedded well-formed id -> None. Mirrors the leniency of
    ``shared.mock_data.load_alert`` so LLM-decorated ids such as
    ``"INC-C-2026-[BlackHaze-srv-db-01]"`` still resolve.

    This only *parses*; whether the incident exists is the store's question.
    """
    key = (text or "").strip().upper()
    if not key:
        return None
    if key in LEGACY_ALIASES:
        return LEGACY_ALIASES[key]
    if _ID_RE.match(key):
        return key
    m = _LEGACY_EMBED_RE.search(key)
    if m:
        return LEGACY_ALIASES[f"INC-{m.group(1)}"]
    m = _EMBEDDED_ID_RE.search(key)
    if m:
        return m.group(0)
    return None
