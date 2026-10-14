"""Read-only, indexed view of one incident's evidence for the rules.

Rules never see ``EvidenceRecord`` objects: they see ``Ev``, which carries the
structured fields only. ``raw`` (the verbatim, possibly hostile, sensor line)
is deliberately absent, so no rule can read, parse or act on it.

The view is bound to exactly one incident (taken from the Core rows, never from
evidence content) and refuses records of any other incident.

Derived context, all from evidence or reference data - never from ground truth:

* ``AddressBook`` - ip -> host, learned only from events where the address is
  unambiguously the host's own (EDR ``network_connect`` / NetFlow ``flow``
  initiator / DNS client). Auth events never contribute. An ip claimed by two
  hosts stays unresolved.
* ``DnsMap`` - ip -> names, from ``dns.answers``.
* ``AssetContext`` - the Core's asset inventory (data classes, criticality).
* ``ThreatIntel`` - the mock IOC database; exact matching on normalised values;
  ``status: benign`` entries form the allowlist.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cyberrescue.core.audit import canonical_json
from cyberrescue.core.models import Asset, EvidenceRecord
from cyberrescue.detection.matchers import (
    normalize_domain,
    normalize_ip,
    normalize_sha256,
)

# Event types whose source.ip is the reporting host's own address.
_SELF_ADDRESS_EVENTS = frozenset({"network_connect", "flow", "dns_query"})


@dataclass(frozen=True)
class Ev:
    """Structured view of one evidence record (no ``raw``)."""

    id: str
    at: datetime
    observed_at: str
    kind: str
    event_type: str
    host: str | None
    asset_id: str | None
    user: str | None
    data: dict[str, Any]

    def s(self, key: str) -> str | None:
        """A string field from ``data`` (non-strings are ignored)."""
        v = self.data.get(key)
        return v if isinstance(v, str) else None

    def i(self, key: str) -> int | None:
        v = self.data.get(key)
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    def strings(self, key: str) -> list[str]:
        v = self.data.get(key)
        if isinstance(v, str):
            return [v]
        return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def _ev(r: EvidenceRecord) -> Ev:
    return Ev(id=r.id, at=datetime.fromisoformat(r.observed_at), observed_at=r.observed_at,
              kind=r.kind.value, event_type=r.event_type, host=r.host, asset_id=r.asset_id,
              user=r.user, data=dict(r.data))


# --- reference data -----------------------------------------------------------

@dataclass(frozen=True)
class Indicator:
    value: str
    type: str
    status: str
    confidence: str
    malware_family: str


class ThreatIntel:
    """Exact-match indicator lookup. Active indicators detect; benign ones allowlist."""

    def __init__(self, indicators: Iterable[dict[str, Any]]) -> None:
        items = list(indicators)
        self.fingerprint = hashlib.sha256(canonical_json(items).encode()).hexdigest()
        self._by_key: dict[tuple[str, str], Indicator] = {}
        for item in items:
            t = str(item.get("type", ""))
            norm = {"ipv4": normalize_ip, "ipv6": normalize_ip, "domain": normalize_domain,
                    "sha256": normalize_sha256}.get(t)
            value = norm(item.get("indicator")) if norm else None
            if value is None:
                continue
            kind = "ip" if t.startswith("ipv") else t
            self._by_key[(kind, value)] = Indicator(
                value=value, type=kind, status=str(item.get("status", "")),
                confidence=str(item.get("confidence", "")),
                malware_family=str(item.get("malware_family", "")))

    @classmethod
    def from_mock(cls) -> ThreatIntel:
        from shared.mock_data import load_iocs
        return cls(load_iocs())

    def _get(self, kind: str, value: str | None) -> Indicator | None:
        return self._by_key.get((kind, value)) if value else None

    def lookup_ip(self, v: object) -> Indicator | None:
        return self._get("ip", normalize_ip(v))

    def lookup_domain(self, v: object) -> Indicator | None:
        return self._get("domain", normalize_domain(v))

    def lookup_sha256(self, v: object) -> Indicator | None:
        return self._get("sha256", normalize_sha256(v))

    @staticmethod
    def active(ind: Indicator | None) -> Indicator | None:
        return ind if ind and ind.status == "active" else None

    @staticmethod
    def allowlisted(ind: Indicator | None) -> bool:
        return bool(ind and ind.status == "benign")


class AssetContext:
    def __init__(self, assets: Iterable[Asset]) -> None:
        self._assets = {a.asset_id: a for a in assets}

    def is_asset(self, name: str | None) -> bool:
        return bool(name) and name in self._assets

    def data_classes(self, host: str | None) -> list[str]:
        a = self._assets.get(host or "")
        return list(a.data_classes) if a else []


# --- derived from evidence ------------------------------------------------------

@dataclass
class AddressBook:
    _hosts: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    @classmethod
    def build(cls, events: Iterable[Ev]) -> AddressBook:
        book = cls()
        for e in events:
            ip = normalize_ip(e.s("source.ip"))
            if e.event_type in _SELF_ADDRESS_EVENTS and e.host and ip:
                book._hosts[ip].add(e.host)
        return book

    def resolve(self, ip: object) -> str | None:
        hosts = self._hosts.get(normalize_ip(ip) or "", set())
        return next(iter(hosts)) if len(hosts) == 1 else None

    def ambiguous(self) -> dict[str, list[str]]:
        return {ip: sorted(h) for ip, h in sorted(self._hosts.items()) if len(h) > 1}


@dataclass
class DnsMap:
    _names: dict[str, dict[str, list[str]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(list)))

    @classmethod
    def build(cls, events: Iterable[Ev]) -> DnsMap:
        m = cls()
        for e in events:
            if e.event_type != "dns_query":
                continue
            name = normalize_domain(e.s("dns.question.name"))
            for a in e.strings("dns.answers"):
                ip = normalize_ip(a)
                if name and ip:
                    m._names[ip][name].append(e.id)
        return m

    def names(self, ip: object) -> dict[str, list[str]]:
        """name -> ids of the DNS evidence that resolved ``ip`` to it."""
        return {n: list(ids) for n, ids in sorted(self._names.get(normalize_ip(ip) or "",
                                                                  {}).items())}


class EvidenceView:
    """One incident's evidence, chronologically ordered, plus derived context."""

    def __init__(self, incident_id: str, records: Iterable[EvidenceRecord], *,
                 intel: ThreatIntel, assets: AssetContext) -> None:
        recs = list(records)
        foreign = sorted({r.incident_id for r in recs} - {incident_id})
        if foreign:
            raise ValueError(f"evidence of other incidents in the view: {foreign}")
        self.incident_id = incident_id
        self.events: tuple[Ev, ...] = tuple(sorted((_ev(r) for r in recs),
                                                   key=lambda e: (e.at, e.id)))
        self._by_id = {e.id: e for e in self.events}
        self._rank = {e.id: n for n, e in enumerate(self.events)}
        self.intel = intel
        self.assets = assets
        self.addresses = AddressBook.build(self.events)
        self.dns = DnsMap.build(self.events)
        # Content-based: independent of who ingested it and when.
        self.fingerprint = hashlib.sha256(canonical_json(
            sorted((r.id, r.content_sha256) for r in recs)).encode()).hexdigest()

    def get(self, evidence_id: str) -> Ev:
        return self._by_id[evidence_id]

    def of_type(self, *event_types: str) -> list[Ev]:
        return [e for e in self.events if e.event_type in event_types]

    def of_kind(self, *kinds: str) -> list[Ev]:
        return [e for e in self.events if e.kind in kinds]

    def ordered(self, ids: Iterable[str]) -> tuple[str, ...]:
        """De-duplicated, in chronological evidence order."""
        return tuple(sorted(set(ids), key=self._rank.__getitem__))
