"""Threat-intel and network rules.

IOC matching is exact, on normalised structured fields only (``destination.ip``,
``source.ip``, ``dns.question.name``, the host of ``url.original``,
``process.hash.sha256``) - never substrings of raw text, so ``198.51.100.234``
does not match the indicator ``198.51.100.23``.

*Indicator observed* is not a finding: an active indicator seen only as the
SOURCE of inbound traffic (e.g. an internet scanner hitting a web server)
yields an Observation. Benign indicators (``status: benign``) are the allowlist.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from cyberrescue.detection.context import Ev, EvidenceView, Indicator
from cyberrescue.detection.matchers import (
    CONFIDENCES_FROM_INTEL,
    is_external,
    normalize_ip,
    safe_token,
    url_host,
)
from cyberrescue.detection.model import ConditionResult, ConditionSpec, RuleSpec, Window
from cyberrescue.detection.registry import Rule
from cyberrescue.detection.rules.common import CORROBORATION_SECONDS, vendor_alerts

# Events where ``host`` initiated the traffic (see context.AddressBook).
OUTBOUND_EVENTS = ("flow", "network_connect")
BLOCKED_STATUS = (403, 407)


def intel_confidence(ind: Indicator) -> str:
    return CONFIDENCES_FROM_INTEL.get(ind.confidence, "low")


class KnownMaliciousHash(Rule):
    spec = RuleSpec(
        rule_id="IOC-001", version=1, name="Known-malicious file executed",
        description="A process starts whose SHA-256 is an active threat-intel indicator. "
                    "Confidence is the indicator's own confidence.",
        finding_type="execution", severity="high",
        window=Window(name="corroboration", seconds=CORROBORATION_SECONDS),
        conditions=(
            ConditionSpec(id="hash_matches_active_ioc", role="required",
                          description="process.hash.sha256 equals an active sha256 IOC"),
            ConditionSpec(id="vendor_alert", role="corroborating",
                          description="an EDR alert on the host names the same hash or "
                                      "process (context)")))

    def evaluate(self, view: EvidenceView) -> list:
        out = []
        for p in view.of_type("process_start"):
            sha = p.s("process.hash.sha256")
            ind = view.intel.active(view.intel.lookup_sha256(sha))
            if not ind:
                continue
            alerts = vendor_alerts(view, p.host, p.at, sha256=sha,
                                   process_name=p.s("process.name"))
            conf = intel_confidence(ind)
            out.append(self.result(
                view, key=[p.host, ind.value, p.id],
                matched={
                    "hash_matches_active_ioc": ConditionResult(
                        id="hash_matches_active_ioc", matched=True, evidence_ids=(p.id,),
                        detail={"indicator": ind.value, "malware_family": ind.malware_family,
                                "ioc_confidence": ind.confidence}),
                    "vendor_alert": ConditionResult(id="vendor_alert", matched=bool(alerts),
                                                    evidence_ids=tuple(a.id for a in alerts))},
                supporting=[p.id], context=[a.id for a in alerts], primary_host=p.host,
                confidence=conf, confidence_basis=f"threat-intel confidence "
                                                  f"{ind.confidence!r} -> {conf}",
                entities={"host": p.host, "user": p.user, "process": p.s("process.name"),
                          "executable": p.s("process.executable"), "indicator": ind.value,
                          "malware_family": ind.malware_family},
                summary=f"{safe_token(p.s('process.name'))} on {safe_token(p.host)} matches "
                        f"known-malicious hash ({safe_token(ind.malware_family.replace(' ', '_'))})."))
        return out


class MaliciousInfrastructureContact(Rule):
    spec = RuleSpec(
        rule_id="IOC-002", version=1, name="Outbound contact with known-malicious "
                                           "infrastructure",
        description="A host connects to, resolves or requests an active IP/domain "
                    "indicator. Blocked attempts are reported with lower severity; "
                    "inbound-only sightings are Observations.",
        finding_type="command_and_control", severity="high",
        window=Window(name="corroboration", seconds=CORROBORATION_SECONDS),
        conditions=(
            ConditionSpec(id="outbound_contact_with_active_ioc", role="required",
                          description="outbound connection, DNS lookup or proxy request to "
                                      "an active IP or domain indicator"),
            ConditionSpec(id="connection_established", role="corroborating",
                          description="at least one connection was established (flow with "
                                      "return traffic, EDR connect, or allowed proxy "
                                      "request)")))

    def _outbound(self, view: EvidenceView):
        """(event, indicator, outcome) for every outbound contact."""
        intel = view.intel
        for e in view.events:
            if not e.host:
                continue
            if e.event_type in OUTBOUND_EVENTS:
                ind = intel.active(intel.lookup_ip(e.s("destination.ip")))
                if ind:
                    est = e.event_type == "network_connect" or (e.i("destination.bytes") or 0) > 0
                    yield e, ind, "established" if est else "attempted"
            elif e.event_type == "dns_query":
                ind = intel.active(intel.lookup_domain(e.s("dns.question.name")))
                if ind:
                    yield e, ind, "resolved"
            elif e.event_type == "http_request":
                ind = intel.active(intel.lookup_domain(url_host(e.s("url.original")))) or \
                    intel.active(intel.lookup_ip(e.s("destination.ip")))
                if ind:
                    blocked = (e.s("event.action") or "").lower() == "blocked" or \
                        e.i("http.response.status_code") in BLOCKED_STATUS
                    yield e, ind, "blocked" if blocked else "established"

    def evaluate(self, view: EvidenceView) -> list:
        groups: dict[tuple[str, str], list[tuple[Ev, Indicator, str]]] = defaultdict(list)
        for e, ind, outcome in self._outbound(view):
            groups[(e.host, ind.value)].append((e, ind, outcome))
        out = []
        for (host, value), items in sorted(groups.items()):
            ind = items[0][1]
            outcomes = sorted({o for _, _, o in items})
            established = [e.id for e, _, o in items if o == "established"]
            overall = "established" if established else \
                "blocked" if "blocked" in outcomes else "attempted"
            conf = intel_confidence(ind)
            out.append(self.result(
                view, key=[host, value],
                matched={
                    "outbound_contact_with_active_ioc": ConditionResult(
                        id="outbound_contact_with_active_ioc", matched=True,
                        evidence_ids=tuple(e.id for e, _, _ in items),
                        detail={"indicator": value, "type": ind.type,
                                "malware_family": ind.malware_family,
                                "outcomes": outcomes}),
                    "connection_established": ConditionResult(
                        id="connection_established", matched=bool(established),
                        evidence_ids=tuple(established), detail={"outcome": overall})},
                supporting=[e.id for e, _, _ in items], primary_host=host,
                severity="high" if established else "medium",
                confidence=conf, confidence_basis=f"threat-intel confidence "
                                                  f"{ind.confidence!r} -> {conf}",
                entities={"host": host, "indicator": value, "indicator_type": ind.type,
                          "malware_family": ind.malware_family, "outcome": overall},
                summary=f"{safe_token(host)} contacted known-malicious {ind.type} "
                        f"{safe_token(value)} ({overall})."))
        out += self._inbound(view, {k for k in groups})
        return out

    def _inbound(self, view: EvidenceView, outbound: set[tuple[str, str]]) -> list:
        """Active indicators seen only as the source of traffic: indicator observed."""
        groups: dict[tuple[str, str], list[Ev]] = defaultdict(list)
        for e in view.events:
            if e.event_type in OUTBOUND_EVENTS or e.event_type == "dns_query" or not e.host:
                continue
            ind = view.intel.active(view.intel.lookup_ip(e.s("source.ip")))
            if ind and (e.host, ind.value) not in outbound:
                groups[(e.host, ind.value)].append(e)
        out = []
        for (host, value), evs in sorted(groups.items()):
            ind = view.intel.lookup_ip(value)
            statuses = sorted({str(e.i("http.response.status_code")) for e in evs
                               if e.i("http.response.status_code") is not None})
            out.append(self.observation(
                view, kind="indicator_observed", key=[host, value, "inbound"],
                primary_host=host, evidence_ids=[e.id for e in evs],
                entities={"host": host, "indicator": value, "direction": "inbound",
                          "malware_family": ind.malware_family, "http_status": statuses},
                reason=f"inbound traffic from active indicator {value} ({ind.malware_family}) "
                       f"to {host} (HTTP {', '.join(statuses) or 'n/a'}); no outbound "
                       "contact - indicator observed, not a finding"))
        return out


class PeriodicOutbound(Rule):
    MIN_CONNECTIONS = 4
    MIN_PERIOD = 30
    spec = RuleSpec(
        rule_id="NET-001", version=1, name="Periodic outbound connections (beaconing)",
        description=">=4 outbound flows from one host to one external destination/port at a "
                    "regular interval (jitter <= max(5 s, 5 %)). Suppressed when the "
                    "destination, or a DNS name it resolved from, is allowlisted.",
        finding_type="beaconing", severity="medium",
        window=Window(name="beacon_horizon", seconds=6 * 3600),
        conditions=(
            ConditionSpec(id="periodic_outbound", role="required",
                          description="regular interval between >=4 flows"),
            ConditionSpec(id="external_destination", role="required",
                          description="destination is outside internal address space"),
            ConditionSpec(id="destination_active_ioc", role="corroborating",
                          description="destination is an active indicator")))

    @staticmethod
    def periodicity(times) -> tuple[int, int] | None:
        gaps = [int((b - a).total_seconds()) for a, b in zip(times, times[1:])]
        if not gaps:
            return None
        median = sorted(gaps)[len(gaps) // 2]
        return median, max(abs(g - median) for g in gaps)

    def evaluate(self, view: EvidenceView) -> list:
        groups: dict[tuple[str, str, int], list[Ev]] = defaultdict(list)
        for e in view.of_type("flow"):
            dst, port = normalize_ip(e.s("destination.ip")), e.i("destination.port")
            if e.host and dst and port is not None and is_external(dst):
                groups[(e.host, dst, port)].append(e)
        out = []
        for (host, dst, port), evs in sorted(groups.items()):
            horizon = evs[0].at + timedelta(seconds=self.spec.window.seconds)
            evs = [e for e in evs if e.at <= horizon]
            stats = self.periodicity([e.at for e in evs])
            if len(evs) < self.MIN_CONNECTIONS or stats is None:
                continue
            period, jitter = stats
            if period < self.MIN_PERIOD or jitter > max(5, period * 5 // 100):
                continue
            entities = {"host": host, "destination_ip": dst, "destination_port": port,
                        "connections": len(evs), "period_seconds": period,
                        "jitter_seconds": jitter}
            matched = {
                "periodic_outbound": ConditionResult(
                    id="periodic_outbound", matched=True,
                    evidence_ids=tuple(e.id for e in evs),
                    detail={"period_seconds": period, "jitter_seconds": jitter,
                            "connections": len(evs)}),
                "external_destination": ConditionResult(id="external_destination",
                                                        matched=True, detail={"ip": dst})}
            reason, extra, allowlisted_as = self._allowlisted(view, dst)
            if reason:
                out.append(self.observation(
                    view, kind="suppressed", key=[host, dst, port], primary_host=host,
                    evidence_ids=[*(e.id for e in evs), *extra],
                    entities=entities | {"allowlisted_as": allowlisted_as},
                    matched=matched,
                    reason=f"periodic outbound to {dst}:{port} every ~{period}s suppressed - "
                           f"{reason}"))
                continue
            ind = view.intel.active(view.intel.lookup_ip(dst))
            matched["destination_active_ioc"] = ConditionResult(
                id="destination_active_ioc", matched=bool(ind),
                detail={"malware_family": ind.malware_family} if ind else {})
            out.append(self.result(
                view, key=[host, dst, port], matched=matched,
                supporting=[e.id for e in evs], primary_host=host, entities=entities,
                summary=f"{safe_token(host)} connects to {safe_token(dst)}:{port} every "
                        f"~{period}s ({len(evs)} connections)."))
        return out

    @staticmethod
    def _allowlisted(view: EvidenceView,
                     dst: str) -> tuple[str | None, list[str], str | None]:
        """(reason, DNS evidence ids, the allowlisted ip/name) or (None, [], None)."""
        if view.intel.allowlisted(view.intel.lookup_ip(dst)):
            return f"{dst} is allowlisted (threat intel status=benign)", [], dst
        for name, ids in view.dns.names(dst).items():
            if view.intel.allowlisted(view.intel.lookup_domain(name)):
                return (f"{dst} was resolved from {name} (DNS evidence {', '.join(ids[:3])}"
                        f"{'...' if len(ids) > 3 else ''}), which is allowlisted "
                        "(threat intel status=benign)", ids, name)
        return None, [], None
