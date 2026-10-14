"""Authentication rules over Windows Security logon events (4624 / 4625).

A logon is keyed by (target host, account, source address). Windows were sized
from the Phase 2B data: attacker bursts take 9-20 s, while the nearest benign
failure -> success pair (a mistyped password) is 28 minutes apart, so 5 minutes
separates them with a wide margin.
"""

from __future__ import annotations

from collections import defaultdict

from cyberrescue.detection.context import Ev, EvidenceView
from cyberrescue.detection.matchers import normalize_ip, safe_token
from cyberrescue.detection.model import ConditionResult, ConditionSpec, RuleSpec, Window
from cyberrescue.detection.registry import Rule

FAIL, SUCCESS = "4625", "4624"
NETWORK_LOGON = "3"
AUTH_WINDOW = Window(name="auth_burst", seconds=300)


def account(e: Ev) -> str | None:
    name = e.user or e.s("user.name")
    return name.lower() if name else None


def logon_groups(view: EvidenceView) -> dict[tuple[str, str, str], list[Ev]]:
    groups: dict[tuple[str, str, str], list[Ev]] = defaultdict(list)
    for e in view.of_type(FAIL, SUCCESS):
        key = (e.host, account(e), normalize_ip(e.s("source.ip")))
        if all(key):
            groups[key].append(e)
    return dict(sorted(groups.items()))


def _first_seen(events: list[Ev], before: Ev) -> ConditionResult:
    prior = [e for e in events if e.event_type == SUCCESS and (e.at, e.id) < (before.at, before.id)]
    return ConditionResult(id="first_seen_source", matched=not prior,
                           detail={"earlier_successes": len(prior)})


def _network(events: list[Ev]) -> ConditionResult:
    net = [e.id for e in events if e.s("winlog.logon.type") == NETWORK_LOGON]
    return ConditionResult(id="network_logon", matched=len(net) == len(events),
                           evidence_ids=tuple(net),
                           detail={"logon_types": sorted({e.s("winlog.logon.type") or "?"
                                                          for e in events})})


_COMMON = (
    ConditionSpec(id="network_logon", role="corroborating",
                  description="the logons are network logons (type 3)"),
    ConditionSpec(id="first_seen_source", role="corroborating",
                  description="no earlier successful logon for this account and source on "
                              "this host in the evidence"),
)


class FailedThenSuccess(Rule):
    MIN_FAILURES = 2
    spec = RuleSpec(
        rule_id="AUTH-001", version=1, name="Repeated failed logons followed by success",
        description="At least two failed logons for one account, target host and source "
                    "address, followed by a successful logon within five minutes.",
        finding_type="credential_access", severity="high", window=AUTH_WINDOW,
        conditions=(
            ConditionSpec(id="repeated_failures", role="required",
                          description=">=2 failed logons (4625) for the same key"),
            ConditionSpec(id="subsequent_success", role="required",
                          description="a successful logon (4624) for the same key within "
                                      "the window of the first failure"),
            *_COMMON))

    def evaluate(self, view: EvidenceView) -> list:
        out = []
        for (host, user, ip), evs in logon_groups(view).items():
            i = 0
            while i < len(evs):
                if evs[i].event_type != FAIL:
                    i += 1
                    continue
                fails, success, j = [], None, i
                while j < len(evs) and self.within(evs[i].at, evs[j].at):
                    if evs[j].event_type == SUCCESS:
                        success = evs[j]
                        break
                    fails.append(evs[j])
                    j += 1
                if success is None or len(fails) < self.MIN_FAILURES:
                    i += 1
                    continue
                after = int((success.at - fails[0].at).total_seconds())
                group = [*fails, success]
                out.append(self.result(
                    view, key=[host, user, ip, fails[0].id],
                    matched={
                        "repeated_failures": ConditionResult(
                            id="repeated_failures", matched=True,
                            evidence_ids=tuple(e.id for e in fails),
                            detail={"failures": len(fails)}),
                        "subsequent_success": ConditionResult(
                            id="subsequent_success", matched=True, evidence_ids=(success.id,),
                            detail={"seconds_after_first_failure": after}),
                        "network_logon": _network(group),
                        "first_seen_source": _first_seen(evs, fails[0])},
                    supporting=[e.id for e in group], primary_host=host,
                    entities={"target_host": host, "user": user, "source_ip": ip,
                              "source_host": view.addresses.resolve(ip),
                              "failures": len(fails), "success_after_seconds": after},
                    summary=f"{len(fails)} failed logons for {safe_token(user)} on "
                            f"{safe_token(host)} from {safe_token(ip)}, then a successful "
                            f"logon {after}s after the first failure."))
                i = j + 1
        return out


class RepeatedFailures(Rule):
    MIN_FAILURES = 3
    spec = RuleSpec(
        rule_id="AUTH-002", version=1, name="Repeated failed logons without success",
        description="At least three failed logons for one account, target host and source "
                    "address within five minutes, with no successful logon in that window "
                    "(bursts that end in success are AUTH-001).",
        finding_type="credential_access", severity="medium", window=AUTH_WINDOW,
        conditions=(
            ConditionSpec(id="repeated_failures", role="required",
                          description=">=3 failed logons (4625) for the same key"),
            ConditionSpec(id="no_success", role="required",
                          description="no successful logon for the same key in the window"),
            *_COMMON))

    def evaluate(self, view: EvidenceView) -> list:
        out = []
        for (host, user, ip), evs in logon_groups(view).items():
            i = 0
            while i < len(evs):
                if evs[i].event_type != FAIL:
                    i += 1
                    continue
                window = [e for e in evs[i:] if self.within(evs[i].at, e.at)]
                fails = [e for e in window if e.event_type == FAIL]
                if any(e.event_type == SUCCESS for e in window) or \
                        len(fails) < self.MIN_FAILURES:
                    i += 1
                    continue
                out.append(self.result(
                    view, key=[host, user, ip, fails[0].id],
                    matched={
                        "repeated_failures": ConditionResult(
                            id="repeated_failures", matched=True,
                            evidence_ids=tuple(e.id for e in fails),
                            detail={"failures": len(fails)}),
                        "no_success": ConditionResult(id="no_success", matched=True),
                        "network_logon": _network(fails),
                        "first_seen_source": _first_seen(evs, fails[0])},
                    supporting=[e.id for e in fails], primary_host=host,
                    entities={"target_host": host, "user": user, "source_ip": ip,
                              "source_host": view.addresses.resolve(ip),
                              "failures": len(fails)},
                    summary=f"{len(fails)} failed logons for {safe_token(user)} on "
                            f"{safe_token(host)} from {safe_token(ip)} with no success."))
                i += len(window)
        return out
