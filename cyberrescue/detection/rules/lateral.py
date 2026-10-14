"""Lateral movement: one account authenticating remotely to several hosts.

The source host comes from the logon's workstation name when it is an
inventory asset, otherwise from the evidence-derived address book; an
unresolvable source is keyed by its ip. The 15-minute window is generous
against the data (the Phase 2B attack spans 67 s) while benign accounts in the
data only ever log on remotely to the domain controller.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from cyberrescue.detection.context import Ev, EvidenceView
from cyberrescue.detection.matchers import ADMIN_PORTS, is_user_writable, normalize_ip, \
    safe_token
from cyberrescue.detection.model import ConditionResult, ConditionSpec, RuleSpec, Window
from cyberrescue.detection.registry import Rule
from cyberrescue.detection.rules.auth import FAIL, NETWORK_LOGON, SUCCESS, account

FLOW_SLACK = timedelta(seconds=60)
PROCESS_LOOKBACK = timedelta(hours=1)


def source_host(view: EvidenceView, e: Ev) -> str | None:
    ws = e.s("source.domain")
    if ws and view.assets.is_asset(ws):
        return ws
    return view.addresses.resolve(e.s("source.ip"))


class RemoteAuthToMultipleHosts(Rule):
    MIN_DESTINATIONS = 2
    spec = RuleSpec(
        rule_id="LAT-001", version=1, name="Remote authentication to multiple hosts",
        description="One account authenticates with network logons from one source to at "
                    "least two other hosts within 15 minutes.",
        finding_type="lateral_movement", severity="high",
        window=Window(name="lateral_movement", seconds=900),
        conditions=(
            ConditionSpec(id="remote_logons_multiple_hosts", role="required",
                          description="network logons (type 3, success or failure) by the "
                                      "same account from the same source to >=2 hosts"),
            ConditionSpec(id="admin_protocol_flows", role="corroborating",
                          description="SMB/RPC/RDP/WinRM connections from the source "
                                      "around the logons"),
            ConditionSpec(id="ntlm_authentication", role="corroborating",
                          description="NTLM was used for the remote logons"),
            ConditionSpec(id="account_ran_suspicious_process", role="corroborating",
                          description="the account started a process from a user-writable "
                                      "path on the source host within the hour before")))

    def evaluate(self, view: EvidenceView) -> list:
        groups: dict[tuple[str, str], list[tuple[Ev, str | None, str]]] = defaultdict(list)
        for e in view.of_type(FAIL, SUCCESS):
            user, ip = account(e), normalize_ip(e.s("source.ip"))
            if e.s("winlog.logon.type") != NETWORK_LOGON or not (e.host and user and ip):
                continue
            src = source_host(view, e)
            if src == e.host:
                continue
            groups[(user, src or ip)].append((e, src, ip))
        out = []
        for (user, _), items in sorted(groups.items()):
            i = 0
            while i < len(items):
                start = items[i][0].at
                window = [it for it in items[i:] if self.within(start, it[0].at)]
                dests = sorted({e.host for e, _, _ in window})
                if len(dests) < self.MIN_DESTINATIONS:
                    i += 1
                    continue
                out.append(self._detect(view, user, window, dests))
                i += len(window)
        return out

    def _detect(self, view, user, window, dests):
        logons = [e for e, _, _ in window]
        src, ip = window[0][1], window[0][2]
        lo, hi = logons[0].at - FLOW_SLACK, logons[-1].at + FLOW_SLACK
        flows = [f for f in view.of_type("flow", "network_connect")
                 if lo <= f.at <= hi and f.i("destination.port") in ADMIN_PORTS
                 and (normalize_ip(f.s("source.ip")) == ip or (src and f.host == src))]
        ntlm = [e for e in logons
                if (e.s("winlog.event_data.AuthenticationPackageName") or "").upper() == "NTLM"]
        procs = [p for p in view.of_type("process_start")
                 if src and p.host == src and account(p) == user
                 and lo - PROCESS_LOOKBACK <= p.at <= hi
                 and is_user_writable(p.s("process.executable"))]
        succeeded = sorted({e.host for e in logons if e.event_type == SUCCESS})
        span = int((logons[-1].at - logons[0].at).total_seconds())
        return self.result(
            view, key=[user, src or ip, logons[0].id],
            matched={
                "remote_logons_multiple_hosts": ConditionResult(
                    id="remote_logons_multiple_hosts", matched=True,
                    evidence_ids=tuple(e.id for e in logons),
                    detail={"destinations": dests, "logons": len(logons)}),
                "admin_protocol_flows": ConditionResult(
                    id="admin_protocol_flows", matched=bool(flows),
                    evidence_ids=tuple(f.id for f in flows),
                    detail={"destination_ips": sorted({f.s("destination.ip") or "?"
                                                        for f in flows}),
                            "ports": sorted({f.i("destination.port") or 0 for f in flows})}),
                "ntlm_authentication": ConditionResult(
                    id="ntlm_authentication", matched=bool(ntlm),
                    evidence_ids=tuple(e.id for e in ntlm)),
                "account_ran_suspicious_process": ConditionResult(
                    id="account_ran_suspicious_process", matched=bool(procs),
                    evidence_ids=tuple(p.id for p in procs),
                    detail={"executables": sorted({p.s("process.executable") or "?"
                                                   for p in procs})})},
            supporting=[*(e.id for e in logons), *(f.id for f in flows), *(p.id for p in procs)],
            primary_host=src,
            entities={"user": user, "source_host": src, "source_ip": ip,
                      "destinations": dests, "succeeded_hosts": succeeded,
                      "failed_only_hosts": sorted(set(dests) - set(succeeded))},
            summary=f"Account {safe_token(user)} authenticated remotely from "
                    f"{safe_token(src or ip)} to {len(dests)} hosts within {span}s "
                    f"({', '.join(safe_token(d) for d in dests)}); successful on "
                    f"{', '.join(safe_token(d) for d in succeeded) or 'none'}.")
