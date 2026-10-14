"""Privilege escalation: a newly created account placed in a privileged group.

Field contract (Windows Security events, ECS-style): 4720 account created and
4728/4732/4756 member added, each with ``user.target.name`` (the affected
account) and, for membership changes, ``group.name``; ``user.name`` is the
actor. NOTE: none of the Phase 2B scenarios contains such events - this rule is
covered by unit fixtures only (decision D1 = a).
"""

from __future__ import annotations

from datetime import timedelta

from cyberrescue.detection.context import Ev, EvidenceView
from cyberrescue.detection.matchers import PRIVILEGED_GROUPS, safe_token
from cyberrescue.detection.model import ConditionResult, ConditionSpec, RuleSpec, Window
from cyberrescue.detection.registry import Rule

CREATED = "4720"
MEMBER_ADDED = ("4728", "4732", "4756")
WINDOW = Window(name="privilege_change", seconds=3600)


def _target(e: Ev) -> str | None:
    t = e.s("user.target.name")
    return t.lower() if t else None


class NewPrivilegedAccount(Rule):
    spec = RuleSpec(
        rule_id="PRIV-001", version=1, name="New account added to a privileged group",
        description="An account is created and added to a privileged group (Domain/"
                    "Enterprise/Schema Admins, Administrators, Backup/Account/Server "
                    "Operators) within an hour.",
        finding_type="privilege_escalation", severity="high", window=WINDOW,
        base_confidence="medium",
        conditions=(
            ConditionSpec(id="account_created", role="required",
                          description="4720 for the account"),
            ConditionSpec(id="added_to_privileged_group", role="required",
                          description="4728/4732/4756 adding the same account to a "
                                      "privileged group within the window"),
            ConditionSpec(id="privileged_logon", role="corroborating",
                          description="the new account logs on (4624/4672) after the "
                                      "change")))

    def evaluate(self, view: EvidenceView) -> list:
        out = []
        created = {}
        for c in view.of_type(CREATED):
            if _target(c):
                created.setdefault(_target(c), []).append(c)
        for add in view.of_type(*MEMBER_ADDED):
            account, group = _target(add), (add.s("group.name") or "").lower()
            if not account or group not in PRIVILEGED_GROUPS:
                continue
            origin = [c for c in created.get(account, [])
                      if c.at <= add.at <= c.at + timedelta(seconds=WINDOW.seconds)]
            if not origin:
                out.append(self.observation(
                    view, kind="indicator_observed", key=[account, group, add.id],
                    primary_host=add.host, evidence_ids=[add.id],
                    entities={"account": account, "group": group, "actor": add.user},
                    reason=f"existing account {safe_token(account)} added to privileged "
                           f"group {group!r}; no account creation in the window - review, "
                           "not a finding"))
                continue
            c = origin[-1]
            logons = [e for e in view.of_type("4624", "4672")
                      if (e.user or e.s("user.name") or "").lower() == account
                      and add.at <= e.at <= c.at + timedelta(seconds=WINDOW.seconds)]
            out.append(self.result(
                view, key=[account, group, c.id],
                matched={
                    "account_created": ConditionResult(id="account_created", matched=True,
                                                       evidence_ids=(c.id,)),
                    "added_to_privileged_group": ConditionResult(
                        id="added_to_privileged_group", matched=True, evidence_ids=(add.id,),
                        detail={"group": group}),
                    "privileged_logon": ConditionResult(
                        id="privileged_logon", matched=bool(logons),
                        evidence_ids=tuple(e.id for e in logons))},
                supporting=[c.id, add.id, *(e.id for e in logons)], primary_host=add.host,
                entities={"account": account, "group": group, "actor": add.user,
                          "host": add.host},
                summary=f"New account {safe_token(account)} was added to privileged group "
                        f"{safe_token(group.replace(' ', '_'))} by "
                        f"{safe_token(add.user)}."))
        return out
