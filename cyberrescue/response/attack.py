"""Static MITRE ATT&CK (Enterprise) labels per detection rule - planner only (Q3).

A rule-level label for the analyst reading a plan: "this step answers activity
of this kind". It is NOT an inference about the specific event, it does not
feed detection, and it is not part of the Phase 3 case. Rules whose behaviour
spans several techniques carry the tactic only (``technique_id`` None).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from cyberrescue.response.model import AttackRef

ATTACK_MAP_VERSION = "attack-map-v1"

TACTICS = {
    "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0006": "Credential Access", "TA0008": "Lateral Movement", "TA0010": "Exfiltration",
    "TA0011": "Command and Control", "TA0040": "Impact",
}


def _ref(tactic_id: str, technique_id: str | None = None,
         technique: str | None = None) -> AttackRef:
    return AttackRef(tactic_id=tactic_id, tactic=TACTICS[tactic_id],
                     technique_id=technique_id, technique=technique)


RULE_ATTACK: dict[str, tuple[AttackRef, ...]] = {
    "AUTH-001": (_ref("TA0006", "T1110", "Brute Force"),),
    "AUTH-002": (_ref("TA0006", "T1110", "Brute Force"),),
    "LAT-001": (_ref("TA0008", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),),
    "IOC-001": (_ref("TA0002"),),
    "PROC-001": (_ref("TA0002"),),
    "PROC-002": (_ref("TA0002", "T1059", "Command and Scripting Interpreter"),),
    "PERSIST-001": (_ref("TA0003"),),
    "PRIV-001": (_ref("TA0004", "T1098", "Account Manipulation"),),
    "IOC-002": (_ref("TA0011", "T1071", "Application Layer Protocol"),),
    "NET-001": (_ref("TA0011", "T1071", "Application Layer Protocol"),),
    "RECOV-001": (_ref("TA0040", "T1490", "Inhibit System Recovery"),),
    "RANSOM-001": (_ref("TA0040", "T1486", "Data Encrypted for Impact"),),
    "DATA-001": (_ref("TA0010"),),
    # Aggregates / opinions: labelled through their members, or not at all.
    "CORR-001": (),
    "ALERT-001": (),
}

_PERSISTENCE = {
    "service": _ref("TA0003", "T1543.003", "Create or Modify System Process: Windows Service"),
    "run_key": _ref("TA0003", "T1547.001", "Boot or Logon Autostart Execution: Registry Run "
                    "Keys / Startup Folder"),
}


def attack_for(rule_id: str, entities: Mapping[str, Any] | None = None) -> tuple[AttackRef, ...]:
    """Labels for one detection (unknown rules get none)."""
    ent = entities or {}
    if rule_id == "PERSIST-001" and ent.get("mechanism") in _PERSISTENCE:
        return (_PERSISTENCE[ent["mechanism"]],)
    if rule_id == "CORR-001":
        return merge(attack_for(m.get("rule_id", "")) for m in ent.get("members", [])
                     if isinstance(m, Mapping))
    return RULE_ATTACK.get(rule_id, ())


def merge(groups: Iterable[Iterable[AttackRef]]) -> tuple[AttackRef, ...]:
    """De-duplicated, sorted by (tactic, technique)."""
    seen = {(r.tactic_id, r.technique_id or ""): r for g in groups for r in g}
    return tuple(seen[k] for k in sorted(seen))
