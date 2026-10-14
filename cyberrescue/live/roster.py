"""Build the trusted roster ``core import-band`` / ``live sync`` need, from
agent_config.yaml (the single source of identities).

The roster maps Band ``sender_id`` -> Core role. Agent ids come from
``agents.<role>.agent_id``; the CISO from ``humans.ciso.user_id``. Extra humans
(e.g. a DPO) can be added explicitly. A human is never inferred from a message.
The output holds Band ids only (no API keys); keep it outside the repository.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyberrescue.core.models import AGENT_ROLES, HUMAN_ROLES
from cyberrescue.live.preflight import AGENTS, classify_secret
from shared.config import ciso_user_id


class RosterError(ValueError):
    pass


def build_roster(cfg: dict[str, Any], humans: dict[str, str] | None = None, *,
                 require_ciso: bool = True) -> dict[str, Any]:
    agents_cfg = cfg.get("agents") or {}
    agents: dict[str, str] = {}
    for role in AGENTS:
        a = agents_cfg.get(role) or {}
        agent_id = str(a.get("agent_id") or "")
        if classify_secret(agent_id) != "set":
            raise RosterError(f"agent_config.yaml: {role}.agent_id is missing or a placeholder")
        if role not in AGENT_ROLES:
            raise RosterError(f"{role!r} is not a Core agent role")
        if agent_id in agents:
            raise RosterError(f"{role} and {agents[agent_id]} share agent_id")
        agents[agent_id] = role
    people: dict[str, str] = {}
    ciso = ciso_user_id(cfg)
    if ciso:
        people[ciso] = "ciso"
    elif require_ciso:
        raise RosterError("agent_config.yaml: humans.ciso.user_id is missing or a placeholder "
                          "-- without it the CISO's ruling imports as 'observer' and can "
                          "never resolve an escalation")
    for hid, role in (humans or {}).items():
        if role not in HUMAN_ROLES:
            raise RosterError(f"human role {role!r} is not one of {sorted(HUMAN_ROLES)}")
        if hid in people and people[hid] != role:
            raise RosterError(f"human id {hid} is already mapped to {people[hid]}")
        people[hid] = role
    for hid in people:
        if hid in agents:
            raise RosterError(f"human id {hid} is also an agent id")
    return {"agents": agents, "humans": people, "default_human_role": "observer"}


def parse_human(spec: str) -> tuple[str, str]:
    """``<band-user-id>=<role>`` (e.g. ``1b2c...=dpo``)."""
    hid, sep, role = spec.partition("=")
    if not sep or not hid.strip() or not role.strip():
        raise RosterError(f"--human must be <band-user-id>=<role>, got {spec!r}")
    return hid.strip(), role.strip()


def write_roster(path: Path, roster: dict[str, Any]) -> None:
    if path.exists():
        raise RosterError(f"{path} already exists (never overwritten)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(roster, indent=2, sort_keys=True) + "\n", encoding="utf-8")
