"""Response-action catalogue: every action the Core knows, with its risk tier.

The four ``warroom_tool=True`` actions are the Commander's existing tools
(agents/commander/tools.py). The rest are declared now so the policy engine
and its tests cover the full tier model; they have no executor until Phase 4.
An action not in this catalogue is denied outright (policy rule P0).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cyberrescue.core.models import ActionTier


@dataclass(frozen=True)
class ActionSpec:
    name: str
    tier: ActionTier
    target: str            # "host" | "account" | "ip" | "none"
    destructive: bool      # destroys state/evidence (legal holds apply)
    reversible: bool
    warroom_tool: bool     # exists as a WarRoom Commander tool today
    description: str


_SPECS = [
    ActionSpec("notify_stakeholders", ActionTier.LOW, "none", False, True, True,
               "Internal notification (legal, DPO, CISO)."),
    ActionSpec("preserve_disk_image", ActionTier.LOW, "host", False, True, True,
               "Forensic disk + memory image; non-destructive."),
    ActionSpec("isolate_host", ActionTier.CONTAINMENT, "host", False, True, True,
               "Network-isolate a host; reversible."),
    ActionSpec("block_ip", ActionTier.CONTAINMENT, "ip", False, True, False,
               "Block an IP at the egress firewall."),
    ActionSpec("disable_account", ActionTier.CONTAINMENT, "account", False, True, False,
               "Disable a user/service account."),
    ActionSpec("kill_process", ActionTier.CONTAINMENT, "host", False, False, False,
               "Terminate a process on a host."),
    ActionSpec("quarantine_file", ActionTier.CONTAINMENT, "host", False, True, False,
               "Move a file to quarantine."),
    ActionSpec("wipe_host", ActionTier.DESTRUCTIVE, "host", True, False, True,
               "Wipe and reimage a host; destroys forensic state."),
    ActionSpec("delete_file", ActionTier.DESTRUCTIVE, "host", True, False, False,
               "Permanently delete a file."),
    ActionSpec("restore_from_backup", ActionTier.DESTRUCTIVE, "host", True, False, False,
               "Overwrite a host from backup; destroys current state."),
    ActionSpec("notify_regulator", ActionTier.DESTRUCTIVE, "none", False, False, False,
               "External regulatory notification; irreversible."),
]

CATALOG: dict[str, ActionSpec] = {s.name: s for s in _SPECS}

# Actions whose (incident, action, asset id) fully identifies WHAT is done, so an
# authorization's own scope binds it to a plan step. Every other action names a
# process, file, address or account the scope cannot express: its request must
# carry ``params.plan_step`` (Phase 5/6 binding rule).
ASSET_BOUND_ACTIONS = frozenset({"isolate_host", "preserve_disk_image", "notify_stakeholders"})


def get_action(name: str | None) -> ActionSpec | None:
    return CATALOG.get((name or "").strip())


# Keyword fallback for prose that names actions loosely ("wipe and reimage").
_KEYWORDS: list[tuple[str, re.Pattern[str]]] = [
    ("wipe_host", re.compile(r"\bwip(?:e|ing)\b|\bre-?imag", re.IGNORECASE)),
    ("isolate_host", re.compile(r"\bisolat", re.IGNORECASE)),
    ("preserve_disk_image", re.compile(
        r"\bpreserv|\bforensic image|\bdisk image|\bimaging\b", re.IGNORECASE)),
    ("notify_stakeholders", re.compile(r"\bnotif", re.IGNORECASE)),
]


def match_actions_in_text(text: str | None) -> list[str]:
    """Catalogue actions named in free text, in catalogue order.

    Exact tool names win: if any appear, only those are returned. Otherwise a
    small keyword table is used. Deterministic; used to scope vetoes and
    sign-off requests that name actions only in prose.
    """
    t = text or ""
    exact = [n for n in CATALOG if re.search(rf"\b{re.escape(n)}\b", t)]
    if exact:
        return exact
    return [n for n, pat in _KEYWORDS if pat.search(t)]
