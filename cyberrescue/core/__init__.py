"""CyberRescue Core — the deterministic source of truth for CyberRescue AI.

LLM agents are reasoning components: they *propose*. The Core records what was
said (append-only, hash-chained audit log), holds the authoritative incident
state, and decides — via a pure, deterministic policy engine — whether an
action is allowed. Only a registered human, through
``CoreService.grant_approval()``, can create an approval.

The Core never imports the Band SDK or any LLM client; WarRoom's Band mode is
untouched by it.
"""

from cyberrescue.core.ids import (
    LEGACY_ALIASES,
    generate_incident_id,
    is_valid_incident_id,
    parse_incident_ref,
)
from cyberrescue.core.models import (
    ActionStatus,
    ActionTier,
    ActorKind,
    EventType,
    IncidentStatus,
    LinkRelation,
    PolicyOutcome,
)
from cyberrescue.core.policy import PolicyConfig, PolicyEngine
from cyberrescue.core.service import ApprovalError, CoreError, CoreService

open_core = CoreService.open

__all__ = [
    "LEGACY_ALIASES",
    "ActionStatus",
    "ActionTier",
    "ActorKind",
    "ApprovalError",
    "CoreError",
    "CoreService",
    "EventType",
    "IncidentStatus",
    "LinkRelation",
    "PolicyConfig",
    "PolicyEngine",
    "PolicyOutcome",
    "generate_incident_id",
    "is_valid_incident_id",
    "open_core",
    "parse_incident_ref",
]
