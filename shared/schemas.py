"""Message-payload schemas for the WarRoom collaboration protocol (Phase 4).

Every operationally meaningful room message an agent posts is **human-readable
text followed by a single fenced ```json block** that validates against
``ProtocolMessage``. The text is for the live demo and the human CISO; the JSON
block is the machine-readable audit record the exporter (Phase 6) parses out of
the room history.

This module is the single source of truth for that block. The shape here is
mirrored verbatim into each agent's ``prompt.md`` — if you change a field,
change the prompts too (``shared/protocol.md`` §E lists where).

Pure Python + Pydantic; no Band/LLM/network dependency, so it is unit-testable
directly (``tests/test_schemas.py``).
"""

from __future__ import annotations

import json
import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class MessageType(str, Enum):
    """The kinds of protocol messages agents post.

    The lifecycle of a contested incident is:
    BRIEF → FINDING(s)/QUESTION(s) → SIGNOFF_REQUEST → SIGNOFF/VETO →
    (ESCALATION → human decision) → ACTION(s) → RESOLUTION.
    CLOSE is the proportional bottom end: Triage closes a false positive.
    """

    BRIEF = "BRIEF"               # Triage's kickoff incident brief + recruitment
    FINDING = "FINDING"           # a specialist's analysis result
    QUESTION = "QUESTION"         # cross-examination: one agent asks another
    SIGNOFF_REQUEST = "SIGNOFF_REQUEST"  # Commander asks specialists to approve a plan
    SIGNOFF = "SIGNOFF"           # a specialist approves the plan
    VETO = "VETO"                 # Compliance blocks an action, citing a regulation
    ESCALATION = "ESCALATION"     # Commander escalates a deadlock to the human CISO
    ACTION = "ACTION"             # Commander records an executed action
    RESOLUTION = "RESOLUTION"     # Commander closes the incident
    CLOSE = "CLOSE"               # Triage closes a false positive without recruiting


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Every protocol message carries these. Type-specific fields are optional so a
# single flat model covers all message types (matches the implementation plan's
# one-schema design and keeps the prompts simple).
class ProtocolMessage(BaseModel):
    """The JSON block every WarRoom room message carries.

    Required on every message: ``type``, ``incident``, ``summary``. Everything
    else is type-specific and optional. ``extra="allow"`` keeps an agent's stray
    extra key from failing the parse — robustness matters more than strictness
    when an LLM is producing these live.
    """

    type: MessageType
    incident: str = Field(..., description="Incident id or alias, e.g. 'INC-C-2026-0042'.")
    summary: str = Field(..., description="One- or two-sentence human-readable summary.")

    severity: Severity | None = Field(
        default=None, description="Set on BRIEF/FINDING; the assessed severity.")
    evidence: list[str] = Field(
        default_factory=list,
        description="Concrete supporting facts (tool outputs, IOCs, rule ids).")
    deadline_utc: str | None = Field(
        default=None, description="ISO-8601 regulatory deadline, when a clock is running.")
    decision: str | None = Field(
        default=None,
        description="The ruling/choice on SIGNOFF/VETO/ESCALATION/RESOLUTION.")
    regulation: str | None = Field(
        default=None, description="Cited rule id(s) for a VETO or a triggered obligation.")
    actions: list[str] = Field(
        default_factory=list,
        description="Action tool names executed/planned (ACTION, RESOLUTION).")
    recruited: list[str] = Field(
        default_factory=list,
        description="Specialists Triage recruited (BRIEF) — the reasoned roster.")
    mentions: list[str] = Field(
        default_factory=list,
        description="Handles this message @mentions, recorded for the audit trail.")

    model_config = {"use_enum_values": True, "extra": "allow"}

    # --- rendering -------------------------------------------------------
    def to_json_block(self, *, indent: int = 2) -> str:
        """Render as the fenced ```json block agents append to their message."""
        body = self.model_dump(exclude_none=True, exclude_defaults=False)
        return "```json\n" + json.dumps(body, indent=indent, default=str) + "\n```"


# Match a fenced code block, optionally tagged ```json, capturing the object.
_BLOCK_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)


def extract_blocks(content: str) -> list[ProtocolMessage]:
    """Parse every valid protocol JSON block out of a message body.

    Tolerant by design: a fenced block that isn't valid JSON, or valid JSON that
    doesn't satisfy ``ProtocolMessage`` (e.g. a tool dump the agent pasted), is
    skipped rather than raised. The exporter relies on this to walk a whole room
    history without choking on a single malformed message.
    """
    out: list[ProtocolMessage] = []
    for match in _BLOCK_RE.finditer(content or ""):
        raw = match.group(1)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict) or "type" not in data:
            continue
        try:
            out.append(ProtocolMessage.model_validate(data))
        except ValidationError:
            continue
    return out


def extract_block(content: str) -> ProtocolMessage | None:
    """The first valid protocol block in a message, or None."""
    blocks = extract_blocks(content)
    return blocks[0] if blocks else None


def example_block(message_type: MessageType, **fields: Any) -> str:
    """A rendered example block for use in prompts/docs."""
    base: dict[str, Any] = {"type": message_type, "incident": "INC-C-2026-0042",
                            "summary": "..."}
    base.update(fields)
    return ProtocolMessage.model_validate(base).to_json_block()
