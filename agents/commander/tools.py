"""Commander action tools: ``isolate_host``, ``preserve_disk_image``,
``wipe_host``, ``notify_stakeholders``.

The Commander is the *only* agent with action tools — the single-action-
authority rule. Every call appends a timestamped JSON line to
``actions_log.jsonl`` at the repo root; that append IS "execution" for the
demo (the implementation plan: an isolate_host tool that writes a log line is
enough). The exporter reads this log for the "Actions taken" section.

Wiring: the Anthropic adapter takes ``additional_tools`` as
``(PydanticInputModel, callable)`` tuples and derives the tool name from the
model's class name. The input-model classes are therefore named exactly like
the tools (lowercase, underscores) so the LLM sees ``isolate_host`` etc.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from shared.config import REPO_ROOT


def _actions_log_path() -> Path:
    return Path(os.getenv("ACTIONS_LOG_PATH", str(REPO_ROOT / "actions_log.jsonl")))


def _cyberrescue_gate(action: str, details: dict[str, Any]) -> dict[str, Any] | None:
    """CyberRescue AI extension (Phase 1b): ask the CyberRescue Core first.

    ``CYBERRESCUE_GATE_MODE`` = ``shadow`` (default) logs the Core's policy
    decision and never changes what this tool does; ``enforce`` executes only
    what the Core authorizes. See ``cyberrescue/core/gate.py``. Imported lazily
    so WarRoom still runs without the ``cyberrescue`` package; in enforce mode
    a missing Core fails closed.
    """
    try:
        from cyberrescue.core.gate import check_commander_action
    except ImportError as e:
        if os.getenv("CYBERRESCUE_GATE_MODE", "").strip().lower() == "enforce":
            return {"proceed": False, "outcome": None, "reason":
                    f"CyberRescue Core unavailable in enforce mode ({e})"}
        return None
    return check_commander_action(action, details)


def _record_action(action: str, **details: Any) -> dict[str, Any]:
    """Append one action record to the log and return the confirmation."""
    gate = _cyberrescue_gate(action, details)
    if gate is not None and not gate.get("proceed", False):
        return {"status": "blocked_by_policy", "action": action, **details,
                "policy_outcome": gate.get("outcome"), "reason_blocked": gate.get("reason"),
                "note": "NOT executed: the CyberRescue Core did not authorize this action. "
                        "Obtain the required sign-offs / human approval, then retry."}
    record = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "actor": "commander",
        "action": action,
        **details,
    }
    path = _actions_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")
    return {"status": "executed", "logged_to": path.name, **record}


# --- Input models (class name == tool name) --------------------------------

class isolate_host(BaseModel):
    """Isolate a host from the network to stop spread. Non-destructive; the host
    stays powered on so it can still be imaged."""
    asset_id: str = Field(..., description="Host to isolate, e.g. 'srv-db-01'.")
    reason: str = Field(..., description="One-line justification for the audit log.")


class preserve_disk_image(BaseModel):
    """Capture a forensically sound disk image (and memory) of a host before any
    destructive remediation. Satisfies evidence-preservation obligations."""
    asset_id: str = Field(..., description="Host to image, e.g. 'srv-db-01'.")
    reason: str = Field(..., description="One-line justification for the audit log.")


class wipe_host(BaseModel):
    """Wipe and reimage a host. DESTRUCTIVE — destroys forensic state. Only run
    after sign-offs and only if no evidence-preservation hold applies."""
    asset_id: str = Field(..., description="Host to wipe, e.g. 'srv-db-01'.")
    reason: str = Field(..., description="One-line justification for the audit log.")


class notify_stakeholders(BaseModel):
    """Notify stakeholders (e.g. legal, the DPO, the CISO, customers) about the
    incident or a decision."""
    stakeholders: list[str] = Field(
        ..., description="Recipients, e.g. ['DPO', 'Legal', 'CISO'].")
    message: str = Field(..., description="The notification text.")


# --- Tool callables (receive a validated input model) ----------------------

def _isolate_host(inp: isolate_host) -> dict[str, Any]:
    return _record_action("isolate_host", asset_id=inp.asset_id, reason=inp.reason)


def _preserve_disk_image(inp: preserve_disk_image) -> dict[str, Any]:
    return _record_action("preserve_disk_image", asset_id=inp.asset_id, reason=inp.reason)


def _wipe_host(inp: wipe_host) -> dict[str, Any]:
    return _record_action("wipe_host", asset_id=inp.asset_id, reason=inp.reason)


def _notify_stakeholders(inp: notify_stakeholders) -> dict[str, Any]:
    return _record_action(
        "notify_stakeholders", stakeholders=inp.stakeholders, message=inp.message)


# --- Framework wiring ------------------------------------------------------

def anthropic_tools() -> list[tuple[type[BaseModel], Any]]:
    """(InputModel, callable) tuples for the Anthropic adapter (additional_tools)."""
    return [
        (isolate_host, _isolate_host),
        (preserve_disk_image, _preserve_disk_image),
        (wipe_host, _wipe_host),
        (notify_stakeholders, _notify_stakeholders),
    ]
