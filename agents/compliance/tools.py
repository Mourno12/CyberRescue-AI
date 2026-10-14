"""Compliance domain tools.

Three tools, all reading ``shared/mock_env/reg_rules.json`` + the asset
inventory:

  * ``check_regulatory_triggers`` — which notification regimes (GDPR/SEC/HIPAA)
    an incident triggers, based on the affected host's data classes.
  * ``start_notification_clock`` — turn a triggered rule into a concrete
    deadline timestamp (the regulatory-clock drama in Phase 5 builds on this).
  * ``evidence_preservation_requirements`` — whether a forensically sound image
    must be captured before destructive remediation. This is the basis for
    Compliance's veto of a wipe on a PII host.

Layering matches the other agents: pure functions + a ``pydantic_ai_tools()``
builder. The Pydantic AI adapter registers tools via ``agent.tool(fn)``, which
requires a ``RunContext`` first parameter — so the wrappers take ``ctx`` and
ignore it; the pure functions below do the real work and are unit-tested
directly.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic_ai import RunContext

from shared import reg_clock
from shared.mock_data import get_asset, list_alerts, load_alert, load_reg_rules

_INC_RE = re.compile(r"INC-[ABC]", re.IGNORECASE)


def _norm_incident(incident: str) -> str:
    """Normalise an incident arg to its INC-A/B/C alias so the clock key is stable
    whether the LLM passes 'INC-C' or 'INC-C-2026-0042'."""
    m = _INC_RE.search(str(incident or ""))
    return m.group(0).upper() if m else str(incident or "")


def _resolve_alert(incident: str) -> dict[str, Any] | None:
    """Resolve an alert from an incident alias/id OR the affected asset id.

    The Compliance LLM sometimes passes the host (e.g. 'srv-db-01') or a free-text
    paraphrase instead of the incident alias. Recover instead of raising — a raise
    here propagates out of the tool, fails the whole message, and stalls the
    incident (observed: Compliance never started the clock / posted its veto).
    """
    try:
        return load_alert(incident)
    except (KeyError, FileNotFoundError):
        pass
    # Maybe they passed the affected asset id — find the alert that names it.
    arg = str(incident or "").strip().lower()
    for fname in list_alerts():
        try:
            data = load_alert(fname)
        except (KeyError, FileNotFoundError):
            continue
        if str(data.get("asset_id", "")).lower() == arg:
            return data
    return None


def _affected_data_classes(incident: str) -> tuple[str | None, list[str]]:
    """(asset_id, data_classes) for the host named in an incident's alert, or
    ``(None, [])`` if the incident arg can't be resolved."""
    alert = _resolve_alert(incident)
    if alert is None:
        return None, []
    asset_id = alert.get("asset_id", "")
    asset = get_asset(asset_id)
    return asset_id, (asset.get("data_classes", []) if asset else [])


def check_regulatory_triggers(incident: str) -> dict[str, Any]:
    """Return the regulatory obligations an incident triggers.

    Matches the affected host's data classes against every rule's trigger and
    returns the obligation, deadline, and evidence-preservation flag for each
    match.
    """
    asset_id, data_classes = _affected_data_classes(incident)
    if asset_id is None:
        return {
            "incident": incident,
            "triggered": [],
            "error": (f"could not resolve incident '{incident}'. Re-call with the "
                      "incident alias (INC-A / INC-B / INC-C) or its full id — not a "
                      "free-text description or the host name alone."),
            "summary": f"Unresolved incident '{incident}'; re-call with the INC alias.",
        }
    dc = set(data_classes)

    triggered = []
    for rule in load_reg_rules():
        trigger_classes = set(rule.get("trigger", {}).get("data_classes", []))
        matched = sorted(dc & trigger_classes)
        if matched:
            triggered.append({
                "rule_id": rule["rule_id"],
                "name": rule["name"],
                "jurisdiction": rule["jurisdiction"],
                "matched_data_classes": matched,
                "obligation": rule["obligation"],
                "deadline": rule["deadline"],
                "evidence_preservation_required": rule.get(
                    "evidence_preservation_required", False),
                "authority": rule.get("authority"),
            })

    return {
        "incident": incident,
        "asset_id": asset_id,
        "data_classes": sorted(dc),
        "triggered": triggered,
        "any_evidence_preservation_required": any(
            t["evidence_preservation_required"] for t in triggered),
        "summary": (
            f"{len(triggered)} regulatory obligation(s) triggered."
            if triggered else
            "No notification regimes triggered by this asset's data classes."
        ),
    }


def _add_business_days(start: datetime, days: int) -> datetime:
    """Add N business days, skipping Saturdays and Sundays."""
    current = start
    remaining = days
    while remaining > 0:
        current = current + timedelta(days=1)
        if current.weekday() < 5:  # Mon-Fri
            remaining -= 1
    return current


def start_notification_clock(
    regulation: str, incident: str, now: datetime | None = None
) -> dict[str, Any]:
    """Compute the deadline for a regulation and start its notification clock.

    ``regulation`` may be a rule_id (e.g. 'GDPR-ART-33') or part of a rule name.
    ``now`` defaults to the current UTC time (parameterised for testing).
    """
    now = now or datetime.now(timezone.utc)
    reg_key = regulation.strip().lower()

    rule = None
    for r in load_reg_rules():
        if r["rule_id"].lower() == reg_key or reg_key in r["name"].lower():
            rule = r
            break
    if rule is None:
        return {"regulation": regulation, "started": False,
                "error": f"no regulatory rule matching '{regulation}'"}

    deadline = rule["deadline"]
    value, unit = deadline["value"], deadline["unit"]
    if unit == "hours":
        deadline_dt = now + timedelta(hours=value)
    elif unit == "days":
        deadline_dt = now + timedelta(days=value)
    elif unit == "business_days":
        deadline_dt = _add_business_days(now, value)
    else:  # "immediate"
        deadline_dt = now

    # Persist the clock ONCE per (incident, regulation) so the deadline is fixed
    # and subsequent turns show a live countdown. Idempotent: re-calling returns
    # the original deadline + the current T-minus (the clock does not restart).
    inc = _norm_incident(incident)
    rec = reg_clock.start_clock(
        incident=inc, regulation=rule["rule_id"], name=rule["name"],
        deadline_utc=deadline_dt.isoformat(), window=f"{value} {unit}", now=now)

    return {
        "regulation": rule["rule_id"],
        "name": rule["name"],
        "incident": inc,
        "started": True,
        "started_utc": rec["started_utc"],
        "deadline_utc": rec["deadline_utc"],
        "t_minus": rec["t_minus"],
        "window": f"{value} {unit}",
        "obligation": rule["obligation"],
        "authority": rule.get("authority"),
    }


def regulatory_clock_status(incident: str, now: datetime | None = None) -> dict[str, Any]:
    """Live status of every notification clock running for an incident, with the
    current T-minus (or BREACHED). Call this on later turns to post 'T-minus'
    reminders without restarting the clocks."""
    inc = _norm_incident(incident)
    clocks = reg_clock.clock_status(inc, now=now)
    return {
        "incident": inc,
        "clocks": clocks,
        "any_breached": any(c.get("breached") for c in clocks),
        "summary": (
            "; ".join(f"{c['regulation']}: {c['t_minus']}" for c in clocks)
            if clocks else "No notification clocks running for this incident."
        ),
    }


def evidence_preservation_requirements(asset_id: str) -> dict[str, Any]:
    """Return forensic evidence-preservation requirements for a host.

    If the host holds regulated data, a forensically sound disk image and a
    volatile-memory capture must be taken BEFORE any destructive remediation
    (wipe/reimage). This is what justifies blocking a wipe.
    """
    asset = get_asset(asset_id)
    if asset is None:
        return {"asset_id": asset_id, "found": False,
                "error": f"asset '{asset_id}' not in inventory"}

    data_classes = set(asset.get("data_classes", []))
    triggering_rules = [
        {"rule_id": r["rule_id"], "name": r["name"]}
        for r in load_reg_rules()
        if r.get("evidence_preservation_required")
        and data_classes & set(r.get("trigger", {}).get("data_classes", []))
    ]
    required = bool(triggering_rules)

    # A subset of those rules impose a litigation/regulatory HOLD on the host
    # itself: imaging does NOT release it, and destroying the host needs a human
    # officer's authorization. This is what makes "image then wipe" insufficient
    # and forces an escalation rather than a clean sequencing of actions.
    hold_rules = [
        {"rule_id": r["rule_id"], "name": r["name"]}
        for r in load_reg_rules()
        if r.get("requires_human_authorization_to_destroy")
        and data_classes & set(r.get("trigger", {}).get("data_classes", []))
    ]
    human_auth_required = bool(hold_rules)

    return {
        "asset_id": asset_id,
        "found": True,
        "data_classes": sorted(data_classes),
        "preservation_required": required,
        "blocks_destructive_actions": ["wipe_host", "reimage"] if required else [],
        "required_artifacts": (
            ["forensic disk image", "volatile memory capture"] if required else []),
        "triggering_rules": triggering_rules,
        # Legal-hold semantics: when true, a forensic image is NOT a substitute
        # for retaining the host, and only a human can authorize destruction.
        "requires_human_authorization_to_destroy": human_auth_required,
        "image_satisfies_hold": not human_auth_required,
        "hold_rules": hold_rules,
        "rationale": (
            "Host is under an active litigation/regulatory hold. A forensic "
            "image does NOT release the hold; the host must be retained intact. "
            "Wiping/reimaging requires explicit human (DPO/General Counsel/CISO) "
            "authorization -- it cannot be resolved by imaging first."
            if human_auth_required else
            "Host holds regulated data; destroying it before imaging risks "
            "spoliation and breaks the notification evidence chain. Preserve "
            "before any wipe/reimage."
            if required else
            "No regulated data on this host; standard remediation may proceed "
            "without a mandatory forensic image."
        ),
    }


# --- Framework wiring ------------------------------------------------------

# Module-level aliases so the nested Pydantic AI wrappers can call the pure
# functions without the inner ``def`` shadowing the name (Python function-scope
# would otherwise make the bare name a local).
_triggers_impl = check_regulatory_triggers
_clock_impl = start_notification_clock
_evidence_impl = evidence_preservation_requirements
_clock_status_impl = regulatory_clock_status


def pydantic_ai_tools() -> list[Any]:
    """Pydantic-AI-compatible tool callables for the adapter (additional_tools).

    The adapter registers these with ``agent.tool``, which passes a RunContext
    as the first argument — accepted and ignored here.
    """

    def check_regulatory_triggers(ctx: RunContext, incident: str) -> str:
        """Return the notification regimes (GDPR/SEC/HIPAA) an incident triggers,
        based on the affected host's data classes. Pass the incident id/alias
        (e.g. 'INC-C')."""
        return json.dumps(_triggers_impl(incident), indent=2, default=str)

    def start_notification_clock(ctx: RunContext, regulation: str, incident: str) -> str:
        """Start the statutory notification clock for a regulation and return its
        deadline + current T-minus. 'regulation' is a rule_id (e.g. 'GDPR-ART-33').
        Idempotent: the deadline is fixed on the first call and does not restart."""
        return json.dumps(_clock_impl(regulation, incident), indent=2, default=str)

    def regulatory_clock_status(ctx: RunContext, incident: str) -> str:
        """Live status (T-minus / BREACHED) of all notification clocks running for
        an incident. Call this on later turns to post 'T-minus' reminders."""
        return json.dumps(_clock_status_impl(incident), indent=2, default=str)

    def evidence_preservation_requirements(ctx: RunContext, asset_id: str) -> str:
        """Return whether a forensic image must be preserved before destructive
        remediation on a host (e.g. 'srv-db-01'). Use this to justify blocking a
        wipe."""
        return json.dumps(_evidence_impl(asset_id), indent=2, default=str)

    return [
        check_regulatory_triggers,
        start_notification_clock,
        regulatory_clock_status,
        evidence_preservation_requirements,
    ]
