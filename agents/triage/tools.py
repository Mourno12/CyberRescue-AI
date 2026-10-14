"""Triage domain tools: ``classify_alert`` and ``lookup_asset``.

Triage is Tier-1: it does *shallow* enrichment (severity, whether indicators
are known-bad vs whitelisted, whether the asset holds regulated data) and from
that decides the disposition and which specialists to recruit. It deliberately
does NOT do the deep actor/spread analysis (Threat Intel's job) or the
regulatory-clock reasoning (Compliance's job) — that asymmetry is what forces
the agents to talk in-room.

Layering (same in all four agents):
  * pure functions (``classify_alert`` / ``lookup_asset``) — framework-free,
    return plain dicts, unit-tested directly.
  * ``langchain_tools()`` — wraps them as LangChain StructuredTools for the
    LangGraph adapter's ``additional_tools=[...]``.
"""

from __future__ import annotations

import json
from typing import Any

from shared.mock_data import get_asset, load_alert, load_iocs

# Data classes that put an incident in scope for a notification regulation
# (GDPR/SEC/HIPAA). Used to decide whether Compliance must be recruited.
REGULATED_DATA_CLASSES = {"customer_pii", "employee_pii", "financial", "phi", "health"}


def _indicator_status(indicator: str) -> str:
    """Shallow IOC membership check: 'malicious' | 'benign' | 'unknown'.

    This is intentionally coarse — Triage only learns *whether* an indicator is
    known-bad, never who's behind it. Threat Intel's ``lookup_ioc`` returns the
    full dossier.
    """
    for ioc in load_iocs():
        if ioc["indicator"].lower() == indicator.lower():
            if ioc.get("status") == "benign":
                return "benign"
            if ioc.get("confidence") in (None, "none"):
                return "benign"
            return "malicious"
    return "unknown"


def classify_alert(incident: str) -> dict[str, Any]:
    """Classify an alert and recommend a disposition + who to recruit.

    Reads the alert file, does a shallow IOC check on its indicators, and cross-
    references the affected asset's data classes. Returns a structured triage
    verdict the Triage agent posts as its kickoff brief.
    """
    alert = load_alert(incident)
    asset_id = alert.get("asset_id", "")
    asset = get_asset(asset_id)

    indicators = alert.get("indicators", [])
    statuses = {ind: _indicator_status(ind) for ind in indicators}
    malicious = [i for i, s in statuses.items() if s == "malicious"]
    benign = [i for i, s in statuses.items() if s == "benign"]

    data_classes = asset.get("data_classes", []) if asset else []
    regulated = sorted(set(data_classes) & REGULATED_DATA_CLASSES)
    pii_involved = bool(regulated)

    severity_hint = alert.get("severity_hint", "medium")
    category = alert.get("category_hint", "unknown")

    # False positive: nothing known-malicious and the sensor only fired low.
    if not malicious and severity_hint in ("low", "info"):
        return {
            "incident_id": alert.get("incident_id", incident),
            "disposition": "close",
            "is_false_positive": True,
            "severity": "informational",
            "category": category,
            "asset_id": asset_id,
            "pii_involved": pii_involved,
            "malicious_indicators": malicious,
            "benign_indicators": benign,
            "recommended_specialists": [],
            "rationale": (
                "All indicators are whitelisted/benign in the IOC database and the "
                "sensor severity is low. No malware, lateral movement, or data "
                "exposure. Close at triage; no specialist recruitment needed."
            ),
        }

    # Real incident: set severity (escalate to critical if regulated data + active malware).
    if pii_involved and malicious:
        severity = "critical"
    elif severity_hint == "critical":
        severity = "critical"
    elif malicious:
        severity = "high" if severity_hint in ("high", "critical") else "medium"
    else:
        severity = severity_hint

    # Recruit reasoning (the recruitment must be *reasoned*, not hardcoded):
    specialists = ["commander"]  # always synthesize/execute through the Commander
    reasons = []
    if malicious or category in ("ransomware", "malware", "intrusion"):
        specialists.insert(0, "threat_intel")
        reasons.append(
            f"{len(malicious)} known-malicious indicator(s) → Threat Intel for "
            "actor attribution and spread assessment"
        )
    if pii_involved:
        specialists.insert(0, "compliance")
        reasons.append(
            f"asset holds regulated data {regulated} → Compliance for notification "
            "obligations and evidence-preservation rules"
        )
    if not reasons:
        reasons.append("active detection requiring Commander synthesis")

    return {
        "incident_id": alert.get("incident_id", incident),
        "disposition": "investigate",
        "is_false_positive": False,
        "severity": severity,
        "category": category,
        "asset_id": asset_id,
        "asset_role": asset.get("role") if asset else None,
        "data_classes": data_classes,
        "pii_involved": pii_involved,
        "malicious_indicators": malicious,
        "benign_indicators": benign,
        "recommended_specialists": specialists,
        "rationale": "; ".join(reasons) + ".",
    }


def lookup_asset(asset_id: str) -> dict[str, Any]:
    """Return the inventory record for a host, or a not-found marker."""
    asset = get_asset(asset_id)
    if asset is None:
        return {"asset_id": asset_id, "found": False,
                "error": f"asset '{asset_id}' not in inventory"}
    return {"found": True, **asset}


# --- Framework wiring ------------------------------------------------------

def langchain_tools() -> list[Any]:
    """LangChain StructuredTools for the LangGraph adapter (additional_tools)."""
    from langchain_core.tools import StructuredTool

    def classify_alert_tool(incident: str) -> str:
        return json.dumps(classify_alert(incident), indent=2, default=str)

    def lookup_asset_tool(asset_id: str) -> str:
        return json.dumps(lookup_asset(asset_id), indent=2, default=str)

    return [
        StructuredTool.from_function(
            classify_alert_tool,
            name="classify_alert",
            description=(
                "Classify a security alert by its id/alias (e.g. 'INC-C'). Returns "
                "severity, disposition (close | investigate), whether regulated data "
                "is involved, and which specialists to recruit. Call this first when "
                "you receive an alert."
            ),
        ),
        StructuredTool.from_function(
            lookup_asset_tool,
            name="lookup_asset",
            description=(
                "Look up a host in the asset inventory by asset_id (e.g. 'srv-db-01'). "
                "Returns role, criticality, owner, and data classes."
            ),
        ),
    ]
