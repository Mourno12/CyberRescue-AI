"""Threat Intel domain tools: ``lookup_ioc`` and ``assess_spread_risk``.

Threat Intel is Tier-2 deep analysis. ``lookup_ioc`` returns the full dossier
for an indicator (actor, malware family, confidence, whether it self-
propagates). ``assess_spread_risk`` reasons about the *host's* position in the
estate — criticality, network segment, and which high-value neighbours are
reachable — to estimate lateral-movement blast radius. Together these drive
its 'isolate (and on INC-C, wipe) now' recommendation.

Layering matches the other agents: pure functions + a ``langchain_tools()``
builder for the LangGraph adapter.
"""

from __future__ import annotations

import json
from typing import Any

from shared.mock_data import get_asset, load_alert, load_assets, load_iocs

# Segments whose compromise implies a large blast radius (domain-wide creds,
# production data, core services).
HIGH_VALUE_SEGMENTS = {"corp-core", "prod-db", "prod-app", "prod-backup"}


def lookup_ioc(indicator: str) -> dict[str, Any]:
    """Return the full threat-intel dossier for an indicator, or a miss.

    Matches a hash, IP, or domain exactly against the IOC database.
    """
    for ioc in load_iocs():
        if ioc["indicator"].lower() == indicator.strip().lower():
            return {"matched": True, **ioc}
    return {
        "matched": False,
        "indicator": indicator,
        "note": "No match in the IOC database. Treat as unknown, not benign.",
    }


def assess_spread_risk(asset_id: str) -> dict[str, Any]:
    """Estimate lateral-movement risk if ``asset_id`` is compromised.

    Combines the host's own criticality/segment with the count of high-value
    hosts reachable from it. Returns a risk level and the reachable targets so
    the recommendation is explainable.
    """
    asset = get_asset(asset_id)
    if asset is None:
        return {"asset_id": asset_id, "found": False,
                "error": f"asset '{asset_id}' not in inventory"}

    segment = asset.get("network_segment", "")
    criticality = asset.get("criticality", "low")

    # Reachable high-value targets: other hosts in high-value segments. From a
    # high-value segment, treat all of them as reachable; otherwise only its own.
    if segment in HIGH_VALUE_SEGMENTS:
        reachable = [
            a["asset_id"] for a in load_assets()
            if a["asset_id"] != asset_id and a.get("network_segment") in HIGH_VALUE_SEGMENTS
        ]
    else:
        reachable = [
            a["asset_id"] for a in load_assets()
            if a["asset_id"] != asset_id and a.get("network_segment") == segment
        ]

    high_value = segment in HIGH_VALUE_SEGMENTS or criticality == "critical"

    if high_value and len(reachable) >= 2:
        risk = "critical"
    elif high_value:
        risk = "high"
    elif reachable:
        risk = "medium"
    else:
        risk = "low"

    # A reachable credential store / domain controller (holds "credentials")
    # means a live foothold can pivot to domain-wide takeover. Network isolation
    # CONTAINS the spread but does not ERADICATE an established foothold: on a
    # self-propagating threat that has already authenticated outward, the host
    # must be wiped/reimaged to be trustworthy again. This is what makes "just
    # isolate" insufficient and puts eradication on a collision course with an
    # evidence/legal hold.
    dc_reachable = any(
        "credentials" in (get_asset(a) or {}).get("data_classes", [])
        for a in reachable
    )
    eradication_requires_reimage = (risk == "critical") and dc_reachable

    rationale_bits = [
        f"host criticality={criticality}",
        f"segment={segment or 'unknown'}"
        + (" (high-value)" if segment in HIGH_VALUE_SEGMENTS else ""),
        f"{len(reachable)} reachable host(s) from this position",
    ]
    if risk in ("high", "critical"):
        rationale_bits.append(
            "containment is time-sensitive -- recommend immediate network isolation"
        )
    if eradication_requires_reimage:
        rationale_bits.append(
            "a domain controller / credential store is reachable: isolation "
            "contains but does NOT eradicate the foothold -- wipe + reimage is "
            "required to prevent domain-wide re-compromise"
        )

    return {
        "asset_id": asset_id,
        "found": True,
        "criticality": criticality,
        "network_segment": segment,
        "spread_risk": risk,
        "reachable_high_value_hosts": reachable,
        "containment_sufficient": not eradication_requires_reimage,
        "eradication_requires_reimage": eradication_requires_reimage,
        "rationale": "; ".join(rationale_bits) + ".",
    }


def analyze_incident(incident: str) -> dict[str, Any]:
    """One-call incident analysis keyed on the incident id — the deterministic path.

    Resolves the alert's **literal** indicators + asset_id from the alert data
    (by id/alias), runs ``lookup_ioc`` on every indicator and ``assess_spread_risk``
    on the asset, and returns the combined dossier. Threat Intel calls this with
    just the incident id (e.g. "INC-A"), which is reliably carried in the BRIEF —
    so the analysis never depends on copying hashes or asset ids out of prose. This
    closes the failure mode where the agent invented placeholder tool arguments
    (e.g. ``lookup_ioc("commodity_trojan_indicator")``) from a paraphrased brief.
    """
    try:
        alert = load_alert(incident)
    except (KeyError, FileNotFoundError) as e:
        return {"found": False, "incident": incident, "error": str(e)}

    indicators = alert.get("indicators", []) or []
    asset_id = alert.get("asset_id")
    ioc_results = [lookup_ioc(ind) for ind in indicators]
    spread = (assess_spread_risk(asset_id) if asset_id
              else {"found": False, "error": "no asset_id in alert"})
    matched = [r for r in ioc_results if r.get("matched")]

    return {
        "found": True,
        "incident_id": alert.get("incident_id", incident),
        "asset_id": asset_id,
        "indicators_analyzed": indicators,
        "ioc_results": ioc_results,
        "matched_iocs": matched,
        "spread_risk": spread,
        "summary": (
            f"{len(matched)}/{len(indicators)} indicator(s) matched the IOC DB; "
            f"spread_risk={spread.get('spread_risk', 'unknown')}, "
            f"eradication_requires_reimage="
            f"{spread.get('eradication_requires_reimage', False)}."
        ),
    }


# --- Framework wiring ------------------------------------------------------

def langchain_tools() -> list[Any]:
    """LangChain StructuredTools for the LangGraph adapter (additional_tools)."""
    from langchain_core.tools import StructuredTool

    def analyze_incident_tool(incident: str) -> str:
        return json.dumps(analyze_incident(incident), indent=2, default=str)

    def lookup_ioc_tool(indicator: str) -> str:
        return json.dumps(lookup_ioc(indicator), indent=2, default=str)

    def assess_spread_risk_tool(asset_id: str) -> str:
        return json.dumps(assess_spread_risk(asset_id), indent=2, default=str)

    return [
        StructuredTool.from_function(
            analyze_incident_tool,
            name="analyze_incident",
            description=(
                "PRIMARY tool — call this FIRST with just the incident id/alias "
                "(e.g. 'INC-A' or 'INC-A-2026-0039'). It resolves the alert's real "
                "indicators and asset_id internally and returns the full dossier: "
                "every IOC lookup, the matched threat actor/malware, and the host "
                "spread-risk assessment. Do NOT type out hashes or asset ids "
                "yourself — pass only the incident id and read the result."
            ),
        ),
        StructuredTool.from_function(
            lookup_ioc_tool,
            name="lookup_ioc",
            description=(
                "Look up one indicator of compromise (file hash, IP, or domain) in "
                "the threat-intel database. Returns the threat actor, malware family, "
                "confidence, status, and whether it self-propagates. Call once per "
                "indicator in the alert."
            ),
        ),
        StructuredTool.from_function(
            assess_spread_risk_tool,
            name="assess_spread_risk",
            description=(
                "Assess lateral-movement / spread risk for a compromised host by "
                "asset_id (e.g. 'srv-db-01'). Returns a risk level and the reachable "
                "high-value hosts. Use this to justify a containment recommendation."
            ),
        ),
    ]
