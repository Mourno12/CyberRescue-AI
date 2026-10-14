"""Offline import of a Band room history into the Core.

Input is the Band agent-context JSON shape (``GET /agent/chats/{id}/context``,
as saved in ``shared/sample_message.json``): ``{"data": [message, ...]}`` or a
bare list. No network, no Band SDK — WarRoom's Band mode is untouched; this
only reads what a finished (or exported) run left behind.

Identity: each message's ``sender_id`` + ``sender_type`` (Band metadata) are
mapped to a role through an operator-supplied ``Roster``. A sender that is not
on the roster gets role ``unknown`` (agent) / ``observer`` (human) and can
therefore never sign off, veto, rule, or drive state.

Non-text messages (``tool_call`` / ``tool_result``) are skipped and counted in
Phase 1; a later phase can record tool results as evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberrescue.core.ids import legacy_alias_for, parse_incident_ref
from cyberrescue.core.ingest import IngestedMessage, ProtocolIngestor
from cyberrescue.core.models import ActorKind, Incident
from cyberrescue.core.service import CoreError, CoreService

SOURCE = "band"


@dataclass
class Roster:
    """Trusted mapping from Band ids to Core roles (operator-supplied)."""
    agents: dict[str, str] = field(default_factory=dict)   # sender_id -> agent role
    humans: dict[str, str] = field(default_factory=dict)   # sender_id -> human role
    default_human_role: str = "observer"

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> Roster:
        return cls(agents=dict(data.get("agents") or {}),
                   humans=dict(data.get("humans") or {}),
                   default_human_role=data.get("default_human_role", "observer"))

    @classmethod
    def from_file(cls, path: str | Path) -> Roster:
        text = Path(path).read_text(encoding="utf-8-sig")
        if str(path).endswith((".yaml", ".yml")):
            import yaml
            return cls.from_mapping(yaml.safe_load(text) or {})
        return cls.from_mapping(json.loads(text))

    def resolve(self, sender_id: str, sender_type: str) -> tuple[ActorKind, str]:
        if sender_type == "User":
            return ActorKind.HUMAN, self.humans.get(sender_id, self.default_human_role)
        return ActorKind.AGENT, self.agents.get(sender_id, "unknown")


@dataclass
class ImportReport:
    incident_id: str
    imported: int = 0
    duplicates: int = 0
    skipped_non_text: int = 0
    protocol_valid: int = 0
    unstructured: int = 0
    human: int = 0


def load_band_messages(source: str | Path | dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    if isinstance(source, (str, Path)):
        # Band exports saved from PowerShell carry a UTF-8 BOM.
        source = json.loads(Path(source).read_text(encoding="utf-8-sig"))
    if isinstance(source, dict):
        source = source.get("data") or []
    return sorted(source, key=lambda m: str(m.get("inserted_at") or ""))


def open_legacy_incident(service: CoreService, ref: str) -> Incident:
    """Open a WarRoom demo incident (INC-A/B/C) using WarRoom's own
    deterministic triage (``classify_alert``) for the recruited roster."""
    from agents.triage.tools import classify_alert
    from shared.mock_data import load_alert

    full = parse_incident_ref(ref)
    alias = legacy_alias_for(full or "")
    if alias is None:
        raise CoreError(f"{ref!r} is not a WarRoom demo incident (INC-A/B/C)")
    alert = load_alert(alias)
    verdict = classify_alert(alias)
    if service.store.get_asset(alert["asset_id"]) is None:
        service.seed_assets_from_mock()
    roles = [] if verdict["disposition"] == "close" else verdict["recommended_specialists"]
    return service.open_incident(
        alert["incident_id"], title=alert.get("title", ""),
        category=alert.get("category_hint"), severity=verdict.get("severity"),
        primary_asset_id=alert["asset_id"], recruited_roles=roles, source=SOURCE)


def import_band_context(service: CoreService, source: str | Path | dict[str, Any] | list[Any],
                        *, incident_ref: str, roster: Roster,
                        open_if_missing: bool = True) -> ImportReport:
    """Ingest a saved Band room into ``incident_ref`` (idempotent per message id)."""
    incident_id = service.store.resolve_incident(incident_ref)
    if incident_id is None:
        if not open_if_missing:
            raise CoreError(f"no Core incident for {incident_ref!r}")
        incident_id = open_legacy_incident(service, incident_ref).id

    report = ImportReport(incident_id=incident_id)
    ingestor = ProtocolIngestor(service)
    for m in load_band_messages(source):
        if (m.get("message_type") or "text") != "text":
            report.skipped_non_text += 1
            continue
        kind, role = roster.resolve(str(m.get("sender_id")), str(m.get("sender_type")))
        res = ingestor.ingest(IngestedMessage(
            incident_ref=incident_id, sender_ref=str(m.get("sender_id")),
            sender_kind=kind, sender_role=role, content=m.get("content") or "",
            source=SOURCE, external_id=m.get("id"), sender_name=m.get("sender_name") or "",
            transport_ts=m.get("inserted_at")))
        if res.duplicate:
            report.duplicates += 1
            continue
        report.imported += 1
        if kind == ActorKind.HUMAN:
            report.human += 1
        elif res.protocol_valid:
            report.protocol_valid += 1
        else:
            report.unstructured += 1
    return report
