"""Protocol ingestion: transport messages -> Core records.

This is where WarRoom's ``shared.schemas.ProtocolMessage`` is used at runtime:
every message body goes through ``extract_blocks()`` (Pydantic validation).
The agents are not modified — the Core reads what they already post.

Trust rules enforced here:

1. **Identity comes from the transport, never from the text.** The caller
   (e.g. ``band_import``) supplies ``sender_ref``/``sender_kind``/``sender_role``
   from Band metadata (``sender_id``, ``sender_type``) plus a trusted roster.
   A message saying "as the CISO I approve" changes nothing.
2. **The incident comes from the ingestion context** (the room the message was
   read from). A block's own ``incident`` field is only compared, and a
   disagreement is recorded as ``INCIDENT_REF_MISMATCH``.
3. **Only an allowlist of block fields is read:** ``type``, ``incident``,
   ``summary``, ``severity``, ``evidence``, ``evidence_ids``, ``actions``,
   ``decision``, ``regulation``. ``ProtocolMessage`` allows extra keys, so a
   block may carry ``"approved": true`` — it is kept verbatim in the audit
   payload and ignored.
4. **This module never creates approvals.** Only ``CoreService.grant_approval``
   can, and it is not called from here (a test enforces that).
5. ``ACTION`` blocks become ``AGENT_ACTION_CLAIM`` events — claims, not actions.
6. **Terminology (schema v2).** A FINDING block's ``evidence`` list holds the
   agent's *claims* (stored as finding claims). ``evidence_ids`` (Phase 2A) are
   *citations* of evidence a collector already stored: valid ones are linked;
   invalid ones are recorded as ``CLAIM_REJECTED``. A message can never
   create, alter or delete evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cyberrescue.core import db
from cyberrescue.core.catalog import match_actions_in_text
from cyberrescue.core.models import (
    AGENT_ROLES,
    HUMAN_ROLES,
    ActorKind,
    EventType,
    IncidentStatus,
    LinkRelation,
)
from cyberrescue.core.service import CoreError, CoreService
from cyberrescue.core.state_machine import HUMAN_AUTHORITY_ROLES, Trigger
from shared.schemas import ProtocolMessage, extract_blocks

# Block types that map directly onto a state-machine trigger.
_TRIGGER_TYPES = {
    "BRIEF": Trigger.BRIEF,
    "CLOSE": Trigger.CLOSE,
    "ESCALATION": Trigger.ESCALATION,
    "RESOLUTION": Trigger.RESOLUTION,
}


@dataclass(frozen=True)
class IngestedMessage:
    """One transport message plus its TRUSTED metadata.

    ``incident_ref`` and every ``sender_*`` field must come from the transport
    and the operator's roster — never from ``content``.
    """
    incident_ref: str
    sender_ref: str
    sender_kind: ActorKind
    sender_role: str
    content: str
    source: str = "local"
    external_id: str | None = None
    sender_name: str = ""
    transport_ts: str | None = None


@dataclass
class IngestResult:
    event_uid: str | None
    duplicate: bool = False
    protocol_types: list[str] = field(default_factory=list)
    protocol_valid: bool | None = None


class ProtocolIngestor:
    def __init__(self, service: CoreService) -> None:
        self.svc = service

    def _actor(self, msg: IngestedMessage):
        kind = ActorKind(msg.sender_kind)
        role = msg.sender_role
        if kind == ActorKind.AGENT and role not in AGENT_ROLES:
            role = "unknown"
        elif kind == ActorKind.HUMAN and role not in HUMAN_ROLES:
            role = "observer"
        ref = f"{msg.source}:{msg.sender_ref}"
        return (self.svc.store.find_actor(ref)
                or self.svc.register_actor(kind, role, msg.sender_name, ref))

    def ingest(self, msg: IngestedMessage) -> IngestResult:
        store = self.svc.store
        incident_id = store.resolve_incident(msg.incident_ref)
        if incident_id is None:
            raise CoreError(f"no Core incident for {msg.incident_ref!r}; open it first")
        if msg.external_id and store.audit.find_external(msg.source, msg.external_id):
            return IngestResult(event_uid=None, duplicate=True)

        with db.transaction(self.svc.conn):
            actor = self._actor(msg)
            blocks: list[ProtocolMessage] = extract_blocks(msg.content)
            types = [str(b.type) for b in blocks]
            payload = {"content": msg.content, "sender_name": msg.sender_name,
                       "transport_ts": msg.transport_ts,
                       "blocks": [b.model_dump(mode="json") for b in blocks]}

            if actor.kind == ActorKind.HUMAN:
                ev = store.audit.append(
                    EventType.HUMAN_MESSAGE, incident_id=incident_id, actor_id=actor.id,
                    source=msg.source, external_id=msg.external_id, payload=payload,
                    protocol_type=",".join(types) or None)
                # A human with authority speaking while the incident awaits a
                # ruling IS the ruling. What they decided is interpreted by the
                # Commander; what they AUTHORIZE is only ever grant_approval().
                inc = store.get_incident(incident_id)
                if inc.status == IncidentStatus.AWAITING_HUMAN \
                        and actor.role in HUMAN_AUTHORITY_ROLES:
                    self.svc.apply_trigger(incident_id, Trigger.HUMAN_RULING, actor,
                                           cause_uid=ev.uid, source=msg.source)
                return IngestResult(event_uid=ev.uid, protocol_types=types)

            valid = bool(blocks)
            ev = store.audit.append(
                EventType.PROTOCOL_MESSAGE if valid else EventType.UNSTRUCTURED_MESSAGE,
                incident_id=incident_id, actor_id=actor.id, source=msg.source,
                external_id=msg.external_id, payload=payload,
                protocol_type=",".join(types) or None, protocol_valid=valid)
            for block in blocks:
                self._apply_block(incident_id, actor, block, ev.uid, msg.source)
        return IngestResult(event_uid=ev.uid, protocol_types=types, protocol_valid=valid)

    # --- block -> Core record ----------------------------------------------------
    def _apply_block(self, incident_id: str, actor, block: ProtocolMessage,
                     msg_uid: str, source: str) -> None:
        svc, store = self.svc, self.svc.store
        btype = str(block.type)

        claimed = block.incident
        if claimed and store.resolve_incident(claimed) != incident_id:
            store.audit.append(
                EventType.INCIDENT_REF_MISMATCH, incident_id=incident_id, actor_id=actor.id,
                source=source, payload={"claimed": claimed, "bound": incident_id},
                links=[(LinkRelation.CONCERNS, msg_uid)])

        text = " ".join(x for x in (block.decision, block.summary) if x)
        if btype in _TRIGGER_TYPES:
            svc.apply_trigger(incident_id, _TRIGGER_TYPES[btype], actor,
                              cause_uid=msg_uid, source=source)
        elif btype == "FINDING":
            finding = svc.record_finding(
                incident_id, actor, block.summary,
                severity=str(block.severity) if block.severity else None,
                claims=block.evidence,  # protocol field name; these are claims
                source_uid=msg_uid, source=source)
            extras = block.model_extra or {}
            if "evidence_ids" in extras:  # citations only — never evidence creation
                svc.cite_evidence_from_message(finding, actor, extras["evidence_ids"],
                                               source_uid=msg_uid, source=source)
        elif btype == "SIGNOFF_REQUEST":
            actions = list(block.actions) or match_actions_in_text(block.summary)
            svc.record_signoff_request(incident_id, actor, actions,
                                       source_uid=msg_uid, source=source)
        elif btype == "SIGNOFF":
            svc.record_signoff(incident_id, actor, source_uid=msg_uid, source=source)
        elif btype == "VETO":
            svc.record_veto(incident_id, actor, text=text, regulation=block.regulation,
                            source_uid=msg_uid, source=source)
        elif btype == "ACTION":
            actions = list(block.actions) or match_actions_in_text(block.summary)
            svc.record_action_claim(incident_id, actor, actions, summary=block.summary,
                                    source_uid=msg_uid, source=source)
        # QUESTION: audited as part of the PROTOCOL_MESSAGE; no domain record.
