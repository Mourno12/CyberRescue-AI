"""Runtime patches for band-sdk 0.2.11 message-ack bugs.

Two related defects make an agent spin forever on a single message, logging
"Catching up missed message <id> via /next resync" indefinitely. This stalled
the INC-C demo twice (Compliance, then Commander). Root cause (verified against
the live API): the SDK lifecycle is mark_processing -> handle -> mark_processed,
and the server's `/processed` endpoint returns HTTP 422 when there is no active
processing attempt. On the FIRST message the attempt is gone by the time
mark_processed runs (it expired during the slow cold-start LLM call, and/or the
startup /next sync raced the WebSocket path for the same first message). The SDK
*swallows* that 422, marks the message processed only locally, and never acks it
server-side -- so /next returns it forever. The local dedupe stops re-handling,
so the spin makes no LLM calls (no token cost) but never ends.

Both fixes are monkeypatches (no SDK fork). Call ``apply_sdk_patches()`` once,
before ``Agent.create``.

1. ``ThenvoiLink.mark_processed`` -- on 422, re-establish the processing attempt
   (``mark_processing``) and retry ``mark_processed`` once. Fixes the cause: the
   message gets acked, so /next stops returning it.
2. ``ExecutionContext._get_next_message`` -- loop guard. Both catch-up loops
   (``_sync_via_next`` and ``_resync_pending_messages``) fetch through this one
   method, so if /next returns the same id N times in a row we force-ack it, mark
   it permanently-failed locally, and return None to break the loop. Defense in
   depth in case the 422 recovery itself fails.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("warroom.sdk_patches")

# After this many consecutive identical /next results, treat it as a stuck loop.
_LOOP_GUARD_THRESHOLD = 5

_APPLIED = False

import re as _re

# role -> Band handle, loaded from agent_config (cached).
_ROLE_HANDLES: dict[str, str] | None = None
# Default team if the incident can't be determined (safe superset).
_DEFAULT_ROLES = {"threat_intel", "compliance", "commander", "facilitator"}
_INC_RE = _re.compile(r"INC-[ABC]", _re.IGNORECASE)


def _role_handles() -> dict[str, str]:
    global _ROLE_HANDLES
    if _ROLE_HANDLES is not None:
        return _ROLE_HANDLES
    out: dict[str, str] = {}
    try:
        from shared.config import load_agent
        for role in ("triage", "threat_intel", "compliance", "commander", "facilitator"):
            try:
                h = load_agent(role).handle
                if h:
                    out[role] = h
            except Exception:  # noqa: BLE001 - role may be absent
                pass
    except Exception:  # noqa: BLE001
        pass
    _ROLE_HANDLES = out
    return out


def _extract_incident(text) -> str | None:
    """Pull an INC-A/B/C alias out of any string (room name, task_id, content)."""
    if not text:
        return None
    m = _INC_RE.search(str(text))
    return m.group(0).upper() if m else None


async def _incident_from_room(tools) -> str | None:
    """Fallback: find the incident id from the alert in the current room."""
    try:
        resp = await tools.rest.agent_api_context.get_agent_chat_context(
            chat_id=tools.room_id, page=1, page_size=50)
        for item in (resp.data or []):
            inc = _extract_incident(getattr(item, "content", "") or "")
            if inc:
                return inc
    except Exception as e:  # noqa: BLE001
        logger.warning("recruit: could not read room for incident id: %s", e)
    return None


async def _recommended_roles(tools, task_id) -> set[str]:
    """Roles to recruit for this incident — reasoned from classify_alert, not
    hardcoded. Resolves the incident from task_id (what Triage passes to
    create_chatroom) or, failing that, from the alert in the room."""
    inc = _extract_incident(task_id) or await _incident_from_room(tools)
    if inc:
        try:
            from agents.triage.tools import classify_alert
            res = classify_alert(inc)
            if res.get("disposition") == "close":
                return set()  # false positive: recruit nobody
            roles = set(res.get("recommended_specialists") or [])
            if roles:
                return roles | {"commander", "facilitator"}
        except Exception as e:  # noqa: BLE001
            logger.warning("recruit: classify_alert(%s) failed: %s", inc, e)
    return set(_DEFAULT_ROLES)  # safe fallback


def _is_422(exc: Exception) -> bool:
    if getattr(exc, "status_code", None) == 422:
        return True
    try:
        from thenvoi_rest.errors.unprocessable_entity_error import (
            UnprocessableEntityError,
        )
    except Exception:  # pragma: no cover - import shape varies
        return False
    return isinstance(exc, UnprocessableEntityError)


def apply_sdk_patches() -> None:
    """Idempotently install the band-sdk 0.2.11 ack-loop fixes."""
    global _APPLIED
    if _APPLIED:
        return

    import thenvoi.platform.link as link_mod
    from thenvoi.runtime.execution import ExecutionContext

    req_opts = link_mod.DEFAULT_REQUEST_OPTIONS
    Link = link_mod.ThenvoiLink

    # --- Fix 1: 422-recovering mark_processed --------------------------------
    async def mark_processed(self, room_id: str, message_id: str) -> None:
        msgs = self.rest.agent_api_messages
        try:
            await msgs.mark_agent_message_processed(
                chat_id=room_id, id=message_id, request_options=req_opts
            )
            return
        except Exception as e:  # noqa: BLE001 - branch on 422 vs other below
            if not _is_422(e):
                logger.warning(
                    "Failed to mark message %s as processed: %s", message_id, e
                )
                return
        # 422 == "no active processing attempt". Re-establish it and retry once.
        try:
            await msgs.mark_agent_message_processing(
                chat_id=room_id, id=message_id, request_options=req_opts
            )
            await msgs.mark_agent_message_processed(
                chat_id=room_id, id=message_id, request_options=req_opts
            )
            logger.info(
                "Recovered 422 ack for message %s (re-marked processing then "
                "processed)",
                message_id,
            )
        except Exception as e:  # noqa: BLE001 - last-resort, don't crash the loop
            logger.warning(
                "422-recovery failed for message %s: %s", message_id, e
            )

    Link.mark_processed = mark_processed

    # --- Fix 2: loop guard on the shared /next fetch -------------------------
    async def _get_next_message(self):
        msg = await self.link.get_next_message(self.room_id)
        if msg is None:
            self._wr_last_next_id = None
            self._wr_last_next_count = 0
            return None

        last = getattr(self, "_wr_last_next_id", None)
        count = getattr(self, "_wr_last_next_count", 0)
        count = count + 1 if msg.id == last else 1
        self._wr_last_next_id = msg.id
        self._wr_last_next_count = count

        if count >= _LOOP_GUARD_THRESHOLD:
            logger.warning(
                "Loop guard: /next returned %s %d times consecutively; "
                "force-acking and breaking the resync loop",
                msg.id,
                count,
            )
            try:
                await self.link.mark_processing(self.room_id, msg.id)
                await self.link.mark_processed(self.room_id, msg.id)
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "Loop guard force-ack failed for %s: %s", msg.id, e
                )
            try:
                self._retry_tracker.mark_permanently_failed(msg.id)
            except Exception:  # noqa: BLE001 - best effort
                pass
            self._wr_last_next_id = None
            self._wr_last_next_count = 0
            return None  # break the catch-up loop

        return msg

    ExecutionContext._get_next_message = _get_next_message

    # --- Fix 3: reasoned, deterministic recruitment via create_chatroom ------
    # Verified in the SDK: create_chatroom() makes an ORPHAN room —
    # add_participant()/send_message() are hard-bound to self.room_id (the room
    # where the agent received the message, which on the free-tier paste flow
    # already contains the human). So the incident actually runs in self.room_id;
    # the "created" rooms were never used, and they let gpt-4o Triage fragment the
    # team. gpt-4o reliably CALLS create_chatroom but unreliably calls
    # add_participant — so we repurpose create_chatroom: instead of an unused
    # orphan, it recruits — IN CODE, idempotently — exactly the specialists this
    # incident needs (classify_alert's recommended_specialists, + commander +
    # facilitator), then returns self.room_id. Reasoned (not hardcoded), so INC-A
    # gets no Compliance and INC-C does. Triage then only needs:
    # classify -> create_chatroom(incident_id) (auto-recruits) -> post the BRIEF.
    from thenvoi.runtime.tools import AgentTools

    async def create_chatroom(self, task_id=None):
        if getattr(self, "_wr_recruited", False):
            return self.room_id  # idempotent: team already recruited
        self._wr_recruited = True
        handles = _role_handles()
        roles = await _recommended_roles(self, task_id)
        added = []
        for role in sorted(roles):
            handle = handles.get(role)
            if not handle:
                continue
            try:
                await self.add_participant(handle)
                added.append(role)
            except Exception as e:  # noqa: BLE001 - already-present / lookup errors
                logger.warning("Recruit: add_participant(%s) failed: %s", handle, e)
        logger.info("Recruited %s into room %s", added, self.room_id)
        return self.room_id

    AgentTools.create_chatroom = create_chatroom

    _APPLIED = True
    logger.info("band-sdk 0.2.11 ack-loop + deterministic-recruit patches applied")
