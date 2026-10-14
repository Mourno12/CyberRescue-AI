"""Facilitator watchdog — keeps a WarRoom incident from stalling.

WarRoom agents are purely reactive: an agent runs its LLM only when a Band
message @mentions it, so the incident advances as a chain of @mentions. If a
message fails to name the next actor (or an agent analyses but never posts), the
room goes permanently idle. This driver is the out-of-band guarantee against
that: it watches the incident room and, when it goes quiet before RESOLUTION,
posts a targeted nudge AS THE FACILITATOR @mentioning whoever should act next.

It posts as a dedicated ``facilitator`` agent (register it on app.band.ai and
add it to agent_config.yaml; Triage adds it to every incident room). The driver
does NOT run an LLM — it only reads the transcript and posts deterministic
nudges, escalating to the human after repeated stalls.

Usage (from repo root, after the agents are up and an incident is live):
    .venv\\Scripts\\python.exe scripts\\incident_driver.py            # auto-detect room
    .venv\\Scripts\\python.exe scripts\\incident_driver.py --room <id>
    .venv\\Scripts\\python.exe scripts\\incident_driver.py --idle 45 --poll 20
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import time
from dataclasses import dataclass

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from shared.config import (  # noqa: E402
    ciso_user_id,
    handles_from_config,
    load_agent,
    read_agent_config,
    render_handles,
)

DEFAULT_BASE_URL = "https://app.band.ai"
SPECIALIST_ROLES = ("threat_intel", "compliance")  # who owes a FINDING in INC-C
TERMINAL_TYPES = {"RESOLUTION", "CLOSE"}

_JSON_BLOCK = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


@dataclass(frozen=True)
class Nudge:
    target: str   # a role key ("commander"/"threat_intel"/...) or "human"
    ask: str      # the instruction to post


@dataclass(frozen=True)
class ParsedMsg:
    role: str | None        # mapped role of the sender, or None (human/unknown)
    is_human: bool
    type: str | None        # protocol block type, or None (no/invalid block)
    text: str = ""          # lowercased message content (for keyword fallback)


def parse_block_type(content: str) -> str | None:
    """Return the `type` of the last fenced json protocol block, if any."""
    blocks = _JSON_BLOCK.findall(content or "")
    for raw in reversed(blocks):
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        t = obj.get("type")
        if isinstance(t, str):
            return t.upper()
    return None


# Beat detection is tolerant: it accepts the protocol json `type` OR role-scoped
# keywords, because the agents don't reliably emit clean json blocks (seen live:
# Commander posted "GATHERING"; Triage's BRIEF parsed as no-type). Keywords are
# scoped to the role that legitimately emits a beat, to limit false positives.

def _beat(p: ParsedMsg, beat: str) -> bool:
    if p.type == beat:
        return True
    t = p.text
    if beat == "BRIEF":
        return p.role == "triage" and ("brief" in t or "recruit" in t)
    if beat == "SIGNOFF_REQUEST":
        return p.role == "commander" and (
            "signoff_request" in t or "sign-off request" in t
            or "signoff request" in t or "please sign off" in t
            or "sign off on" in t or "requesting sign" in t)
    if beat == "VETO":
        return p.role == "compliance" and "veto" in t
    if beat == "ESCALATION":
        # Positive markers only — "no escalation needed" / "does not require
        # escalation" must NOT count (that false-positive stalled INC-A by routing
        # to the human for a ruling that wasn't needed).
        return p.role == "commander" and (
            "escalation:" in t or "escalating" in t or "escalate to" in t)
    if beat == "RESOLUTION":
        return p.role == "commander" and (
            "incident closed" in t or "incident is closed" in t
            or "incident resolved" in t or "has been resolved" in t)
    if beat == "CLOSE":
        return p.role == "triage" and "false positive" in t
    return False


def decide_nudge(parsed: list[ParsedMsg],
                 recruited: tuple[str, ...] = SPECIALIST_ROLES) -> Nudge | None:
    """Pure state machine (tolerant): given the incident transcript (oldest→
    newest), return the next nudge, or None if nothing is owed / the incident is
    done. Mirrors shared/protocol.md §E.2: BRIEF → FINDINGs → SIGNOFF_REQUEST →
    SIGNOFF/VETO → (ESCALATION → human ruling) → RESOLUTION.

    Robust to messy LLM output: a specialist counts as having contributed if it
    posted ANY message (not only a `type:FINDING` block), and beats are detected
    by `type` OR role-scoped keywords.
    """
    if any(_beat(p, "RESOLUTION") or _beat(p, "CLOSE") for p in parsed):
        return None  # incident closed — nothing to drive

    def first_idx(beat: str) -> int:
        for i, p in enumerate(parsed):
            if _beat(p, beat):
                return i
        return -1

    sr_idx = first_idx("SIGNOFF_REQUEST")
    esc_idx = first_idx("ESCALATION")
    veto = any(_beat(p, "VETO") for p in parsed)

    # A specialist has "contributed" if it has posted any message at all.
    contributed = {p.role for p in parsed if p.role in recruited}

    # Has the incident even started? (BRIEF, or any specialist/commander post.)
    started = (any(_beat(p, "BRIEF") for p in parsed) or bool(contributed)
               or sr_idx >= 0 or any(p.role == "commander" for p in parsed))
    if not started:
        return Nudge("triage", "classify the alert and post the BRIEF, recruiting "
                     "the specialists, so the incident can start.")

    # Escalation takes priority: once the Commander has escalated (which can happen
    # before every sign-off is in), the human ruling — then resolution — drives
    # everything. Don't fall back to chasing sign-offs after an escalation.
    if esc_idx >= 0:
        human_ruled = any(p.is_human for p in parsed[esc_idx + 1:])
        if not human_ruled:
            return Nudge("human", "the incident is escalated to you — please post "
                         "your decision so the Commander can resolve it.")
        return Nudge("commander", "the CISO has ruled — execute the approved "
                     "actions (call the action tools) and post the RESOLUTION.")

    # Phase: gather FINDINGs (until the Commander issues a SIGNOFF_REQUEST).
    if sr_idx < 0:
        missing = [r for r in recruited if r not in contributed]
        if missing:
            return Nudge(missing[0],
                         "post your FINDING now (call thenvoi_send_message) "
                         "@mentioning @merolavtech/commander — the Commander is "
                         "waiting on it to issue the SIGNOFF_REQUEST.")
        return Nudge("commander", "all specialist FINDINGs are in — post your "
                     "SIGNOFF_REQUEST @mentioning each specialist.")

    # Phase: collect sign-offs / veto AFTER the request (any post counts).
    decided = {p.role for p in parsed[sr_idx + 1:] if p.role in recruited}
    missing_decisions = [r for r in recruited if r not in decided]
    if missing_decisions:
        return Nudge(missing_decisions[0],
                     "respond to the Commander's SIGNOFF_REQUEST with a SIGNOFF "
                     "or a VETO @mentioning @merolavtech/commander.")

    # Veto with no escalation yet (esc_idx < 0 is guaranteed here — we returned
    # above if an escalation existed): push the Commander to escalate.
    if veto:
        return Nudge("commander", "Compliance has VETOed the contested action — "
                     "post one ESCALATION @mentioning the human CISO (@merolavtech).")

    return Nudge("commander", "all sign-offs are in — execute the plan and post "
                 "the RESOLUTION.")


# --------------------------------------------------------------------------- I/O

def _roster() -> dict[str, dict]:
    roster = {}
    for role in ("triage", "threat_intel", "compliance", "commander"):
        try:
            c = load_agent(role)
            roster[role] = {"id": c.agent_id, "handle": c.handle.lstrip("@"),
                            "name": role}
        except Exception:
            pass
    return roster


def _list_messages(client, room_id):
    msgs, page = [], 1
    while True:
        resp = client.agent_api_messages.list_agent_messages(
            chat_id=room_id, status="all", page=page, page_size=100)
        msgs.extend(resp.data)
        meta = resp.metadata
        if page >= (getattr(meta, "total_pages", None) or 1):
            break
        page += 1
    # oldest -> newest
    return sorted(msgs, key=lambda m: getattr(m, "inserted_at", "") or "")


def _recruited_specialists(client, room_id, roster) -> tuple[str, ...]:
    """Which specialist roles are ACTUALLY in this room — so the state machine
    only waits on specialists that were recruited (INC-A has no Compliance).
    Falls back to all specialists if participants can't be read."""
    try:
        parts = client.agent_api_participants.list_agent_chat_participants(
            chat_id=room_id).data
    except Exception:  # noqa: BLE001
        return SPECIALIST_ROLES
    ids = {getattr(p, "id", None) for p in parts}
    present = tuple(r for r in SPECIALIST_ROLES
                   if roster.get(r, {}).get("id") in ids)
    return present or SPECIALIST_ROLES


def _parse(messages, roster: dict[str, dict]) -> list[ParsedMsg]:
    id_to_role = {v["id"]: r for r, v in roster.items()}
    out = []
    for m in messages:
        is_human = getattr(m, "sender_type", "") == "User"
        role = id_to_role.get(getattr(m, "sender_id", None))
        content = getattr(m, "content", "") or ""
        out.append(ParsedMsg(role=role, is_human=is_human,
                             type=parse_block_type(content),
                             text=content.lower()))
    return out


def _discover_room(client, explicit: str | None):
    if explicit:
        return explicit
    resp = client.agent_api_chats.list_agent_chats(page=1, page_size=100)
    rooms = sorted(resp.data, key=lambda r: getattr(r, "updated_at", "") or "",
                   reverse=True)
    if not rooms:
        return None
    return rooms[0].id  # most recently active room the Facilitator is in


def _human_mention(client, room_id, ciso_handle: str = "", ciso_id: str | None = None):
    """Resolve the human (CISO) from the room PARTICIPANTS (not the transcript —
    the human posts the alert in the intake room, so it may not appear here).

    CyberRescue: when agent_config.yaml names the CISO (``humans.ciso``), only
    that user is mentioned; the handle fallback is the configured one."""
    try:
        resp = client.agent_api_participants.list_agent_chat_participants(chat_id=room_id)
        for p in resp.data:
            if getattr(p, "type", "") != "User":
                continue
            if ciso_id and p.id != ciso_id:
                continue
            return {"id": p.id,
                    "handle": (getattr(p, "handle", None) or ciso_handle).lstrip("@"),
                    "name": getattr(p, "name", None) or "CISO"}
    except Exception:
        pass
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Facilitator watchdog for a WarRoom incident.")
    ap.add_argument("--room", default=None, help="Incident room id (default: auto-detect).")
    ap.add_argument("--idle", type=int, default=45, help="Seconds of silence before nudging.")
    ap.add_argument("--poll", type=int, default=20, help="Seconds between polls.")
    ap.add_argument("--max-nudges-per-state", type=int, default=3,
                    help="Stop nudging the same state after N tries (then escalate to human).")
    args = ap.parse_args(argv)

    try:
        from thenvoi_rest import RestClient
        from thenvoi_rest.types.chat_message_request import ChatMessageRequest
        from thenvoi_rest.types.chat_message_request_mentions_item import (
            ChatMessageRequestMentionsItem,
        )
    except ImportError:
        print("[driver] thenvoi_rest not installed in this interpreter.", file=sys.stderr)
        return 2

    try:
        fac = load_agent("facilitator")
    except Exception as e:
        print(f"[driver] facilitator agent not configured: {e}\n"
              "[driver] Register a 'Facilitator' External Agent on app.band.ai and add it "
              "to agent_config.yaml (see agent_config.yaml.example).", file=sys.stderr)
        return 2

    # CyberRescue: nudge texts name upstream handles; render the configured ones.
    try:
        cfg = read_agent_config(None)
        handles = handles_from_config(cfg)
    except Exception as e:
        print(f"[driver] {e}", file=sys.stderr)
        return 2
    ciso_id = ciso_user_id(cfg)

    client = RestClient(api_key=fac.api_key, base_url=DEFAULT_BASE_URL)
    roster = _roster()

    room = _discover_room(client, args.room)
    if not room:
        print("[driver] no incident room yet — waiting for Triage to create one and "
              "add the Facilitator (Ctrl-C to stop)...")
        while not room:
            time.sleep(args.poll)
            try:
                room = _discover_room(client, args.room)
            except Exception as e:
                print(f"[driver] discover error: {e}", file=sys.stderr)
    print(f"[driver] watching room {room} | idle>{args.idle}s | poll {args.poll}s")

    def post(text: str, mentions: list[dict]) -> None:
        items = [ChatMessageRequestMentionsItem(id=m["id"], handle=m["handle"],
                                                name=m["name"]) for m in mentions]
        tags = " ".join(f"@{m['handle']}" for m in mentions)
        client.agent_api_messages.create_agent_chat_message(
            chat_id=room,
            message=ChatMessageRequest(
                content=f"{tags} [Facilitator] {render_handles(text, handles)}",
                mentions=items))

    last_seen_count = 0
    quiet_since = time.time()
    state_key = None
    state_nudges = 0

    while True:
        try:
            messages = _list_messages(client, room)
        except Exception as e:
            print(f"[driver] list error: {e}", file=sys.stderr)
            time.sleep(args.poll)
            continue

        if len(messages) != last_seen_count:
            last_seen_count = len(messages)
            quiet_since = time.time()  # new activity → reset the idle timer

        parsed = _parse(messages, roster)
        if any(p.type in TERMINAL_TYPES for p in parsed):
            print("[driver] incident reached RESOLUTION/CLOSE — done.")
            return 0

        idle_for = time.time() - quiet_since
        if idle_for < args.idle:
            time.sleep(args.poll)
            continue

        recruited = _recruited_specialists(client, room, roster)
        nudge = decide_nudge(parsed, recruited)
        if nudge is None:
            time.sleep(args.poll)
            continue

        # Track repeated nudging of the same state; escalate to human if stuck.
        key = (nudge.target, nudge.ask)
        if key == state_key:
            state_nudges += 1
        else:
            state_key, state_nudges = key, 1

        target = nudge.target
        if state_nudges > args.max_nudges_per_state and target != "human":
            target, ask = "human", (f"the incident is stuck waiting on "
                                     f"{nudge.target} ({nudge.ask}). Please intervene.")
        else:
            ask = nudge.ask

        if target == "human":
            hm = _human_mention(client, room, handles["ciso"], ciso_id)
            mentions = [hm] if hm else []
        else:
            r = roster.get(target)
            mentions = [{"id": r["id"], "handle": r["handle"], "name": r["name"]}] if r else []

        if not mentions:
            print(f"[driver] cannot resolve mention for '{target}'; skipping.", file=sys.stderr)
            time.sleep(args.poll)
            continue

        try:
            post(ask, mentions)
            print(f"[driver] nudged {target} (idle {idle_for:.0f}s, try {state_nudges}): {ask[:80]}")
        except Exception as e:
            print(f"[driver] post error: {e}", file=sys.stderr)

        quiet_since = time.time()  # don't re-nudge until the next idle window
        time.sleep(args.poll)


if __name__ == "__main__":
    raise SystemExit(main())
