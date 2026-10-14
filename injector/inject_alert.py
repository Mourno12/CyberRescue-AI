"""Fire a scripted alert at the Triage agent to kick off an incident.

This is the demo's starting gun: it posts a SOC-style alert to Triage,
and exits. Triage reads the alert and creates the incident war room,
recruiting the specialists it needs (see ``shared/protocol.md`` §E).

    python -m injector.inject_alert INC-C
    python -m injector.inject_alert INC-A
    python -m injector.inject_alert INC-C --dry-run   # just print the message

How it posts
------------
**Note**: Band's free tier blocks human API access (creating rooms via user key).
The injector falls back to printing the alert message for manual paste into Band.

Automatic posting requires Band Enterprise tier. For demos, the manual fallback
works: copy the printed alert, paste it into an intake room (or any room with
Triage) in the Band UI, and Triage will read it and create the incident room.

Running without BAND_INJECTOR_API_KEY or with --dry-run prints the ready-to-paste
message and instructions.
"""

from __future__ import annotations

import argparse
import os
import sys

from shared.config import load_agent
from shared.mock_data import list_alerts, load_alert

DEFAULT_BASE_URL = "https://app.band.ai"  # Verified in Phase 0; see shared/protocol.md §A.0


def build_alert_message(incident: str) -> tuple[str, dict]:
    """Return (human-readable alert text, the loaded alert dict)."""
    alert = load_alert(incident)
    inc_id = alert.get("incident_id", incident)
    indicators = ", ".join(alert.get("indicators", [])) or "none"
    obs = alert.get("observations", [])
    obs_block = "\n".join(f"  - {o}" for o in obs)
    text = (
        f"@Triage *** NEW SECURITY ALERT *** {inc_id}\n"
        f"{alert.get('title', '')}\n"
        f"Source: {alert.get('source', 'unknown')} | "
        f"Severity hint: {alert.get('severity_hint', 'unknown')} | "
        f"Category: {alert.get('category_hint', 'unknown')}\n"
        f"Affected host: {alert.get('asset_id', 'unknown')}\n"
        f"Indicators: {indicators}\n"
        f"Observations:\n{obs_block}\n\n"
        f"Triage this incident (alias {incident.upper()}): classify it and "
        f"recruit the specialists you need."
    )
    return text, alert


def _post_via_rest(content: str, triage, api_key: str, base_url: str) -> str:
    """Create intake room with Triage, add Triage as participant, post alert.

    Returns the intake room ID (for reference only; the demo doesn't need it).
    Uses the Band SDK's RestClient for proper request serialization.
    """
    # CyberRescue: the handle comes from agent_config.yaml only (no upstream fallback).
    if not triage.handle:
        raise ValueError("agents.triage.handle is not set in agent_config.yaml")
    handle = triage.handle.lstrip("@")

    from thenvoi_rest import RestClient
    from thenvoi_rest.human_api_chats.types import (
        CreateMyChatRoomRequestChat,
    )
    from thenvoi_rest.types import ChatMessageRequest

    client = RestClient(api_key=api_key, base_url=base_url)

    # Create intake room
    chat_req = CreateMyChatRoomRequestChat(name="WarRoom Intake (Triage kickoff)")
    room_resp = client.human_api_chats.create_my_chat_room(chat=chat_req)
    room_id = room_resp.id

    # Add Triage as a participant to the intake room
    client.human_api_chats.add_participant(
        chat_id=room_id,
        agent_id=triage.agent_id,
    )

    # Post alert @mentioning Triage
    msg_req = ChatMessageRequest(
        content=content,
        mentions=[{"id": triage.agent_id, "handle": handle, "name": "triage"}],
    )
    client.human_api_messages.send_my_chat_message(
        chat_id=room_id,
        message=msg_req,
    )

    return room_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fire an alert at the Triage agent.")
    parser.add_argument("incident", nargs="?", default="INC-C",
                        help="Alert alias/id (INC-A, INC-B, INC-C). Default: INC-C.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the message and exit without posting.")
    args = parser.parse_args(argv)

    try:
        content, _alert = build_alert_message(args.incident)
    except (KeyError, FileNotFoundError) as e:
        print(f"[injector] {e}\n[injector] available alerts: {list_alerts()}",
              file=sys.stderr)
        return 2

    triage = load_agent("triage")  # also loads .env so BAND_INJECTOR_API_KEY is set
    api_key = os.getenv("BAND_INJECTOR_API_KEY")
    base_url = os.getenv("BAND_REST_URL", DEFAULT_BASE_URL)

    print(f"[injector] incident={args.incident.upper()}")

    if args.dry_run or not api_key:
        if not args.dry_run:
            print("[injector] no auto-post: missing BAND_INJECTOR_API_KEY "
                  "(a Band user API key)")
        print("[injector] Paste this into a Band room with Triage "
              "(it @mentions Triage):\n")
        print("-" * 72)
        print(content)
        print("-" * 72)
        return 0

    try:
        room_id = _post_via_rest(content, triage, api_key, base_url)
    except Exception as e:  # noqa: BLE001 — surface any REST/auth error clearly
        # Human API requires Enterprise tier; fall back to manual paste
        if "Enterprise plan" in str(e) or "plan_required" in str(e):
            print("[injector] Band free tier blocks human API (room creation).")
            print("[injector] Please use the manual paste method:\n")
        else:
            print(f"[injector] POST failed: {type(e).__name__}: {e}", file=sys.stderr)
            print("[injector] Falling back to manual paste:\n")
        print(content)
        return 1

    print(f"[injector] created intake room {room_id} with Triage and posted alert.")
    print("[injector] Triage will read it, classify it, and create the incident room.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
