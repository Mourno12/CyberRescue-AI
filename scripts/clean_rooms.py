"""Room hygiene for WarRoom: show (and optionally leave) every Band room each
agent is a member of, so each demo run starts in ONE fresh incident room.

Why this exists
---------------
The Band SDK auto-subscribes an agent to *every* room it has ever been added to
and replays that room's backlog on startup. After a few test runs the agents
wake up and re-litigate old incidents in stale rooms (e.g. the Phase-2
`d41f480c` room), which blows up token usage and pollutes the transcript that is
the demo's actual deliverable. This tool removes each agent from old rooms.

Usage (run from the repo root)
------------------------------
    # SAFE: just list what each agent is in (no changes)
    .venv\\Scripts\\python.exe scripts\\clean_rooms.py

    # Leave EVERY room (full reset before a clean run)
    .venv\\Scripts\\python.exe scripts\\clean_rooms.py --execute

    # Leave every room EXCEPT the active incident room(s)
    .venv\\Scripts\\python.exe scripts\\clean_rooms.py --execute --keep 8d2fbe2b-... --keep ...

    # Only operate on one agent
    .venv\\Scripts\\python.exe scripts\\clean_rooms.py --agent commander --execute

Notes
-----
- Stop the agents first (``scripts\\run_all.ps1 -Stop`` or Ctrl-C each window) so
  you're not leaving a room out from under a live process.
- Leaving works by the agent removing *itself* as a participant. Band only lets
  the room owner/admin remove participants, so a room the agent was merely added
  to (didn't create) may refuse the leave with a 403 — that's reported, not fatal.
- Base URL matches the injector (``https://app.band.ai``); override with
  ``BAND_REST_URL`` if needed.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys

# Make `shared` importable whether run as `python scripts/clean_rooms.py` or `-m`.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from shared.config import load_agent  # noqa: E402

ROSTER = ["triage", "threat_intel", "compliance", "commander"]
DEFAULT_BASE_URL = "https://app.band.ai"  # same backend the injector reaches
PAGE_SIZE = 100


def _list_rooms(client) -> list:
    """All rooms the agent (whose key built `client`) is a participant of."""
    rooms: list = []
    page = 1
    while True:
        resp = client.agent_api_chats.list_agent_chats(page=page, page_size=PAGE_SIZE)
        rooms.extend(resp.data)
        meta = resp.metadata
        total_pages = getattr(meta, "total_pages", None) or 1
        if page >= total_pages:
            break
        page += 1
    return rooms


def _room_label(room) -> str:
    title = getattr(room, "title", None) or "(untitled)"
    updated = getattr(room, "updated_at", "")
    return f"{room.id}  {str(updated)[:19]:<19}  {title}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="List/leave the Band rooms each WarRoom agent is in.")
    parser.add_argument("--execute", action="store_true",
                        help="Actually leave rooms. Without this, only lists (safe).")
    parser.add_argument("--keep", action="append", default=[], metavar="ROOM_ID",
                        help="Room id to KEEP (repeatable). Ignored unless --execute.")
    parser.add_argument("--agent", choices=ROSTER, default=None,
                        help="Limit to one agent (default: all four).")
    args = parser.parse_args(argv)

    try:
        from thenvoi_rest import RestClient
    except ImportError:
        print("[clean_rooms] thenvoi_rest not installed in this interpreter.", file=sys.stderr)
        return 2

    base_url = os.getenv("BAND_REST_URL", DEFAULT_BASE_URL)
    keep = set(args.keep)
    roster = [args.agent] if args.agent else ROSTER

    mode = "EXECUTE (leaving rooms)" if args.execute else "DRY RUN (listing only)"
    print(f"[clean_rooms] {mode} | base_url={base_url}")
    if args.execute and keep:
        print(f"[clean_rooms] keeping: {', '.join(sorted(keep))}")
    print()

    total_left = total_failed = total_kept = 0

    for name in roster:
        creds = load_agent(name)  # loads .env/.env.local; gives api_key + agent_id
        client = RestClient(api_key=creds.api_key, base_url=base_url)
        print(f"=== {name}  ({creds.handle})  account={creds.account} ===")

        try:
            rooms = _list_rooms(client)
        except Exception as e:  # noqa: BLE001 — surface auth/host errors clearly
            print(f"  [error] could not list rooms: {type(e).__name__}: {e}\n")
            continue

        if not rooms:
            print("  (in no rooms)\n")
            continue

        for room in rooms:
            label = _room_label(room)
            if not args.execute:
                print(f"  - {label}")
                continue
            if room.id in keep:
                print(f"  KEEP   {label}")
                total_kept += 1
                continue
            try:
                client.agent_api_participants.remove_agent_chat_participant(
                    chat_id=room.id, id=creds.agent_id,
                )
                print(f"  LEFT   {label}")
                total_left += 1
            except Exception as e:  # noqa: BLE001
                reason = type(e).__name__
                print(f"  FAIL   {label}  ({reason}: owner/admin only?)")
                total_failed += 1
        print()

    if args.execute:
        print(f"[clean_rooms] done: left={total_left} kept={total_kept} failed={total_failed}")
        if total_failed:
            print("[clean_rooms] FAILs are usually rooms the agent didn't create "
                  "(can't self-remove). Have the room owner remove them, or ignore "
                  "stale rooms you won't reuse.")
    else:
        print("[clean_rooms] dry run only -- re-run with --execute to leave rooms.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
