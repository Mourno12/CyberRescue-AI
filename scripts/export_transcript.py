"""Export a WarRoom incident transcript to a Markdown file.

On the Band free tier no single key can read the whole room (the human API is
Forbidden and the agent API is per-mention scoped). So this merges the
`get_agent_chat_context` views of every agent key (each returns the messages it
sent + the ones that mention it) and de-dupes by message id — the union
reconstructs a near-complete transcript, including the human's rulings (captured
via the Commander's view). The Commander's executed actions are appended from
actions_log.jsonl.

Usage (from repo root, after a run — agents may be stopped; REST reads still work):
    .venv\\Scripts\\python.exe scripts\\export_transcript.py            # newest room
    .venv\\Scripts\\python.exe scripts\\export_transcript.py --room <id>
    .venv\\Scripts\\python.exe scripts\\export_transcript.py --out report.md
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from shared.config import REPO_ROOT, load_agent  # noqa: E402

DEFAULT_BASE_URL = "https://app.band.ai"
ROLES = ("triage", "threat_intel", "compliance", "commander", "facilitator")


def _clients():
    from thenvoi_rest import RestClient
    out = {}
    for role in ROLES:
        try:
            c = load_agent(role)
            out[role] = (c, RestClient(api_key=c.api_key, base_url=DEFAULT_BASE_URL))
        except Exception:
            pass
    return out


def _discover_room(clients, explicit):
    if explicit:
        return explicit
    newest = None
    for _role, (_creds, client) in clients.items():
        try:
            rooms = client.agent_api_chats.list_agent_chats(page=1, page_size=50).data
        except Exception:
            continue
        for r in rooms:
            ts = getattr(r, "updated_at", "") or ""
            if newest is None or ts > newest[1]:
                newest = (r.id, ts)
    return newest[0] if newest else None


def _collect(clients, room_id):
    """Merge every agent's context view of the room, de-duped by message id."""
    by_id = {}
    for _role, (_creds, client) in clients.items():
        page = 1
        while page <= 50:
            try:
                resp = client.agent_api_context.get_agent_chat_context(
                    chat_id=room_id, page=page, page_size=100)
            except Exception:
                break
            data = resp.data or []
            for m in data:
                by_id[m.id] = m
            meta = getattr(resp, "meta", None)
            total = getattr(meta, "total_pages", None) if meta else None
            if (total and page >= total) or len(data) < 100:
                break
            page += 1
    return sorted(by_id.values(), key=lambda m: str(getattr(m, "inserted_at", "") or ""))


def _hhmmss(ts) -> str:
    if ts is None:
        return "--:--:--"
    if hasattr(ts, "strftime"):
        return ts.strftime("%H:%M:%S")
    return str(ts)[11:19] or "--:--:--"


def _to_dt(value):
    """Parse a timestamp (datetime or ISO string, 'T' or space separator) to an
    aware datetime, or None."""
    if value is None or value == "":
        return None
    if hasattr(value, "isoformat") and not isinstance(value, str):
        return value
    try:
        return datetime.fromisoformat(str(value).replace(" ", "T"))
    except Exception:
        return None


def _actions_since(since) -> list[dict]:
    """Actions logged at/after `since` (so we only show THIS run's actions, not
    earlier rehearsals accumulated in the shared log)."""
    path = pathlib.Path(REPO_ROOT) / "actions_log.jsonl"
    if not path.exists():
        return []
    since_dt = _to_dt(since)
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            a = json.loads(line)
        except Exception:
            continue
        a_dt = _to_dt(a.get("timestamp_utc"))
        if since_dt is None or a_dt is None or a_dt >= since_dt:
            rows.append(a)
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Export a WarRoom incident transcript.")
    ap.add_argument("--room", default=None, help="Room id (default: newest).")
    ap.add_argument("--out", default=None, help="Output path (default: exports/...).")
    args = ap.parse_args(argv)

    try:
        import thenvoi_rest  # noqa: F401
    except ImportError:
        print("[export] thenvoi_rest not installed.", file=sys.stderr)
        return 2

    clients = _clients()
    if not clients:
        print("[export] no agent credentials available.", file=sys.stderr)
        return 2

    room = _discover_room(clients, args.room)
    if not room:
        print("[export] no room found.", file=sys.stderr)
        return 1

    messages = _collect(clients, room)
    if not messages:
        print(f"[export] room {room} has no readable messages.", file=sys.stderr)
        return 1

    # Best-effort incident id from any protocol block.
    incident = "INC-?"
    import re
    jb = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
    for m in messages:
        for b in jb.findall(getattr(m, "content", "") or ""):
            try:
                inc = json.loads(b).get("incident")
                if inc:
                    incident = inc
                    break
            except Exception:
                pass
        if incident != "INC-?":
            break

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines = [
        f"# WarRoom incident transcript — {incident}",
        "",
        f"- Room: `{room}`",
        f"- Messages: {len(messages)} (merged across {len(clients)} agent views)",
        f"- Exported: {now}",
        "",
        "---",
        "",
    ]
    for m in messages:
        sn = getattr(m, "sender_name", "?") or "?"
        st = getattr(m, "sender_type", "?") or "?"
        mt = getattr(m, "message_type", "text") or "text"
        content = (getattr(m, "content", "") or "").strip()
        tag = "" if mt == "text" else f" _({mt})_"
        lines.append(f"### [{_hhmmss(getattr(m, 'inserted_at', ''))}] {sn} ({st}){tag}")
        lines.append("")
        lines.append(content if content else "_(no text)_")
        lines.append("")

    actions = _actions_since(getattr(messages[0], "inserted_at", None))
    if actions:
        lines += ["---", "", "## Actions executed (actions_log.jsonl)", ""]
        for a in actions:
            ts = a.get("timestamp_utc", "")[:19]
            detail = a.get("asset_id") or ", ".join(a.get("stakeholders", []) or [])
            lines.append(f"- `{ts}` **{a.get('action')}** → {detail} — {a.get('reason', '')}")
        lines.append("")

    out = args.out or str(pathlib.Path(REPO_ROOT) / "exports" /
                          f"transcript-{incident}-{now[:19].replace(':', '')}.md")
    out_path = pathlib.Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[export] wrote {len(messages)} messages to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
