"""Read-only export of a Band room into the JSON shape ``core import-band`` reads.

``scripts/export_transcript.py`` (upstream WarRoom) writes Markdown for humans;
the Core importer needs the Band agent-context JSON (``{"data": [message...]}``,
see ``shared/sample_message.json``). This module produces that JSON.

Band free tier: no single key can read a whole room -- each agent key's
``get_agent_chat_context`` returns only the messages that agent sent or was
@mentioned in. So, like the Markdown exporter, every configured agent key is
queried and the views are merged and de-duplicated by Band message id. The
export records which views were read and which failed, so an incomplete union
is visible rather than silent.

Network: only when ``collect_room`` is called with real clients (``export-band``
command). It only READS; it never posts, joins, or modifies a room.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_BASE_URL = "https://app.band.ai"
ROLES = ("triage", "threat_intel", "compliance", "commander", "facilitator")
MESSAGE_FIELDS = ("id", "chat_id", "content", "sender_id", "sender_type", "sender_name",
                  "message_type", "inserted_at", "updated_at", "metadata")
MAX_PAGES = 50
PAGE_SIZE = 100


def message_to_dict(m: Any) -> dict[str, Any]:
    if isinstance(m, dict):
        raw = m
    elif hasattr(m, "model_dump"):
        raw = m.model_dump(mode="json")
    else:
        raw = {f: getattr(m, f, None) for f in MESSAGE_FIELDS}
    out = {f: raw.get(f) for f in MESSAGE_FIELDS if raw.get(f) is not None}
    for f in ("inserted_at", "updated_at"):
        if f in out and not isinstance(out[f], str):
            out[f] = out[f].isoformat() if hasattr(out[f], "isoformat") else str(out[f])
    return out


class TruncatedView(Exception):
    """A view still had more pages when the page limit was reached."""


def _read_view(client: Any, room_id: str) -> list[dict[str, Any]]:
    msgs: list[dict[str, Any]] = []
    for page in range(1, MAX_PAGES + 1):
        resp = client.agent_api_context.get_agent_chat_context(
            chat_id=room_id, page=page, page_size=PAGE_SIZE)
        data = list(getattr(resp, "data", None) or [])
        msgs += [message_to_dict(m) for m in data]
        meta = getattr(resp, "meta", None)
        total = getattr(meta, "total_pages", None) if meta else None
        if (total and page >= total) or len(data) < PAGE_SIZE:
            return msgs
    # Every page up to the limit was full and no last page was signalled: the
    # view is incomplete. Never report it as complete (CyberRescue fix).
    raise TruncatedView(f"more than {MAX_PAGES * PAGE_SIZE} messages (page limit reached)")


def collect_room(clients: dict[str, Any], room_id: str) -> dict[str, Any]:
    """Merge every view of ``room_id``; returns the export document."""
    by_id: dict[str, dict[str, Any]] = {}
    views: dict[str, Any] = {}
    for role, client in clients.items():
        try:
            msgs = _read_view(client, room_id)
        except TruncatedView:
            views[role] = {"ok": False, "error": "TruncatedView",
                           "detail": f"page limit {MAX_PAGES}x{PAGE_SIZE} reached"}
            continue
        except Exception as e:  # noqa: BLE001 -- record the gap, keep the other views
            views[role] = {"ok": False, "error": type(e).__name__}
            continue
        views[role] = {"ok": True, "messages": len(msgs)}
        for m in msgs:
            if m.get("id"):
                by_id.setdefault(str(m["id"]), m)
    data = sorted(by_id.values(), key=lambda m: str(m.get("inserted_at") or ""))
    return {
        "_provenance": "band-live-export",
        "_note": "Read from Band by cyberrescue.live export-band (union of per-agent context "
                 "views, de-duplicated by message id). Not edited.",
        "room_id": room_id,
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "views": views,
        "message_count": len(data),
        "message_types": _count(m.get("message_type") or "text" for m in data),
        "data": data,
    }


def _count(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


def real_clients(roles: Iterable[str] = ROLES,
                 base_url: str = DEFAULT_BASE_URL,
                 loader: Callable[[str], Any] | None = None) -> tuple[dict[str, Any], list[str]]:
    """One REST client per configured agent key. Returns (clients, skipped roles)."""
    from thenvoi_rest import RestClient

    from shared.config import load_agent
    loader = loader or load_agent
    clients, skipped = {}, []
    for role in roles:
        try:
            creds = loader(role)
        except Exception:  # noqa: BLE001 -- missing/placeholder entry
            skipped.append(role)
            continue
        clients[role] = RestClient(api_key=creds.api_key, base_url=base_url)
    return clients, skipped


def write_export(path: Path, doc: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"{path} already exists (exports are never overwritten)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
