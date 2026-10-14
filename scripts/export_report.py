"""Phase 6: audit-trail exporter — a structured incident report.

Turns a finished WarRoom room into ``incident-report-<id>.md``:
  - Executive summary (incident, severity, outcome, participants)
  - Decision timeline (every FINDING/QUESTION/SIGNOFF/VETO/ESCALATION/ACTION/
    RESOLUTION, with timestamp, actor, evidence; human rulings highlighted)
  - Regulatory section (triggered obligations + the notification clock: deadline,
    window, live status)
  - Actions taken (from actions_log.jsonl; human-authorized actions flagged)
  - Appendix: verbatim transcript

It reuses the transcript-gathering from ``export_transcript`` (merge every agent's
context view — the free-tier workaround for per-agent read scoping). The
report-building (``build_report``) is a pure function so it's unit-tested without
the network.

    .venv\\Scripts\\python.exe scripts\\export_report.py            # newest room
    .venv\\Scripts\\python.exe scripts\\export_report.py --room <id> --out report.md
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from datetime import datetime, timezone
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))          # export_transcript
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))   # repo root

from shared import reg_clock  # noqa: E402
from shared.config import REPO_ROOT  # noqa: E402

_JSON = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
_INC_ID = re.compile(r"INC-[A-Z](?:-\d{4}-\d{4})?", re.IGNORECASE)
_INC_ALIAS = re.compile(r"INC-[ABC]", re.IGNORECASE)
# The human's FIRST message is the kickoff alert, not a ruling — it carries the
# injector's alert signature. Used to avoid mislabeling it as a "CISO RULING".
_ALERT_SIG = re.compile(r"NEW SECURITY ALERT|Triage this incident", re.IGNORECASE)

# Fallbacks for when agents post prose WITHOUT the typed json block (the gpt-4o
# LangGraph specialists do this). Recover incident_id + severity from the
# classify_alert tool-result — heavily escaped JSON, so tolerate optional
# backslashes around the quotes (e.g. `\"severity\": \"medium\"`).
_CLS_SEVERITY = re.compile(r'\\?"severity\\?"\s*:\s*\\?"([a-z]+)', re.IGNORECASE)
_CLS_INCIDENT = re.compile(r'\\?"incident_id\\?"\s*:\s*\\?"(INC-[A-Z0-9-]+)', re.IGNORECASE)
# Bold protocol markers in prose (e.g. **FINDING**, **SIGNOFF_REQUEST**) — longest
# alternatives first so SIGNOFF_REQUEST wins over SIGNOFF.
_PROSE_MARKER = re.compile(
    r"\*\*\s*(BRIEF|FINDING|QUESTION|SIGNOFF_REQUEST|SIGNOFF|VETO|ESCALATION|"
    r"ACTION|RESOLUTION|CLOSE)\s*\*\*", re.IGNORECASE)

# Protocol block types that belong on the decision timeline, in priority order.
_TIMELINE_TYPES = {
    "BRIEF", "FINDING", "QUESTION", "SIGNOFF_REQUEST", "SIGNOFF",
    "VETO", "ESCALATION", "ACTION", "RESOLUTION", "CLOSE",
}


def _protocol_blocks(content: str) -> list[dict[str, Any]]:
    """Parse the fenced ```json protocol blocks (those with a `type`) from text."""
    out = []
    for raw in _JSON.findall(content or ""):
        try:
            obj = json.loads(raw)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(obj, dict) and isinstance(obj.get("type"), str):
            out.append(obj)
    return out


def _ts(value: Any) -> str:
    if value is None:
        return "????-??-?? ??:??"
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)[:19].replace("T", " ")


def _content(m: Any) -> str:
    return getattr(m, "content", "") or ""


def _classify_facts(msgs: list[Any]) -> dict[str, str]:
    """Recover incident_id + severity from the classify_alert tool-result — the
    authoritative source when Triage's BRIEF lacks a typed json block. Detected by
    the snake_case `incident_id` key, which is unique to the classify_alert output
    (protocol blocks use `incident`)."""
    facts: dict[str, str] = {}
    for m in msgs:
        c = _content(m)
        im = _CLS_INCIDENT.search(c)
        if not im:
            continue  # not a classify_alert result
        if "incident" not in facts:
            facts["incident"] = im.group(1).upper()
        sm = _CLS_SEVERITY.search(c)
        if sm and "severity" not in facts:
            facts["severity"] = sm.group(1).lower()
        if "incident" in facts and "severity" in facts:
            break
    return facts


def build_report(messages: list[Any], actions: list[dict[str, Any]],
                 clocks: list[dict[str, Any]], *, room_id: str = "",
                 now: datetime | None = None) -> str:
    """Pure: assemble the incident-report markdown from collected data."""
    now = now or datetime.now(timezone.utc)
    msgs = sorted(messages, key=lambda m: str(getattr(m, "inserted_at", "") or ""))

    # --- parse protocol events (a message may carry one block) ----------------
    events = []
    # Pass 1: typed json blocks, plus human plain-text (kickoff ALERT vs CISO
    # RULING — only an actual decision is highlighted as the CISO's call).
    for m in msgs:
        blocks = _protocol_blocks(_content(m))
        for b in blocks:
            events.append({
                "type": b["type"].upper(),
                "block": b,
                "sender": getattr(m, "sender_name", "?") or "?",
                "sender_type": getattr(m, "sender_type", "?") or "?",
                "ts": getattr(m, "inserted_at", None),
            })
        if getattr(m, "sender_type", "") == "User" and _content(m).strip() and not blocks:
            text = _content(m).strip()
            events.append({
                "type": "ALERT" if _ALERT_SIG.search(text) else "CISO RULING",
                "block": {"summary": text[:400]},
                "sender": getattr(m, "sender_name", "CISO") or "CISO",
                "sender_type": "User",
                "ts": getattr(m, "inserted_at", None),
            })
    # Pass 2: prose fallback for agents that omitted the json block — synthesize a
    # timeline event from a **bold** protocol marker, de-duped against any typed
    # block of the same type+sender (so the Commander's json beats, which it also
    # echoes as bold prose, aren't double-counted).
    for m in msgs:
        if getattr(m, "sender_type", "") == "User":
            continue
        c = _content(m).strip()
        if not c or _protocol_blocks(c):
            continue
        mk = _PROSE_MARKER.search(c)
        if not mk:
            continue
        btype = mk.group(1).upper()
        sender = getattr(m, "sender_name", "?") or "?"
        if any(e["type"] == btype and e["sender"] == sender for e in events):
            continue
        events.append({
            "type": btype,
            "block": {"summary": c[:400]},
            "sender": sender,
            "sender_type": getattr(m, "sender_type", "?") or "?",
            "ts": getattr(m, "inserted_at", None),
        })
    events.sort(key=lambda e: str(e["ts"] or ""))  # restore chronological order

    facts = _classify_facts(msgs)

    def _first(pred):
        return next((e for e in events if pred(e)), None)

    # --- incident id / severity / outcome -------------------------------------
    # Prefer classify_alert's incident_id — it's authoritative, and beats a
    # model-invented `incident` value in a block (e.g. "GreyLoader-ws-eng-014").
    incident = facts.get("incident") or next(
        (e["block"].get("incident") for e in events if e["block"].get("incident")), None)
    if not incident:
        for m in msgs:
            mm = _INC_ID.search(_content(m))
            if mm:
                incident = mm.group(0).upper()
                break
    incident = incident or "INC-UNKNOWN"
    alias_m = _INC_ALIAS.search(incident)
    alias = alias_m.group(0).upper() if alias_m else incident

    # Severity from a typed block if present, else recovered from classify_alert.
    sev_ev = _first(lambda e: e["block"].get("severity"))
    severity = (sev_ev["block"]["severity"] if sev_ev else facts.get("severity")) or "unspecified"

    res_ev = _first(lambda e: e["type"] in ("RESOLUTION", "CLOSE"))
    outcome = (res_ev["block"].get("summary") if res_ev
               else "OPEN — no RESOLUTION/CLOSE recorded.")

    participants = sorted({f"{getattr(m,'sender_name','?')} ({getattr(m,'sender_type','?')})"
                           for m in msgs if getattr(m, "sender_name", None)})

    L: list[str] = []
    L += [f"# Incident report — {incident}", ""]
    L += ["> *This report was not written after the incident. It **is** the "
          "incident — generated from the room where the decisions were made.*", ""]

    # --- executive summary ----------------------------------------------------
    L += ["## Executive summary", ""]
    L += [f"- **Incident:** {incident}",
          f"- **Severity:** {severity}",
          f"- **Outcome:** {outcome}",
          f"- **Room:** `{room_id}`" if room_id else "",
          f"- **Generated:** {now.isoformat(timespec='seconds')}",
          f"- **Participants:** {', '.join(participants) or 'n/a'}",
          f"- **Protocol events:** {len(events)} | **Actions executed:** {len(actions)}",
          ""]

    # --- decision timeline ----------------------------------------------------
    L += ["## Decision timeline", ""]
    timeline = [e for e in events if e["type"] in _TIMELINE_TYPES
                or e["type"] in ("CISO RULING", "ALERT")]
    if not timeline:
        L += ["_No structured protocol blocks were posted._", ""]
    for e in timeline:
        b = e["block"]
        human = " 👤 **HUMAN RULING**" if e["type"] == "CISO RULING" else ""
        L.append(f"### [{_ts(e['ts'])}] {e['type']} — {e['sender']}{human}")
        if b.get("summary"):
            L.append(f"- {b['summary']}")
        if b.get("decision"):
            L.append(f"- **Decision:** {b['decision']}")
        if b.get("regulation"):
            L.append(f"- **Regulation:** {b['regulation']}")
        if b.get("deadline_utc"):
            L.append(f"- **Deadline:** {b['deadline_utc']}")
        for ev in (b.get("evidence") or []):
            L.append(f"  - _evidence:_ {ev}")
        L.append("")

    # --- regulatory section ---------------------------------------------------
    L += ["## Regulatory obligations & clock", ""]
    if clocks:
        L += ["| Regulation | Deadline (UTC) | Window | Status (at report time) |",
              "|---|---|---|---|"]
        for c in clocks:
            status = "⏰ BREACHED" if c.get("breached") else c.get("t_minus", "")
            L.append(f"| {c.get('regulation','')} | {c.get('deadline_utc','')} | "
                     f"{c.get('window','')} | {status} |")
        L.append("")
    else:
        L += ["_No notification clocks were started for this incident._", ""]
    veto = _first(lambda e: e["type"] == "VETO")
    if veto:
        L += [f"**Compliance VETO:** {veto['block'].get('summary','')} "
              f"(regulation: {veto['block'].get('regulation','n/a')})", ""]

    # --- actions taken --------------------------------------------------------
    L += ["## Actions taken", ""]
    if not actions:
        L += ["_No actions were executed._", ""]
    else:
        for a in actions:
            tgt = a.get("asset_id") or ", ".join(a.get("stakeholders", []) or [])
            L.append(f"- `{str(a.get('timestamp_utc',''))[:19]}` "
                     f"**{a.get('action')}** → {tgt}")
            if a.get("reason"):
                L.append(f"  - {a['reason']}")
        L.append("")

    # --- appendix: verbatim transcript ---------------------------------------
    L += ["---", "", "## Appendix — verbatim transcript", ""]
    for m in msgs:
        sn = getattr(m, "sender_name", "?") or "?"
        st = getattr(m, "sender_type", "?") or "?"
        mt = getattr(m, "message_type", "text") or "text"
        tag = "" if mt == "text" else f" _({mt})_"
        L.append(f"**[{_ts(getattr(m, 'inserted_at', None))}] {sn} ({st}){tag}**")
        L.append("")
        L.append((_content(m).strip() or "_(no text)_"))
        L.append("")

    L += ["---", "",
          "*Generated by WarRoom `export_report.py` — the audit trail is a side "
          "effect of the work, not a document written afterward.*"]
    return "\n".join(x for x in L if x is not None), incident, alias


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Export a WarRoom incident report.")
    ap.add_argument("--room", default=None, help="Room id (default: newest).")
    ap.add_argument("--out", default=None, help="Output path (default: reports/...).")
    args = ap.parse_args(argv)

    try:
        import export_transcript as xt
    except Exception as e:  # noqa: BLE001
        print(f"[report] could not import export_transcript: {e}", file=sys.stderr)
        return 2

    clients = xt._clients()
    if not clients:
        print("[report] no agent credentials available.", file=sys.stderr)
        return 2
    room = xt._discover_room(clients, args.room)
    if not room:
        print("[report] no room found.", file=sys.stderr)
        return 1
    messages = xt._collect(clients, room)
    if not messages:
        print(f"[report] room {room} has no readable messages.", file=sys.stderr)
        return 1

    since = getattr(messages[0], "inserted_at", None)
    actions = xt._actions_since(since)

    # Resolve the incident alias for the clock lookup from the messages.
    inc = next((b.get("incident") for m in messages
                for b in _protocol_blocks(_content(m)) if b.get("incident")), "")
    am = _INC_ALIAS.search(inc or "") or _INC_ALIAS.search(
        " ".join(_content(m) for m in messages))
    clocks = reg_clock.clock_status(am.group(0).upper()) if am else []

    report, incident, _alias = build_report(messages, actions, clocks, room_id=room)
    out = args.out or str(pathlib.Path(REPO_ROOT) / "reports" /
                          f"incident-report-{incident}.md")
    out_path = pathlib.Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(f"[report] wrote incident report ({len(messages)} msgs, {len(actions)} "
          f"actions) to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
