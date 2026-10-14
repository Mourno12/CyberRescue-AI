# Phase 4 — Collaboration protocol: run & tuning guide

**Goal (exit criterion):** all three incidents run end-to-end with correct,
distinct behaviour; INC-C reliably produces cross-examination → veto →
escalation → human ruling → resolution.

The collaboration layer is what the judges score. The code, prompts, and message
schema are in place — this phase is **live iteration**: run, watch, tune the
prompts, repeat.

## What's implemented

- **Message schema** — `shared/schemas.py` (`ProtocolMessage`): the fenced
  ```json block every message carries. Mirrored into every `prompt.md`.
- **Protocol** — `shared/protocol.md` §E: flow, the who-@mentions-whom routing
  table, anti-loop guards, the INC-C conflict.
- **Prompts** — all four `agents/*/prompt.md` rewritten to the full protocol.
- **Tool allowlists** — each `agents/*/main.py` grants the right *platform*
  tools (Triage gets recruitment; Commander gets participant lookup). Domain
  tools ride in via `additional_tools` and are always available.
- **Injector** — `injector/inject_alert.py` fires an alert at Triage.

## One-time setup per run

1. In the Band UI, create a **fresh room** containing the **human (CISO) + the
   Triage agent**. Paste its id into `agent_config.yaml` → `room.default_room_id`
   (or pass `--room`, or set `BAND_ROOM_ID`). Fresh room per run = no stale
   history, no 24h-retention surprise.
2. (Optional, for auto-posting) put a Band **user** API key in
   `BAND_INJECTOR_API_KEY`. Without it the injector prints a paste-ready message.
3. Confirm the cross-account contact handshake is still in place so Triage can
   add Compliance (see `shared/protocol.md` §A.0).

## Run

```bash
docker compose up            # all four agents, four log panes
python -m injector.inject_alert INC-C    # the contested incident
```

(or paste the injector's printed message into the room).

## Expected behaviour

**INC-C (contested):**
1. Triage classifies → recruits **Threat Intel + Compliance + Commander** into
   the room (reasoned: "srv-db-01 holds customer_pii → Compliance"), posts BRIEF.
2. Threat Intel: BlackHaze active, lateral movement → **isolate + wipe now**.
3. Compliance: GDPR-ART-33 (72h clock) + evidence-preservation hold →
   **VETO the wipe**; isolate + image instead.
4. ≥2 cross-examination QUESTIONs between the specialists.
5. Commander SIGNOFF_REQUEST → veto/recommendation conflict → **ESCALATION** to
   the human CISO.
6. Human rules in one message → Commander executes (action tools write to
   `actions_log.jsonl`) → **RESOLUTION**. ≤ ~15 room messages.

**INC-A (clean):** Triage recruits Threat Intel + Commander (**no** Compliance),
findings + sign-offs, **no escalation**, resolved.

**INC-B (false positive):** Triage posts CLOSE, recruits **no one**.

## Tuning checklist (iterate until all hold)

- [ ] Recruitment is reasoned and matches `classify_alert` (B: none; A: no
      Compliance; C: all three).
- [ ] Every message carries a valid JSON block (verify with
      `shared.schemas.extract_block`).
- [ ] ≥2 substantive cross-examination exchanges on INC-C.
- [ ] The veto fires from Compliance's own tool output, not a script.
- [ ] Escalation summary is ≤5 neutral lines with one concrete decision request.
- [ ] No loops: ≤2 negotiation rounds, no re-litigation after RESOLUTION.
- [ ] Only the Commander calls action tools.

## Common failure modes → fix

- **An agent never reacts:** it wasn't @mentioned (handles route delivery). Check
  the sender used the exact handle from `shared/protocol.md` §E.0.
- **Agent replies as raw text:** reinforce "always `thenvoi_send_message`" in its
  prompt (already there; some models need it louder).
- **Triage can't add Compliance:** the cross-account contact lapsed — redo the
  agent-to-agent handshake (§A.0).
- **Agent loops / re-litigates:** tighten the anti-loop lines; lower temperature.

Export the room after every run (`exporter/export_report.py`, Phase 6) so a clean
transcript survives for the demo.
