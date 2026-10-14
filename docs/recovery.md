# Failure modes & recovery (Phase 5.4)

What happens if an agent crashes or is killed mid-incident, and how WarRoom
recovers. Exit criterion for Phase 5.4: **an agent restart does not strand the
incident.**

## TL;DR for the demo

If an agent hangs or dies mid-incident, **relaunch it** — it rejoins its rooms and
catches up automatically; already-executed actions are not undone; the Facilitator
watchdog covers any gap; the human CISO is the final backstop.

```powershell
# Restart everything (kills stale PIDs first) and keep the run going:
powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1 -Headless -Force
# …or relaunch just one agent (it re-subscribes + catches up on its own):
.venv\Scripts\python.exe -m agents.compliance.main
```

For a *clean* demo, prefer restarting all four + the watchdog and firing a **fresh**
incident over salvaging a half-broken room.

## Why a restart recovers (mechanics)

| Concern | What happens on restart | Where |
|---|---|---|
| **Room membership** | The agent re-subscribes to every room it's a participant of (`agent_rooms`) and loads history. | band-sdk runtime (observed: "Loaded N historical messages") |
| **Unprocessed messages** | It pulls anything not yet processed via `/next` and handles it (crash-safe backlog). | `runtime/execution.py` `_sync_via_next` |
| **Messages stuck "processing"** (killed mid-handle) | `_recover_stale_processing_messages` re-marks + re-processes them. | band-sdk |
| **Ack loop after recovery** | `mark_processed` 422 (no active attempt) is auto-recovered (re-`processing`→`processed`); a residual spin is broken by the loop guard. | `shared/sdk_patches.py` (Fix 1 + Fix 2) |
| **Executed actions** | Recorded in `actions_log.jsonl` (append-only). A restart does NOT undo them; the log is the audit trail. | `agents/commander/tools.py` |
| **Regulatory clock** | Persisted to `regulatory_clocks.json`; the deadline is fixed, so a Compliance restart **continues the same countdown** (does not reset). | `shared/reg_clock.py` |
| **Recruitment** | `create_chatroom` recruitment is idempotent; re-adding an already-present participant errors harmlessly (caught). | `shared/sdk_patches.py` (Fix 3) |
| **Stall while an agent is down** | The out-of-band Facilitator watchdog keeps observing and nudges the expected next actor; it is itself restartable and re-discovers the room. | `scripts/incident_driver.py` |

## Observed this session (2026-06-14)

- **Surgical mid-incident restart:** during a live INC-C, the Compliance agent was
  killed and relaunched while the incident was open. On restart it re-subscribed,
  re-received the BRIEF, and resumed posting findings — the incident was not
  stranded.
- **Full restarts** (all four) between runs consistently recovered: agents rejoin
  rooms and replay backlog via `/next`.
- **Network/DNS drops** (`[Errno 11001] getaddrinfo failed`) are transient: the SDK
  errors on that poll and retries on the next; if the drop is sustained, stop and
  relaunch once connectivity returns. No state is lost (room history + clock +
  actions_log persist server-side / on disk).

## Known failure modes and their handling

| Failure | Handling |
|---|---|
| `mark_processed` 422 → infinite `/next` resync | Patched: 422-recovery + loop guard (`sdk_patches.py`). |
| Triage creates duplicate rooms / splits the team | Reasoned, idempotent recruiter (`create_chatroom` recruits the per-incident roster into the current room). |
| An agent analyses but never posts | Prompt "turn discipline" (always end in `thenvoi_send_message`) + watchdog nudge. |
| Round-robin stall (no one holds the baton) | Facilitator watchdog nudges the expected next actor; escalates to the human after repeated stalls. |
| Commander won't pull the trigger (haiku final-mile) | Watchdog "execute and resolve" nudge; or run the Commander on Sonnet (`run_all.ps1 -CommanderModel claude-sonnet-4-6`). |

## Repeatable validation (run when the network is stable)

1. `run_all.ps1 -Headless` → fire INC-C → wait until the specialists have posted
   FINDINGs.
2. Kill one agent mid-incident: `powershell scripts\run_all.ps1 -Check` to see PIDs,
   then `taskkill /PID <compliance_pid> /T /F` (or `Stop-Process`).
3. Relaunch it: `.venv\Scripts\python.exe -m agents.compliance.main`.
4. **Expect:** it reconnects, replays the room via `/next`, and re-engages; the
   incident proceeds to RESOLUTION (watchdog + human cover any gap). The regulatory
   countdown continues from the same deadline (clock persisted).

## Demo recovery policy (decided)

- **Mid-incident crash → relaunch the agent**, let it catch up; do not reset the room.
- **Persistent network loss → pause**; relaunch once connectivity returns (state
  survives).
- **Anything messy/half-broken right before the climax → restart all four + the
  watchdog and fire a fresh incident.** A clean run beats a salvaged one on stage.
- Keep the **backup video** (Phase 7) as the ultimate fallback — live LLM demos fail
  at the worst moment.
