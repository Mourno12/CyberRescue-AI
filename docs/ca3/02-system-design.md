# 02 — System design

## 1. Components

| Component | Location | Kind | Origin |
|---|---|---|---|
| Triage agent | `agents/triage/` | LLM (LangGraph, gpt-4o by default) | upstream WarRoom |
| Threat Intel agent | `agents/threat_intel/` | LLM (LangGraph, gpt-4o) | upstream WarRoom |
| Compliance agent | `agents/compliance/` | LLM (Pydantic AI, `openai:gpt-4o`) on a 2nd Band account | upstream WarRoom |
| Commander agent | `agents/commander/` | LLM (Anthropic, `claude-haiku-4-5-20251001` by default) | upstream WarRoom (+ gate hook, CyberRescue) |
| Facilitator | `scripts/incident_driver.py` | deterministic watchdog, no LLM | upstream WarRoom |
| Protocol schema | `shared/schemas.py` | Pydantic `ProtocolMessage` | upstream WarRoom |
| Mock environment | `shared/mock_env/` | deterministic tool data | upstream WarRoom |
| CyberRescue Core | `cyberrescue/core/` | SQLite store, audit chains, policy engine, gate, Band import, anchors | CyberRescue |
| Telemetry | `cyberrescue/telemetry/` | SYNTHETIC datasets → hashed evidence | CyberRescue |
| Detection | `cyberrescue/detection/` | deterministic rules + correlation | CyberRescue |
| Investigation | `cyberrescue/investigation/` | read-only case: timeline, graph, scope, gaps | CyberRescue |
| Response planning | `cyberrescue/response/` | advisory plan, ATT&CK map, policy preview | CyberRescue |
| Execution | `cyberrescue/execution/` | SIMULATED executor + Core-recorded accountability | CyberRescue |
| Evaluation | `cyberrescue/evaluation/` | ground-truth scoring (evaluation only) | CyberRescue |
| Live preparation | `cyberrescue/live/` | preflight, roster, read-only Band export | **this task** |

## 2. Two paths through the system

**Live agent path (UNVERIFIED in this work):** an alert is pasted into Band →
Triage classifies it and recruits → specialists post FINDINGs, QUESTIONs,
SIGNOFFs or a VETO → the Commander requests sign-off, escalates to the human, and
calls action tools → each action tool asks the Core gate → the action is logged
to `actions_log.jsonl` (this log line *is* the "execution"; nothing touches a
real host).

**Deterministic path (VERIFIED offline):** SYNTHETIC telemetry → Core evidence
(SHA-256 per record) → detection findings persisted with evidence citations →
read-only investigation case → advisory response plan → Commander requests each
step through `CoreService.request_action` → policy decision; a human approval is
recorded where policy requires one → the SIMULATED executor runs only authorized
steps and records `execution_records` → `core verify` checks every hash chain →
`core anchor` signs a checkpoint with an external HMAC key.

## 3. What is an LLM decision and what is code

| Decision | Made by |
|---|---|
| Alert classification, severity and specialist roster | Deterministic tool `classify_alert` (mock env), called by the Triage LLM |
| Room creation + recruiting the team | **Code**: `shared/sdk_patches.py` repurposes `thenvoi_create_chatroom` to add the configured handles |
| IOC attribution, spread risk | Deterministic tools; the Threat Intel LLM writes the FINDING text |
| Regulatory triggers, evidence-preservation hold, deadline clock | Deterministic tools; the Compliance LLM decides whether to VETO |
| Plan proposal, when to escalate, which action tool to call | **Commander LLM** |
| Whether an action may run | **Code**: Core policy engine (`policy-v2`) via the gate (in enforce mode) |
| Human approval | **A human** via `python -m cyberrescue.core approve` (never via chat text) |
| Anti-stall nudges | **Code**: Facilitator driver (fixed rules) |
| Detection, investigation, planning, simulated execution (offline path) | **Code** only; no LLM anywhere in `cyberrescue/` |

## 4. Trust boundaries (enforced in code, covered by tests)

1. **Identity comes from transport metadata.** It is Band `sender_id` and
   `sender_type` plus an operator roster, never message text. Unrostered senders
   become `unknown`/`observer` and cannot sign off, veto, or rule.
2. **The incident comes from the ingestion context.** A block that names another
   incident is recorded as `INCIDENT_REF_MISMATCH`.
3. **Messages never create approvals.** Fields like `"approved": true` are kept
   verbatim in the audit log and ignored.
4. **Single-use, scoped, expiring approvals.** Each approval is bound to
   (incident, action, asset), has a TTL of 60 minutes by default, and is consumed
   by one request.
5. **Policy-v2 rules.** P0–P3 and P9 are hard denies. P4 requires a specialist
   sign-off, and a human cannot substitute for it. P5–P8 require a human approval:
   critical asset, tier-3 action, Compliance veto (needs `overrides_veto`), and
   legal hold (needs `overrides_hold` plus a reason).
6. **The gate fails closed in enforce mode.** A missing incident, a Core error,
   or an unavailable Core blocks the action. An unrecognised mode value falls
   back to shadow and never silently enforces.
7. **The audit log is append-only.** SQLite triggers forbid UPDATE and DELETE.
   Hash chains run per incident. A keyed anchor detects truncation or a rewritten
   tail.
8. **Execution is simulated only.** `execution_records.mode` has a CHECK
   constraint of `'simulated'`, and only the SYSTEM executor actor may record.

## 5. Data stores

| Store | Written by | Contents |
|---|---|---|
| `cyberrescue.db` (path from `CYBERRESCUE_DB_PATH`) | Core only | incidents, actors, evidence, findings, sign-offs, vetoes, holds, approvals, action requests, execution records, audit events (hash-chained) |
| `cyberrescue_gate_log.jsonl` | Commander gate | one JSON line per gate decision (also a `GATE_DECISION` audit event) |
| `actions_log.jsonl` | Commander action tools | WarRoom "execution" log lines (live path) |
| `<agent>.log` | `run_all.ps1` | agent stdout/stderr |
| Anchor file + key | `core anchor` / `anchor-keygen` | HMAC-signed chain heads; key kept outside the repo |

All of the above are gitignored.

## 6. Live integration gap and how it is addressed

**Original finding (from reading the code):** live SIGNOFF and VETO messages did
not reach Core authorization during a run. The only path from Band to the Core
was the after-the-fact `core import-band`. In `enforce` mode the gate therefore
saw no sign-offs, and containment stayed blocked (P4). That is fail-closed, but
it stalls the demo.

**Implemented (offline-tested, live NOT VERIFIED):**

| Part | What it does | Reuses |
|---|---|---|
| `live export-band` | read-only export of a room as import JSON (union of all agent views, de-duplicated by message id) | upstream exporter approach |
| `live sync` (`cyberrescue/live/sync.py`) | bounded polling: each poll exports, then imports **new** message ids | `band_export.collect_room`, `band_import.import_band_context` / `ProtocolIngestor`, `open_legacy_incident`, `extract_blocks`, `verify_audit` |
| Runtime handles (`shared/config.py`) | prompts and Facilitator texts keep the upstream handles verbatim; they are rendered from `agent_config.yaml` at load time; an agent refuses to start on an unresolved handle | `agent_config.yaml` (single source) |

**Safety properties of `live sync`** (covered by `tests/test_live_sync.py` and
`tests/test_live_hardening.py`; MOCKED Band, real Core):

- **No new authority.** The sync calls no approval, request, authorization or
  execution API (a static test checks the source). Imported CISO messages stay
  messages: `verified approvals` counts only `core approve` records.
- **Prevent vs detect.** These checks run *before* a write and **prevent** it:
  incomplete or truncated views; invalid or timezone-less timestamps; out-of-order
  arrival; cross-incident blocks; a hash chain that already fails verification
  (`audit_pre`). These run *after* a poll's writes and only **detect**: the
  approval/authorization invariant, and the post-import chain verification
  (`audit`). Their writes are already committed; the sync halts before importing
  more.
- **Ordering.** Timestamps are parsed to UTC instants (timezone-less values are
  rejected). A batch is sorted by (instant, message id), and messages are handed
  to the importer **one at a time**, so the importer's text sort cannot reorder
  them.
- **Accounting.** `imported_message_ids` lists only messages the importer
  actually recorded. Skipped non-text messages are listed separately with a
  reason, and concurrent duplicates separately again.
- **Duplicate protection.** An id filter, ingestor de-duplication and a UNIQUE
  index on `(source, external_id)`; one sync per database (lock file).
- **Errors.** SQLite lock errors are retried a bounded number of times
  (attempts plus a time limit), then halt. Any other error halts with exit 1.
  The last log record always matches the exit code (`stop`/0, `halted`/1|2,
  `interrupted`/130). A failure is never logged as success.
- **Runtime paths.** The sync, roster and export refuse paths inside the
  repository. `live_sync_*.jsonl` and `*.live-sync.lock` are gitignored as a
  backstop.
- **Out-of-order recovery is manual** (runbook §6). There is no skip mechanism.

**Proposed, not implemented (needs approval): make the after-import checks
preventive.** The sync could wrap each message import in an outer
`db.transaction`. The ingestor's own transaction would then nest as a SAVEPOINT,
and the invariant and chain checks could run before the outer COMMIT, rolling
back a bad message. No Core change is needed. Implications: each message would
hold SQLite's write lock (`BEGIN IMMEDIATE`) for the import plus a full-chain
verification, which takes milliseconds at demo volumes but grows with chain
length. The Commander gate's writes would wait (busy_timeout 5 s) or fail
closed with a lock error during that window.

**Residual risks.** These are not tested against real Band: real-world view
latency and ordering; free-tier views that may miss messages mentioning none of
our agents; and a Commander tool call made between a sign-off and the next poll
(blocked, so the Commander must retry).
