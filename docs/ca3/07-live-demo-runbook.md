# 07 — Live demo runbook (four LLM agents on Band)

> **Every live step in this runbook is NOT VERIFIED.** No live run has been made
> on this branch: no `agent_config.yaml`, `.env` or `.env.local` exists in the
> checkout, and paid API usage has not been approved. The commands use code that
> passes the offline test suite with MOCKED Band clients. That shows the code
> paths behave as designed against SYNTHETIC inputs. It does not show that a
> real Band room or real LLMs behave as expected. Do not present a live run as
> successful until §8 passes on records it actually produced.

Labels used below:

| Label | Meaning |
|---|---|
| **[NOT VERIFIED]** | never run against real Band or LLMs |
| **[offline-tested]** | behaviour covered by the offline test suite (mocks / synthetic data) |
| **[upstream-reported]** | stated by upstream WarRoom files; not re-checked here |
| **[offline]** | free, no network |
| **[read-only network]** | reads Band, posts nothing |
| **[paid]** | LLM usage |

## 0. Cost and safety

- **[paid]** Three agents call OpenAI-compatible models and the Commander calls
  Anthropic. **[upstream-reported]** One Sonnet-Commander run used about 1.27M
  tokens (`agents/commander/main.py` comment). Haiku is the cheaper default.
  Caps: `*_MAX_TOKENS`, `*_RECURSION_LIMIT`.
- **Simulated actions only.** Commander action tools append to
  `actions_log.jsonl`. With `CYBERRESCUE_GATE_MODE=enforce` they run only on a
  Core ALLOW **[offline-tested]**.
- **`live sync` has no authority [offline-tested].** It reads the room and
  imports messages through the existing importer. It contains no call that
  requests, approves, authorizes or executes an action (a static test checks
  the source). **An imported CISO message is a message, not an approval.** Only
  `core approve` creates one. The checks that run *after* an import (approval
  invariant, audit chain) **detect** a problem; they do not undo a write that is
  already committed (see §6, table "Checks").
- Outward-facing steps (posting in Band, `clean_rooms.py --execute`) affect real
  accounts. Run them deliberately.

## 1. External prerequisites (you supply these)

| Item | Detail |
|---|---|
| Band **primary** account | Triage, Threat Intel, Commander, Facilitator agents, and the human CISO user |
| Band **secondary** account | Compliance (external counsel). Send a contact request from primary to secondary and accept it before launch **[upstream-reported]** |
| 5 External Agents | app.band.ai → Agents → New Agent → External Agent. Record each **agent UUID**, **API key** (shown once) and **handle** |
| CISO identity | The CISO's Band **handle** (`@owner`) and **user id** (the `sender_id` on their messages; visible in any `export-band` output) |
| LLM keys | `OPENAI_API_KEY` (+ optional `OPENAI_BASE_URL`), `ANTHROPIC_API_KEY` (+ optional `ANTHROPIC_BASE_URL`) |
| Band tier | **[upstream-reported]** The free tier blocks the human API, so the alert is pasted manually (`BAND_TIER_LIMITATION.md`) |

## 2. Configuration [offline]

All identities live in **one** file, `agent_config.yaml` (gitignored):

```powershell
cd <repo-root>                        # the folder of your clone of this repository
copy agent_config.yaml.example agent_config.yaml
copy .env.example .env.local          # OPENAI_API_KEY / ANTHROPIC_API_KEY (gitignored)
```

The shape is below. **Every `<...>` value is a placeholder.** The preflight
rejects it, as well as `REPLACE_WITH_...`, `@you/...` and `@youraccount/...`,
until you replace it with the real value (a test enforces this for this exact
block):

```yaml
agents:
  triage:       {account: primary,   framework: langgraph,   handle: "@<primary-account>/triage",       agent_id: "<uuid>", api_key: "<key>"}
  threat_intel: {account: primary,   framework: langgraph,   handle: "@<primary-account>/threat-intel", agent_id: "<uuid>", api_key: "<key>"}
  compliance:   {account: secondary, framework: pydantic_ai, handle: "@<secondary-account>/compliance", agent_id: "<uuid>", api_key: "<key>"}
  commander:    {account: primary,   framework: anthropic,   handle: "@<primary-account>/commander",    agent_id: "<uuid>", api_key: "<key>"}
  facilitator:  {account: primary,   framework: none,        handle: "@<primary-account>/facilitator",  agent_id: "<uuid>", api_key: "<key>"}
humans:
  ciso: {handle: "@<primary-account>", user_id: "<ciso band user id>"}
room:
  default_room_id: ""
```

An `agent_config.yaml` written before this change, without `humans.ciso`, fails
the preflight with a migration message. Copy the `humans:` block from
`agent_config.yaml.example`.

**How handles are used.** The upstream prompts (`agents/*/prompt.md`) and
Facilitator nudges are kept verbatim. They name the upstream author's accounts
(`@merolavtech/...`, `@merolavtechnologies/compliance`, CISO `@merolavtech`). At
startup each agent loads its prompt through `shared.config.render_prompt`. This
replaces every upstream handle with the configured one in a single pass, and
raises if any `@owner/slug` or bare `@owner` handle would remain that is not a
configured identity.

**[offline-tested]** That rejection is covered by unit tests (`render_prompt`
fails closed; each agent `main.py` calls it). **No real agent startup has been
performed.** Recruitment (`shared/sdk_patches.py`), the Facilitator and the
injector read the same file.

## 3. Preflight [offline]

```powershell
.\.venv313\Scripts\python.exe -m cyberrescue.live preflight
```

Expected when ready: `READY for launch: 0 failures`. It never prints keys.
**Format checks only.** The preflight cannot prove that a key, UUID or handle
exists or works.

| FAIL / WARN line | Meaning and fix |
|---|---|
| `[credentials] OPENAI_API_KEY / ANTHROPIC_API_KEY missing\|placeholder` | Fill in `.env.local` |
| `[agent_config] file … not found` | Copy the example (§2) |
| `[agent_config] <role> agent_id/api_key missing\|placeholder`, `duplicates` | Wrong, placeholder or copied credentials for that agent |
| WARN `agent_id not a UUID` / `humans.ciso.user_id not a UUID` | The Band ids seen so far are UUIDs (`shared/sample_message.json`). Check the copy |
| `[identities] handles … agents.<role>.handle=…` | Handle missing, placeholder/example, not `@owner/slug`, or duplicated |
| `[identities] handles … humans.ciso is missing` | Old config: add the `humans.ciso` block |
| `[identities] humans.ciso.user_id missing or placeholder` | Without it the CISO's ruling imports as `observer` and can never resolve an escalation |
| `[identities] account mapping …` | Primary-account agents must share one owner; a `secondary` agent must not be on the primary owner |
| `[prompts] <role> unresolved handles …` | A prompt names an identity that is not configured |
| `[secrets] … TRACKED / not gitignored` | Remove the file from git (`git rm --cached`) before doing anything else |

## 4. Common setup — paste into EVERY PowerShell window [offline]

Each window needs its own variables; PowerShell windows do not share them. Pick
the run folder **once**, outside the repository, and reuse that exact path in
every window. The sync and export commands refuse any path inside the
repository.

```powershell
cd <repo-root>
$run = "$env:TEMP\cyberrescue-live-<yyyymmdd-hhmm>"   # same value everywhere
$py  = (Resolve-Path ".\.venv313\Scripts\python.exe").Path   # absolute path, run from <repo-root>
$env:CYBERRESCUE_DB_PATH       = "$run\live.db"
$env:CYBERRESCUE_GATE_LOG      = "$run\gate_log.jsonl"
$env:ACTIONS_LOG_PATH          = "$run\actions_log.jsonl"
$env:CYBERRESCUE_GATE_MODE     = "enforce"
$env:CYBERRESCUE_INCIDENT      = "INC-C"
$env:CYBERRESCUE_COMMANDER_REF = "band:<commander agent_id>"
```

Window 1 only (once):

```powershell
New-Item -ItemType Directory -Force $run | Out-Null
& $py -m cyberrescue.core init
& $py -m cyberrescue.core seed-assets
& $py -m cyberrescue.core register-actor --kind human --role ciso --name "CISO" --ref "band:<ciso user_id>"
& $py -m cyberrescue.live roster --out "$run\roster.json"
& $py -m cyberrescue.live preflight          # gate section: enforce / INC-C
```

Registering the CISO with ref `band:<user_id>` means the ingestor reuses that
actor for the CISO's imported Band messages, so their messages and their
`core approve` approvals belong to one Core actor. This follows from the code
(`ProtocolIngestor._actor` looks the ref up). It is exercised in offline tests
only via ingestion-created actors.

## 5. Launch [NOT VERIFIED] [paid once an alert arrives] — window 1

```powershell
& $py scripts\clean_rooms.py                                  # lists stale rooms only
powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1 -Headless
powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1 -Check
& $py -m injector.inject_alert INC-C --dry-run                # alert text to paste
```

1. Create an intake room in the Band UI, add Triage, and paste the alert.
   **[upstream-reported]** Triage creates the incident room and recruits the team
   (recruitment is in code, `shared/sdk_patches.py`).
2. Note the **incident room id**. In window 2 (after §4's common setup):
   `& $py scripts\incident_driver.py --room <room-id>`

## 6. Safe synchronisation [NOT VERIFIED] [read-only network] — window 3

After §4's common setup:

```powershell
& $py -m cyberrescue.live sync --room <room-id> --incident INC-C --interval 10 --max-minutes 60 --log "$run\live_sync.jsonl"
```

**[upstream-reported]** On the free tier each agent key's context view holds
only the messages that agent sent or was @mentioned in (`scripts/export_transcript.py`,
`BAND_TIER_LIMITATION.md`). So every poll reads **all five** agent views and
merges them by message id. Messages that @mention none of our agents may be
invisible. This is not verified here.

Each poll **[offline-tested]**:
- parses every timestamp to a UTC instant (timezone-less values are rejected);
- sorts new messages by (instant, message id);
- waits until they are at least `--settle` seconds old (default 5);
- imports text messages **one at a time** through the same importer as
  `core import-band`.

Non-text messages (tool calls and results) are listed under `skipped` with a
reason and are never reported as imported.

**Expected console format.** This is from the offline rehearsal (MOCKED room,
SYNTHETIC messages, real Core), not live output:

```text
[sync] poll 1: +3 imported, 0 skipped (non-text), 0 settling | AWAITING_SIGNOFF | sign-offs [] vetoes [] | verified approvals 0 | human msgs +1 (not approvals)
[sync] poll 2: +4 imported, 1 skipped (non-text), 0 settling | AWAITING_HUMAN | sign-offs ['compliance', 'threat_intel'] vetoes ['wipe_host'] | ...
[sync] stop: incident is RESOLVED | 4 poll(s), 9 message(s) imported | exit 0
```

`verified approvals` counts unconsumed approvals created by `core approve`.
`human msgs` counts imported CISO messages, which are **not** approvals.

### Checks: prevent or detect

| Code | Prevents or detects | Meaning |
|---|---|---|
| `incomplete` | prevents | an agent view failed or was truncated (page limit): nothing imported that poll; halts after `--max-errors` consecutive polls |
| `invalid` | prevents | missing id/sender, unparseable or timezone-less timestamp, another room; or the Core already holds a Band message without a usable timestamp |
| `out_of_order` | prevents | a new text message is older than one already imported (see the procedure below) |
| `correlation` | prevents | a protocol block names a different or unknown incident |
| `audit_pre` | prevents | the incident hash chain fails verification **before** this poll imports anything |
| `audit` | detects | the chain fails verification **after** this poll's imports. Those writes are committed |
| `invariant` | detects | an event caused by this poll's import is an approval, authorization or execution. Committed; the sync halts before importing more |
| `db_locked` | — | SQLite stayed locked after `--db-lock-attempts` (default 5) or `--db-lock-timeout` s (default 30). Messages committed before the lock stay; none is half-written |
| `unexpected` | — | any other error. The log records the exception type; details are withheld unless known to be safe |

### Terminal record and exit codes [offline-tested]

The last line of the sync log always states the outcome, and it matches the
exit code:

| Last record `kind` | Exit | When |
|---|---|---|
| `stop` | 0 | incident terminal, or `--max-polls` / `--max-minutes` reached |
| `halted` | 1 | any check above (`config` problems: 2) |
| `interrupted` | 130 | Ctrl-C |
| (no log written) | 2 | lock held, path inside the repo, missing credentials, bad arguments |

**Ctrl-C.** Each message import is its own database transaction. If you
interrupt during a poll, the message being written is rolled back. Messages
committed earlier in that poll stay, and the poll as a whole is not one
transaction. The lock file is removed and an `interrupted` record is written.

### Out-of-order halt — operator procedure (no automatic skip)

An `out_of_order` halt means a view returned a message older than one already in
the Core. Importing it now could change what earlier records mean. For example,
a SIGNOFF imported before its SIGNOFF_REQUEST is rejected **permanently**,
because message ids are imported once. The sync never skips a message. Re-running
the sync halts again on the same message; it does **not** resume by itself.

1. **Stop** syncing this incident. Leave the sync stopped. The agents and the
   gate keep running; the gate fails closed on anything not yet imported.
2. **Preserve** the evidence. Keep `$run\live_sync.jsonl` (its `halted` record
   lists the message ids and normalised timestamps), and take an export:
   `& $py -m cyberrescue.live export-band --room <room-id> --out "$run\export-at-halt.json"`
3. **Verify the chain:** `& $py -m cyberrescue.core verify --incident INC-C`
4. **Inspect** the listed ids in the export: their `inserted_at`, sender, type,
   and which views returned them (compare with earlier exports, if any).
5. **Classify** the cause: delayed delivery by Band; inconsistent views; a
   message that was missing earlier; or genuinely invalid ordering.
6. **Decide explicitly**, and write the decision down in `$run`:
   - If the late message changes nothing that is already recorded (for example
     a FINDING or QUESTION), you may import it once through the **same
     importer**. The ingestor's role and identity checks still apply:
     `& $py -m cyberrescue.core import-band "$run\export-at-halt.json" --incident INC-C --roster "$run\roster.json"`
     Then confirm with `verify-sync` (§8) before restarting the sync.
   - If it would change the meaning of recorded sign-offs or vetoes, **do not**
     import it into this incident. Continue authorization manually with
     `core approve` decisions based on what is recorded, or run the scenario as
     a **fresh incident**.
7. **Resume** only after step 6. The sync's own checks still apply when it is
   restarted. There is no flag to skip a message, and none should be added.

### Authorization during the run (human-in-the-loop)

When the gate blocks with P5 (critical asset), or the wipe needs P6/P7/P8, a
human approves through the Core. Chat text never approves:

```powershell
& $py -m cyberrescue.core show --incident INC-C
& $py -m cyberrescue.core approve --incident INC-C --action isolate_host --asset srv-db-01 --approver <ciso actor id> --reason "..."
# the wipe additionally needs: --override-hold --override-veto
```

Then ask the Commander in Band to retry. Each retry is a fresh gate decision.

### Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `... resolves inside the repository` | Set `CYBERRESCUE_DB_PATH` / `--log` / `--out` to the run folder (§4) |
| `refusing to start: no usable credentials for [...]` | One agent's entry is missing or a placeholder. A complete set of views is required |
| `another sync holds …live-sync.lock` | One sync per database. If none is running, delete the lock file |
| Repeated `incomplete transcript: views [...] failed or were truncated` | Band, network or key problem for that agent, or more than 5,000 messages in a view |
| `db_retry` lines, then `HALTED (db_locked)` | Another process held the database too long. Check nothing else is writing it, then rerun |
| `HALTED (out_of_order)` | Follow the procedure above |
| `HALTED (correlation)` | Wrong `--room`, or an agent wrote a different incident id. Check the export |
| `HALTED (audit_pre)` | The chain was already broken. Stop and investigate (`core verify`); do not import |
| `unrostered senders imported as unknown/observer` | A sender id is not in `agent_config.yaml`. They cannot sign off, veto or rule |
| Containment stays blocked with P4 | A specialist's SIGNOFF has not been synced yet, or the latest SIGNOFF_REQUEST doesn't cover the action |
| Agent exits at start with `HandleConfigError` | Fix `agent_config.yaml` handles (preflight `[identities]` / `[prompts]`) |

## 7. Capture (after RESOLUTION) [NOT VERIFIED] — any window after §4

```powershell
& $py -m cyberrescue.live export-band --room <room-id> --out "$run\export-final.json"
& $py -m cyberrescue.live sync --room <room-id> --incident INC-C --once --log "$run\live_sync.jsonl"
& $py scripts\export_transcript.py --room <room-id> --out "$run\transcript.md"
& $py -m cyberrescue.core verify
& $py -m cyberrescue.core anchor-keygen --out "<folder outside the repo>\anchor.key"
& $py -m cyberrescue.core anchor --out "$run\anchor.json" --key-file "<...>\anchor.key"
& $py -m cyberrescue.core verify --anchor "$run\anchor.json" --key-file "<...>\anchor.key"
copy triage.log, threat_intel.log, compliance.log, commander.log $run
```

**`transcript.md` limitation.** Upstream `scripts/export_transcript.py` always
reads `actions_log.jsonl` from the **repository root**. This run writes it to
`$env:ACTIONS_LOG_PATH` (`$run\actions_log.jsonl`), so the transcript's
"Actions executed" section will be empty. The authoritative action records are
`$run\actions_log.jsonl` and `$run\gate_log.jsonl`, plus the Core audit chain.
The upstream exporter is left unchanged.

## 8. Verification before calling it a success

```powershell
& $py -m cyberrescue.live verify-sync --export "$run\export-final.json" --log "$run\live_sync.jsonl" --incident INC-C
```

`verify-sync` is read-only (SQLite opened read-only, no network) **[offline-tested]**.
It reports `CONSISTENT` (exit 0) only if all of these hold:
- the export's views are complete;
- every text message in the export is in the Core, and the Core holds no Band
  message absent from the export;
- every id the sync log reports as imported is in the Core, exactly once;
- each poll's chain head matches the Core chain;
- the chain verifies;
- the log's last record is `stop` with exit 0.

Also check by hand:

- [ ] Every `actions_log.jsonl` line has a matching earlier `ALLOW` in `gate_log.jsonl` (same action and asset)
- [ ] Every `gate_log.jsonl` `core_event_uid` exists as a `GATE_DECISION` in the Core
- [ ] Approvals in the Core = the `core approve` commands you ran (no others)
- [ ] `core verify` OK; anchor verify OK
- [ ] Opt-in live tests: `$env:CYBERRESCUE_LIVE_TESTS="1"; $env:CYBERRESCUE_LIVE_ROOM="<room-id>"; & $py -m pytest tests_live -q -p no:cacheprovider -rs`

Record any failure as found. Never edit or fill in missing records.

## 9. Cleanup

```powershell
# Ctrl-C the sync and the Facilitator windows
powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1 -Stop
Remove-Item Env:CYBERRESCUE_GATE_MODE, Env:CYBERRESCUE_INCIDENT, Env:CYBERRESCUE_COMMANDER_REF
# optional, outward-facing: & $py scripts\clean_rooms.py --execute --keep <room-id>
```

Keep `$run` (the evidence) and the anchor key outside the repository.
