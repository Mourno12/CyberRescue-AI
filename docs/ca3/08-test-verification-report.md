# 08 — Test and verification report

All results were produced on **2026-10-11** on Windows 11, Python 3.13.15
(`.venv313`), at base commit `67a7f16` (archived history) plus the uncommitted changes listed in
[11 §3](11-contribution-attribution.md#3-changes-made-during-this-task-2026-10-11-ai-assisted-claude-code)
(stages 1–3). Those changes were later committed as `ebdfa24` (archived history). Both hashes refer to
the archived history in the original repository (https://github.com/Mourno12/-CyberRescue-AI,
branch `cyberrescue-ai`); this repository is a single snapshot of the same files ([11 §4](11-contribution-attribution.md#4-repository-history)).

## 1. Offline test suite

| Run | Command | Result |
|---|---|---|
| Baseline (before any change) | `.venv313\Scripts\python.exe -m pytest -q -p no:cacheprovider` | **1431 passed**, exit 0 (117.8 s) |
| After stage 1 | same | **1489 passed**, exit 0 (85.1 s) |
| After stage 2 | same | **1555 passed**, exit 0 (89.3 s) |
| **After stage 3 — pre-live hardening (current)** | same | **1633 passed**, exit 0 (106.8 s when run alone; 203–231 s in runs that overlapped other jobs. `--durations=12`: slowest test 1.77 s, none from stage 3) |
| Live suite, not opted in | `… -m pytest tests_live -q -p no:cacheprovider -rs` | **3 skipped** ("LIVE test: set CYBERRESCUE_LIVE_TESTS=1"), exit 0 |

No existing test was deleted, skipped or weakened, and no upstream test was
edited. The upstream prompt texts are unchanged, so `tests/test_option_b*.py`
still check them as written. 202 new offline tests in total (stage 3 adds 78):

| File | Tests | Covers | Doubles used |
|---|---|---|---|
| `tests/test_live_hardening.py` (stage 3) | 76 | **errors**: lock retried then succeeds; lock mid-batch (committed messages kept, each imported once); retry exhaustion by attempts and by time; non-retryable SQLite error; unexpected error (details withheld from the log); `SystemExit` still writes a failed terminal record; clean shutdown; interrupted message rolled back; CLI boundary → exit 1. **placeholders**: 12 placeholder forms rejected; 5 unfamiliar real-looking values accepted; example/malformed handles; **the runbook's YAML block and `agent_config.yaml.example` fail preflight**; missing `humans.ciso` → migration message. **accounting**: skipped reported once and never as imported; counts equal database changes; manual import plus mixed batch; concurrent duplicate. **timestamps**: Z / fractional / offset equivalence; timezone-less or invalid rejected; a batch whose lexical order differs from its chronological order is imported chronologically (mutation-checked: a text-sort mutant fails the test); id tie-break; an ambiguous Core timestamp halts; out-of-order across formats. **recovery**: a re-run halts again; no skip. **paths**: inside-repo detection (normalised, case, `..`, prefix trap); sync/roster/export refuse repo paths before any network; gitignore patterns. **audit**: a tampered chain halts before import (prevented); a post-import failure is detected after the write. **exporter/handles**: truncated view incomplete; exact last page complete; swapped handles not rewritten twice; bare handles detected. **verify-sync**: clean run consistent; a missing message and a dirty end are flagged; read-only | MOCKED room / REST clients, SYNTHETIC messages, SIMULATED SQLite locks, real Core |
| `tests/test_live_handles.py`, `tests/test_live_preflight.py` (stage 3 additions) | +1, +1 | a non-UUID CISO id warns but does not fail; UUID-shaped ids pass **format** checks only | SYNTHETIC |

Stage 2 tests:

| File | Tests | Covers | Doubles used |
|---|---|---|---|
| `tests/test_live_sync.py` (stage 2) | 38 | polling bounds; first import and recorded state; **idempotency** (repeated polls leave the chain byte-identical; sync after a manual import adds nothing); incremental growth; settle window; tool calls counted not ingested; **halts**: out-of-order, 4 invalid-message kinds, 3 cross-incident refs, incomplete views (nothing imported), invariant (a forged approval halts), unknown incident; transient error then recovery; max polls / max minutes; stops at RESOLVED; Ctrl-C clean shutdown; one sync per DB; log ↔ chain-head consistency; source never calls authorizing APIs; **synced sign-offs → real Commander tool in enforce**: P4 → P5 (the CISO ruling message did not approve) → executed after `grant_approval` → duplicate blocked; CLI refuses incomplete credentials; CLI `--once` through the real exporter | **MOCKED** Band room / REST clients, SYNTHETIC messages, real Core, ingestor, gate and tool |
| `tests/test_live_handles.py` (stage 2) | 27 | handle validation (7 bad cases, missing CISO); CISO user id; every upstream prompt renders with zero upstream or unresolved handles; CISO handle doesn't clobber longer handles or emails; rendering with upstream handles is the identity; `render_prompt` fails closed; agent mains use the renderer; driver nudges rendered and only the configured CISO mentioned; injector fails before any network call; identity/account-mapping/CISO checks; no keys in the report; roster requires the CISO | SYNTHETIC identities; stub Band participants |

Stage 1 tests (`test_live_preflight.py` is now 31 after stage-2 updates for `humans.ciso`):

| File | Tests | Covers | Doubles used |
|---|---|---|---|
| `tests/test_live_preflight.py` | 31 | config validation; placeholder/duplicate detection; `.env.local` precedence; no secret value in output; env untouched; tracked-secret detection; gate-mode warnings; prompts render to configured handles; unconfigured identity in a prompt fails; agent import failure reported; **real** agent and facilitator imports; launcher uses the resolver; CLI exit codes | SYNTHETIC config; MOCKED importer in one test |
| `tests/test_live_roster_export.py` | 13 | roster building and rejection; Band view union, de-duplication, ordering, pagination; failed view recorded; tool-call counting; export → `core import-band` → gate decisions round trip; idempotent re-import | **MOCKED** Band REST clients, SYNTHETIC messages |
| `tests/test_live_protocol_flow.py` | 10 | Commander replanning (old sign-offs don't carry over, veto persists); SIGNOFF without request rejected; human escalation (observer and agent-claiming-CISO cannot rule; ruling ≠ approval); malformed messages (4 kinds); wrong-incident block; duplicate message id; **real Commander tool in enforce**: blocked (P4) → blocked (P5) → executed once → duplicate blocked; every decision in the gate log and Core audit with the same actor | SYNTHETIC messages, real ingestor, gate and tools |
| `tests/test_launcher_python.py` | 5 | `.venv313` preferred over `.venv`; env and explicit override order; a missing explicit path is an error, not a fallback; no venv → error | real PowerShell, placeholder exe files |

## 2. Deterministic evaluation (ground truth, SYNTHETIC)

`python -m cyberrescue.evaluation run --investigation --response --execution --accountability`
exit **0**. Across all three scenarios: **114 checks `match`, 17
`not_evaluated` (ground truth silent), 0 mismatches.**

| Scenario | Incident | Truth | Findings | Malicious evidence cited | Plan | Simulated and recorded |
|---|---|---|---|---|---|---|
| A | INC-C-2026-0042 | true positive, 225 events / 58 malicious | 10 (0 unexpected) | **58/58** | **8 steps, 3 decision points** | **8/8** recorded and verified, 0 refused |
| B | INC-B-2026-0041 | false positive, 153 / 0 | 0 | 0/0 | 0 steps | 0 |
| C | INC-A-2026-0039 | true positive, 110 / 6 | 5 | 5/6 as support (6/6 incl. context) | 5 steps, 1 decision point | 5 |

The four audit figures to re-verify (10 findings; 58/58; 8-step plan with 3
decision points; 8/8 execution records) were **all confirmed** for scenario A.

## 3. Offline stepwise demo

`scripts\demo_offline.ps1` ran twice with exit 0 (run 1 with `-SkipEvaluation`,
run 2 complete). Observed: 5 ALLOW and 3 REQUIRE_APPROVAL (P5) on first request;
`wipe_host` REQUIRE_APPROVAL (P6, P8); 3 CISO approvals → 3 ALLOW; 8 simulated
executions recorded and VERIFIED; `core verify` OK (442 incident events, 14
system events, 225 evidence records); anchor OK; the tampered copy reports
`TAMPERED … seq 427: content hash mismatch` and anchor `MISMATCH` (exit 1 as
expected).

## 4. Live preparation checks

| Check | Result |
|---|---|
| `python -m cyberrescue.live preflight` on this checkout | **NOT READY** (exit 1). FAIL: `OPENAI_API_KEY` missing, `ANTHROPIC_API_KEY` missing, `agent_config.yaml` not found. WARN: no `.env`/`.env.local`, gate in shadow. OK: Python 3.13.15 in `.venv313`, all pinned packages, the 4 agent modules and facilitator import, no secret file tracked |
| `run_all.ps1 -Headless` with a failing preflight | Refused: "preflight failed (exit 1) -- nothing was launched"; no PID file, no logs |
| Live multi-agent run | **Not performed** (no credentials; paid usage not approved) |
| `live sync --once` without `agent_config.yaml` (stage 2) | exit 2, `agent_config.yaml not found`; no database created |
| `live sync` offline rehearsal (stage 2, MOCKED room, real Core) | 4 polls → RESOLVED, 9 messages imported, exit 0; a second room with a late message → `HALTED (out_of_order)`, exit 1 (`sync_rehearsal_mocked\`) |
| Preflight on this checkout (stage 2) | still **NOT READY** for the same 3 reasons; no `[identities]` section because there is no config to check |
| Preflight with a copy of `agent_config.yaml.example` (stage 3) | **NOT READY**, exit 1: 8 FAIL (both keys, the 5 agents' placeholder id/key, handles). The runbook-YAML copy (after the identity-report fix) reports 9 FAIL, including `humans.ciso.user_id`. No secret values printed |
| Offline sync rehearsal (stage 3, MOCKED, `rehearsal\`) | clean run → `stop`/0, 9 imported, 1 tool call skipped; lock exhausted → `halted`/1 (`db_locked`), 0 imported; mixed timestamp formats → imported in chronological order; out-of-order → `halted`/1 with the normalised timestamp. `verify-sync` on the clean run → CONSISTENT, exit 0 |

## 5. Security and hygiene

- Secret-pattern scan over tracked and new files: no matches except clearly
  labelled `SYNTHETIC` test strings.
- `.env`, `.env.local` and `agent_config.yaml` are absent, untracked and gitignored.
- No database, log, key or PID file was left in the working tree. Demo outputs go
  to `%TEMP%`.
- `origin` is unchanged, and no commit or push was made during verification.

## Evidence files

In `%TEMP%\cyberrescue-ca3-evidence\` on the verification machine (outside the
repository, not committed; copy it somewhere permanent, because `%TEMP%` can be
cleaned):

| File | Content |
|---|---|
| `offline_eval_scenarioA.txt` (+ `.exitcode`) | first evaluation run, exit 0 |
| `offline_eval_scenarioA_final.txt` | final evaluation run, exit 0 |
| `offline_eval_all_scenarios.txt` | A, B and C evaluation, exit 0 |
| `offline_demo_run1\`, `offline_demo_run1.console.txt` | stepwise demo, run 1 |
| `offline_demo_run2\`, `offline_demo_run2.console.txt`, `.exitcode` | stepwise demo, run 2 (complete) |
| `pytest_baseline.txt` | 1431 passed, exit 0 (before any change) |
| `pytest_full_after_changes.txt` | 1487 passed (intermediate, before the prompt-handle tests) |
| `pytest_final.txt` | 1489 passed, exit 0 |
| `pytest_live_skipped.txt` | 2 skipped (stage 1) |
| `pytest_stage2.txt`, `pytest_stage2_final.txt` | 1555 passed, exit 0 (stage 2) |
| `pytest_live_stage2.txt` | 3 skipped (stage 2) |
| `offline_eval_all_stage2.txt` | A, B, C evaluation after stage 2, exit 0 (114 match, 17 not evaluated) |
| `offline_demo_stage2\`, `offline_demo_stage2.console.txt` | stepwise demo after stage 2, exit 0 |
| `sync_rehearsal_mocked\` | console and JSONL logs of the MOCKED-room sync rehearsal |

Stage 3 evidence is in `%TEMP%\cyberrescue-ca3-stage3\`:
`pytest.txt` / `pytest_final.txt` (1633 passed), `pytest_live.txt` (3 skipped),
`eval.txt` (A/B/C, exit 0), `demo\` and `demo.console.txt` (exit 0),
`preflight_example.txt` and `preflight_runbook_yaml.txt` (NOT READY, exit 1),
`rehearsal\` (sync scenarios and `verify-sync.txt`), and `durations.txt`.
