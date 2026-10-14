# 11 — Contribution and upstream attribution statement

All facts below come from the original git history of CyberRescue-AI, which is
preserved unchanged in the original repository, https://github.com/Mourno12/-CyberRescue-AI
(branch `cyberrescue-ai`, last commit `ebdfa24`), called the archived history
below. This repository is a single snapshot commit (see §4); the commit hashes
cited below refer to the archived history and do not exist in this repository. Nothing here describes team
roles or individual effort beyond what git records. Add your own statement of
individual contribution where your module requires it.

## 1. Inherited: upstream WarRoom

- Source: `https://github.com/genyarko/warroom` (the `origin` remote of the original development
  repository).
- 23 commits authored as **"George"** (GitHub account `merolavtechnologies`),
  dated 2026-06-13 to 2026-06-15. Tag `warroom-baseline` = `e5c11bc` (upstream
  commit; also in the archived history).
- 20 of these 23 commits carry `Co-Authored-By` trailers for Claude models
  (6 × Claude Haiku 4.5, 14 × Claude Opus 4.8).
- Neither the upstream repository nor this one contains a license file; see
  [`NOTICE.md`](../../NOTICE.md).
- **The four-agent architecture originates substantially from upstream.** That
  includes:
  - the Triage, Threat Intel, Compliance and Commander agents (`agents/`), their
    prompts and domain tools;
  - the Band protocol and `ProtocolMessage` schema (`shared/protocol.md`,
    `shared/schemas.py`);
  - the deterministic mock environment (`shared/mock_env/`);
  - the Band SDK patches including code-based recruitment (`shared/sdk_patches.py`);
  - the launcher (`scripts/run_all.ps1`), the Facilitator watchdog
    (`scripts/incident_driver.py`), the exporters, the injector, Docker files, and
    the original 77-test suite.

## 2. Previously implemented in CyberRescue-AI (before this task)

- 79 commits authored under the git identity **Mourno12**, dated 2026-09-27 to
  2026-10-04 (`07be340` … `67a7f16`, archived history).
- Upstream files modified: `agents/commander/tools.py` (+25 lines: the Core gate
  hook), `.gitignore`, `Dockerfile`, `pyproject.toml`. All other work is new
  files.
- New packages (`cyberrescue/`, about 14,950 inserted lines across 98 files, plus
  tests):

  | Phase | Package | Content |
  |---|---|---|
  | 1 / 1b | `cyberrescue/core` | SQLite Core, audit hash chains, state machine, policy engine (policy-v2), Commander gate (shadow/enforce), protocol ingestion, offline Band import |
  | 2A–2C | `core` evidence, `telemetry`, `detection` | hashed evidence, SYNTHETIC telemetry datasets, deterministic detection and correlation |
  | 3 | `investigation` | read-only case: timeline, graph, scope, gaps, export |
  | 4 | `response` | advisory planning, ATT&CK mapping, policy previews |
  | 5–6 | `execution` | SIMULATED executor, Core-recorded accountability (schema v3) |
  | 7 | `core/anchor.py` | keyed external audit anchors |
  | — | `evaluation` | ground-truth evaluation harness |

- The test suite grew from 77 (baseline) to 1,431 (at `67a7f16`, archived history).
- AI assistance: the phase 1–7 work was developed with substantial AI assistance
  from Claude Code, which was used for implementation, testing, debugging and
  documentation. Each of the 79 commits carries a
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` trailer, and together
  they cover every `cyberrescue/` package, the tests, the synthetic datasets, a
  bug fix (`1f5cb20`, archived history) and the phase documentation under
  `docs/cyberrescue/`. This code was therefore not written independently by
  Mourno12; it was produced with Claude Code under Mourno12's direction, review and
  testing. Describe the extent of that assistance further where your
  institution's academic-integrity policy requires it.

## 3. Changes made during this task (2026-10-11; AI-assisted, Claude Code)

| File | Change |
|---|---|
| `scripts/Resolve-RepoPython.ps1` | **new**. Interpreter resolution `-Python` → `CYBERRESCUE_PYTHON` → `.venv313` → `.venv`; never silently substitutes |
| `scripts/run_all.ps1` | **modified (upstream file)**. Uses the resolver (fixes the hard-coded `.venv`); runs the offline preflight before launching; stops all launched agents if one fails |
| `scripts/demo_offline.ps1` | **new**. Stepwise offline demo with artifacts, outcome assertions, and a tamper test on a copy |
| `cyberrescue/live/` (`preflight.py`, `roster.py`, `band_export.py`, `cli.py`, `__main__.py`, `__init__.py`) | **new**. Offline preflight (no network, never prints secrets, checks prompt handles); roster builder; read-only Band → import-JSON export |
| `tests/test_live_preflight.py`, `tests/test_live_roster_export.py`, `tests/test_live_protocol_flow.py`, `tests/test_launcher_python.py` | **new**. Offline tests (synthetic or mocked, labelled) |
| `tests_live/` | **new**. Opt-in live tests (read-only Band), skipped by default |
| `pyproject.toml` | `testpaths = ["tests"]` so the default run stays offline |
| `docs/ca3/` | **new**. This package |
| `README.md` | CyberRescue section added; upstream content kept |

### Stage 2 (2026-10-11, same session; AI-assisted, Claude Code)

| File | Change |
|---|---|
| `shared/config.py` | **modified (upstream file)**. Adds runtime handle configuration: `UPSTREAM_HANDLES` (the handles as written upstream), `handles_from_config`, `render_handles`, `render_prompt` (fails closed on unresolved handles), `ciso_user_id` |
| `agents/{triage,threat_intel,compliance,commander}/main.py` | **modified (upstream files)**, one line each: load the prompt through `render_prompt` |
| `scripts/incident_driver.py` | **modified (upstream file)**. Nudge texts rendered with configured handles; mentions only the configured CISO; no upstream handle fallback |
| `injector/inject_alert.py` | **modified (upstream file)**. No upstream handle fallback; checks before any network call |
| `agent_config.yaml.example` | **modified (upstream file)**. New `humans.ciso` (handle, user_id) |
| `cyberrescue/live/sync.py` + `cli.py` | **new**. `python -m cyberrescue.live sync` |
| `cyberrescue/live/preflight.py`, `roster.py` | identity, CISO and account-mapping checks; prompts checked after rendering; roster takes the CISO from config |
| `tests/test_live_handles.py`, `tests/test_live_sync.py` | **new**. Offline tests (SYNTHETIC identities, MOCKED Band) |
| `tests/test_live_preflight.py`, `tests/test_live_roster_export.py` | updated for the `humans.ciso` config and rendering |
| `tests_live/test_live_band_readonly.py` | opt-in single live sync poll |
| `docs/ca3/*` | runbook rewritten; design, limitations, report and checklist updated |

Not changed: the upstream prompt texts (`agents/*/prompt.md`), `shared/protocol.md`,
upstream tests, Core, policy, gate, and datasets. No commit, push, deployment,
Band message, or paid API call was made.

### Stage 3 — pre-live hardening (2026-10-11, same session; AI-assisted, Claude Code)

| File | Change |
|---|---|
| `cyberrescue/live/sync.py` | bounded SQLite lock retry; fail-safe terminal record (`stop`/`halted`/`interrupted`) matching the exit code; unexpected errors halt with exit 1 and a log-safe reason; UTC-normalised (instant, id) ordering with timezone-less timestamps rejected; one-message-per-import; truthful accounting (`imported`, `skipped`, `duplicates`); pre-import chain check (`audit_pre`); post-import checks documented as detection only |
| `cyberrescue/live/verify.py` | **new**. `verify-sync`: read-only cross-check of export, sync log and Core |
| `cyberrescue/live/cli.py` | refuse runtime paths inside the repo (sync DB/log, roster, export); `--db-lock-attempts/--db-lock-timeout`; `verify-sync`; CLI boundary turns unexpected errors into exit 1 |
| `cyberrescue/live/band_export.py` | a view that reaches the page limit is reported incomplete (`TruncatedView`) |
| `cyberrescue/live/preflight.py` | shared placeholder detection; UUID-format warnings (format only) |
| `shared/config.py` | **modified (upstream file)**. `is_placeholder`; example/placeholder handles rejected; missing `humans.ciso` → migration message; single-pass handle rendering; bare-handle detection |
| `.gitignore` | **modified (upstream file)**. `live_sync_*.jsonl`, `*.live-sync.lock` |
| `tests/test_live_hardening.py` | **new** (76 tests) |
| `tests/test_live_sync.py`, `tests/test_live_handles.py`, `tests/test_live_preflight.py` | updated to the new contracts (terminal record kinds, skipped reporting, timestamps in details, migration message, UUID warnings); no assertion weakened |
| `docs/ca3/07-live-demo-runbook.md` | rewritten: placeholder YAML, labels (NOT VERIFIED / offline-tested / upstream-reported), per-window setup, prevent-vs-detect table, out-of-order procedure, `verify-sync`, `transcript.md` limitation |
| `docs/ca3/02`, `05`, `08`, `09`, `11` | updated |

Not changed: Core, policy, gate, the upstream prompt texts, upstream tests,
upstream `scripts/export_transcript.py`, and datasets.

## 4. Repository history

- The original development history (23 upstream commits by George and 80 commits
  by Mourno12, ending at `ebdfa24`) is preserved unchanged in the original
  repository, https://github.com/Mourno12/-CyberRescue-AI, branch `cyberrescue-ai`. It is not
  part of this repository. The §3 work was committed there as `ebdfa24` (archived history) on 2026-10-14.
- This repository consists of a single snapshot commit of the same project files, plus
  `NOTICE.md` and the history notes in this document and in
  [08](08-test-verification-report.md), and without the upstream `.idea/` IDE
  settings folder (now gitignored). It was created and committed by Mourno12
  to publish the project as one snapshot. **The author recorded on that commit
  does not mean that Mourno12 wrote all of its content:** §1–§3 and
  [`NOTICE.md`](../../NOTICE.md) state who wrote what, and the archived history
  in the original repository keeps the per-commit authorship and `Co-Authored-By` trailers.
