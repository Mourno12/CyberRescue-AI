# 05 — Installation and user guide (Windows / PowerShell)

## 1. Prerequisites

| Need | For | Notes |
|---|---|---|
| Windows 10/11 + Windows PowerShell 5.1 | all scripts | verified on Windows 11 |
| Python 3.13 | `.venv313` | the verified interpreter is 3.13.15. Python 3.14 (`.venv`) also exists but is not the verified one |
| Git | preflight secret checks | |
| Band accounts + 5 external agents + LLM keys | **live mode only** | see [07](07-live-demo-runbook.md) |

## 2. Environment

The existing verified environment is `.venv313`. To recreate it (replace
`<repo-root>` with the folder where you cloned this repository; every command
in these documents runs from there):

```powershell
cd <repo-root>
py -3.13 -m venv .venv313
.\.venv313\Scripts\python.exe -m pip install -e .
.\.venv313\Scripts\python.exe -m pip install pytest
```

`pyproject.toml` pins `band-sdk==0.2.11` and `pydantic-ai-slim==1.56.0`. Do not
upgrade them; the preflight fails if they drift.

Every PowerShell script picks its interpreter in this order: `-Python <path>`,
then `$env:CYBERRESCUE_PYTHON`, then `.venv313`, then `.venv`. A path given
explicitly that does not exist is an error. The script never quietly switches to
another interpreter.

## 3. Offline mode (no credentials)

```powershell
# full deterministic evaluation (one command)
.\.venv313\Scripts\python.exe -m cyberrescue.evaluation run --scenario A --investigation --response --execution --accountability

# step-by-step demo with artifacts (fresh DB in %TEMP%, never in the repo)
powershell -ExecutionPolicy Bypass -File scripts\demo_offline.ps1          # add -Pause to present
```

See [06](06-offline-demo-runbook.md) for what each step shows.

### Individual commands (all accept `--db PATH`, or use `$env:CYBERRESCUE_DB_PATH`)

| Layer | Command |
|---|---|
| Core | `python -m cyberrescue.core init / seed-assets / register-actor / request / approve / show / verify / anchor-keygen / anchor / import-band` |
| Telemetry | `python -m cyberrescue.telemetry list / show / open-incident --scenario A / ingest --scenario A --collector <id> / check` |
| Detection | `python -m cyberrescue.detection rules / run --incident INC-C [--persist --detector <id>] / findings` |
| Investigation | `python -m cyberrescue.investigation case / timeline / scope / gaps / entity / path / pivot / provenance / verify-case` |
| Response | `python -m cyberrescue.response plan / step / verify-plan` |
| Execution | `python -m cyberrescue.execution simulate --plan PLAN.json [--record --recorder <id>] / verify / show` |
| Live prep | `python -m cyberrescue.live preflight / roster / export-band / sync / verify-sync` (runtime paths must be outside the repo) |

## 4. Live mode configuration

```powershell
copy .env.example .env.local                      # then edit; .env.local is gitignored
copy agent_config.yaml.example agent_config.yaml  # then edit; gitignored
.\.venv313\Scripts\python.exe -m cyberrescue.live preflight
```

`agent_config.yaml` is the single source of identities: five agents
(`agents.<role>.handle/agent_id/api_key/account`) and the CISO
(`humans.ciso.handle/user_id`). The unchanged upstream prompts are rendered with
these handles when each agent starts. See [07 §2](07-live-demo-runbook.md#2-configuration-offline).

Never commit `.env`, `.env.local` or `agent_config.yaml`. The preflight fails if
any of them is tracked or not ignored. It prints only `missing`, `placeholder` or
`set` for credentials, never the values.

### Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | live | Triage, Threat Intel, Compliance |
| `ANTHROPIC_API_KEY` | live | Commander |
| `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` | optional | OpenAI-compatible or proxy endpoints (upstream used the AIML endpoint) |
| `TRIAGE_MODEL`, `THREAT_INTEL_MODEL`, `COMPLIANCE_MODEL`, `COMMANDER_MODEL` | optional | defaults `gpt-4o`, `gpt-4o`, `openai:gpt-4o`, `claude-haiku-4-5-20251001` |
| `CYBERRESCUE_GATE_MODE` | recommended | `enforce` for the authorization demo (default `shadow` only logs) |
| `CYBERRESCUE_INCIDENT` | recommended | `INC-C`, which binds gate decisions to the incident |
| `CYBERRESCUE_COMMANDER_REF` | recommended | `band:<commander agent_id>`, so gate requests and imported Commander messages share one Core actor |
| `CYBERRESCUE_DB_PATH` | optional | Core database (default `<repo>\cyberrescue.db`, gitignored) |
| `CYBERRESCUE_GATE_LOG` | optional | gate JSONL log path |
| `CYBERRESCUE_ANCHOR_KEY_FILE` | optional | anchor key path (keep it outside the repo) |

### Launcher

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1 -Headless   # preflight, then launch 4 agents
powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1 -Check      # are all 4 listening?
powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1 -Stop       # stop everything it started
```

Behaviour added in this task:

- `run_all.ps1` runs the offline preflight first and launches nothing if it fails
  (`-SkipPreflight` overrides).
- If any agent FAILS during startup, every agent the run launched is stopped
  (`-KeepOnFailure` overrides). Logs are kept.

## 5. Tests

```powershell
.\.venv313\Scripts\python.exe -m pytest -q -p no:cacheprovider            # offline suite (tests/)
$env:CYBERRESCUE_LIVE_TESTS = "1"; $env:CYBERRESCUE_LIVE_ROOM = "<room-id>"
.\.venv313\Scripts\python.exe -m pytest tests_live -q -p no:cacheprovider -rs   # LIVE, read-only Band
```
