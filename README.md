# CyberRescue-AI (built on WarRoom)

CyberRescue-AI is a project that extends the upstream WarRoom project below with
**CyberRescue Core**. The Core is a deterministic, audited system of record: an
evidence store, detection, investigation, response planning, a policy engine
that gates the Commander's actions, SIMULATED execution, and tamper-evident
audit anchoring. The four-agent design and everything under "WarRoom" below come
from upstream ([attribution](docs/ca3/11-contribution-attribution.md)).

| | Command (PowerShell, verified environment `.venv313`) |
|---|---|
| Offline evaluation | `.\.venv313\Scripts\python.exe -m cyberrescue.evaluation run --scenario A --investigation --response --execution --accountability` |
| Offline stepwise demo | `powershell -ExecutionPolicy Bypass -File scripts\demo_offline.ps1 -Pause` |
| Live readiness (no network) | `.\.venv313\Scripts\python.exe -m cyberrescue.live preflight` |
| Offline tests | `.\.venv313\Scripts\python.exe -m pytest -q -p no:cacheprovider` |

The offline pipeline is verified. **Live four-agent collaboration has not been
verified on this branch**; see the [CA3 package](docs/ca3/README.md),
specifically the [live runbook](docs/ca3/07-live-demo-runbook.md) and the
[limitations](docs/ca3/09-limitations-security.md). Phase design documents are
in [`docs/cyberrescue/`](docs/cyberrescue/).

---

# WarRoom

**Multi-agent cybersecurity incident response, coordinated through Band.**
Band of Agents Hackathon · Track 3 — Regulated & High-Stakes Workflows

A security alert fires. Four autonomous AI agents — built on **different agent
frameworks** and spanning **two organizations' Band accounts** — respond to the
incident *together*, entirely through one Band chat room using `@mention`
messages. A human is pulled in only for the irreversible, regulated decisions.
And when it's over, the transcript **is** the audit trail.

---

## The team of agents

| Agent | Framework | Role |
|---|---|---|
| **Triage** | LangGraph | Classifies the alert; recruits the right specialists into the room. |
| **Threat Intel** | LangGraph | Malware attribution + lateral-movement spread assessment. |
| **Compliance** | Pydantic AI | Runs on a **separate company's** Band account (external counsel). Owns the regulatory clock and holds **veto power**. |
| **Incident Commander** | Anthropic | Drives the response; executes actions **only** after explicit sign-offs. |
| _Facilitator_ | (watchdog) | Silent observer that nudges the expected next actor if the incident stalls. |

Different frameworks, two accounts — a genuine test of **Band as an
interoperability layer**, not four copies of one agent.

## The scenario (demo: `INC-C`)

Ransomware hits the primary customer database (PII + financial data).

- **Threat Intel:** isolate and wipe now — it's spreading toward the domain controllers.
- **Compliance:** that host is forensic evidence under a **legal hold** — you can't destroy it. (GDPR Art. 33 starts a **live 72h T-minus countdown**.)

Neither agent is wrong → a genuine deadlock. So the Commander **escalates to a
human CISO**, who rules in a single message. Evidence is preserved first, the
wipe is then authorized, and **every destructive action is gated** behind a
sign-off or a human ruling.

The other incidents exercise the rest of the protocol: `INC-A` (a commodity
trojan) resolves **autonomously**, no human needed; `INC-B` is a false positive
that Triage closes without recruiting anyone.

## How it works

- One Band room; agents speak only via `@mention` messages.
- A structured protocol: `BRIEF → FINDING → QUESTION → SIGNOFF_REQUEST → SIGNOFF / VETO → ESCALATION → ACTION → RESOLUTION`.
- Asymmetric knowledge — only Threat Intel queries IOCs, only Compliance reasons over data classes/regulations — **forces** the agents to talk.
- Domain tools read from a deterministic mock environment (`shared/mock_env/`).
- `scripts/export_report.py` turns the finished room into a structured incident
  report: decision timeline, the human's ruling, the regulatory clock, and every
  action with its reason.

## Quickstart (Windows / PowerShell)

```powershell
# 1. Set up the environment (Python 3.11+; developed on 3.14)
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .

# 2. Configure credentials
copy .env.example .env                          # AIML / OpenAI + Anthropic keys
copy agent_config.yaml.example agent_config.yaml # Band agent UUIDs + API keys

# 3. Launch all four agents (headless) and wait for the green light
powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1 -Headless
#   -Check  : "are all 4 connected?"   -Stop : stop them   -Force : relaunch

# 4. Fire an incident
.venv\Scripts\python.exe -m injector.inject_alert INC-C
#   On Band's free tier, room creation via the human API is blocked, so the
#   injector prints the alert for you to PASTE into a fresh room @-mentioning
#   Triage. INC-C will run to the human-escalation pause; post your CISO ruling
#   @mentioning the Commander to let it finish.

# 5. Export the audit trail
.venv\Scripts\python.exe scripts\export_report.py --room <room-id>
```

A `Dockerfile` + `docker-compose.yml` are also provided for booting the agents in
containers.

## Project layout

```
agents/        triage · threat_intel · compliance · commander (main.py + tools.py + prompt.md each)
shared/        protocol, config, mock_env data, reg_clock, band logging, sdk_patches
injector/      inject_alert.py — fires a scripted alert at Triage
scripts/       run_all.ps1 (launcher) · incident_driver.py (Facilitator watchdog) ·
               export_report.py · export_transcript.py · clean_rooms.py
tests/         pytest suite (77 passing) — pure-function coverage, no network
docs/          recovery.md (crash/restart behavior) and more
demo/          video narration script + presentation text
```

## Tests

```powershell
.venv\Scripts\python.exe -m pytest tests/ -q     # 77 passing (upstream baseline)
```

On the `cyberrescue-ai` branch the offline suite is far larger; current results
are in [docs/ca3/08-test-verification-report.md](docs/ca3/08-test-verification-report.md).

## Notes & known limits

- **Band free tier** blocks the human room-creation API, so the injector falls
  back to a manual paste; Compliance lives on a second account as external counsel.
- The LangGraph/Pydantic-AI agents run gpt-4o via the OpenAI-compatible **AIML**
  endpoint; the Commander uses **Anthropic** (`docs/recovery.md` covers failure
  modes and recovery — agents rejoin rooms and replay backlog on restart).
- See [`shared/protocol.md`](./shared/protocol.md) for the full collaboration
  protocol and [`warroom-implementation-plan.md`](./warroom-implementation-plan.md)
  for the build plan.
