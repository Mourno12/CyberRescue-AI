# 06 — Offline demo runbook

> **Scope statement.** The offline demo runs the deterministic CyberRescue
> pipeline on SYNTHETIC telemetry, with SIMULATED actions, and no LLM, Band or
> network. It shows detection, investigation, response planning, policy
> authorization with human approval, accountable simulated execution, and
> tamper-evident audit. **It does not demonstrate live LLM agent
> collaboration.** That is [07](07-live-demo-runbook.md).

## Prerequisites

- A clone of this repository with `.venv313` ([05](05-installation-user-guide.md)).
  `<repo-root>` below means the folder of that clone.
- No credentials or network access.
- About 1 minute for the evaluation and 1–2 minutes for the stepwise script.

## Option A — one command (ground-truth evaluation)

```powershell
cd <repo-root>
.\.venv313\Scripts\python.exe -m cyberrescue.evaluation run --scenario A --investigation --response --execution --accountability
```

Expected output: exit code **0**. These are the key lines observed on 2026-10-11:

```text
== Scenario A (INC-C-2026-0042) ground truth: true_positive, 225 events, 58 malicious
   findings: 10  unexpected: 0
   malicious evidence cited as support: 58/58  (incl. context: 58/58)
== Response plan PLAN-… (scenario A): 8 steps, 3 decision points, 3 tasks
== Simulated execution (scenario A) - SIMULATION ONLY
   commander_only   succeeded 4, blocked_authorization 1, blocked_legal_hold 2, blocked_human_decision 1, blocked_dependency 3
   with_approvals   succeeded 8, blocked_legal_hold 2, blocked_human_decision 1
== Execution accountability (scenario A) - SIMULATION ONLY: 8 recorded, 0 refused, 0 on replay
   check records_match_simulated        match         expected='8/8' observed='8/8'
```

Plan and case IDs contain a timestamp-dependent hash, so they differ between
runs. Step IDs (`STEP-…`) were identical across runs.

## Option B — stepwise demo with artifacts (recommended for presenting)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo_offline.ps1 -Pause
```

The script creates `%TEMP%\cyberrescue-ca3-demo-<timestamp>\`, which is outside
the repository; the script refuses an output folder inside it. It uses a fresh
Core database and stops at the first unexpected exit code or policy outcome.

| Step | What to say | What appears (observed) |
|---|---|---|
| 0 | "The whole pipeline is scored against ground truth." | Option A output |
| 1 | "A fresh Core opens INC-C from the alert. The legal hold is placed by rule, not by an LLM." | `opened INC-C-2026-0042 (INC-C) on srv-db-01` |
| 2 | "225 synthetic telemetry events become hashed evidence." | `225 event(s) -> 225 evidence record(s) ingested` |
| 3 | **Detection**: deterministic rules plus correlation. | 10 findings incl. `CORR-001 multi_stage critical`, `RANSOM-001`, `IOC-002 … 185.220.101.47`; `DATA-001` stays an *observation* (partial exfil chain, not a finding) |
| 4 | **Investigation**: read-only scope and honest gaps. | scope `compromised srv-db-01 / accessed srv-app-01 / targeted srv-dc-01`; gaps G1, G4, G5 ("absence of observed evidence, not of activity"); `case.html` written |
| 5 | **Response plan**: advisory only, with policy previews. | 8 steps, 3 human decision points (`notify_regulator`, `restore_from_backup`, `wipe_host`); isolate/kill/quarantine on `srv-db-01` preview `REQUIRE_APPROVAL [P5]` |
| 6a | **Authorization**: the Commander requests every step. | 5 `ALLOW`, 3 `REQUIRE_APPROVAL` (P5: critical asset) |
| 6b | "Can it wipe the evidence host? No." | `REQUIRE_APPROVAL: wipe_host` with P6 (tier-3) and P8 (legal hold) |
| 6c–d | "A human CISO approves only the three flagged steps; the Commander retries." | three `approve …` lines, then three `ALLOW … used approval …` |
| 7 | **Simulated execution**, recorded and verified in the Core. | `recorded 8 simulated execution(s) in the Core (mode simulated); 0 refused`; `recorded run (8 Core execution record(s)) VERIFIED` |
| 8 | **Audit**: hash chains, plus an external keyed anchor. | `INC-C-2026-0042: OK (442 events)`; `anchored 2 chain(s)`; anchor verify `OK` |
| 9 | **Tamper test** on a copy: one audit payload is edited directly in SQLite. | `TAMPERED … seq 427: content hash mismatch`; anchor `MISMATCH`; both exit 1 as expected |

Files to open afterwards: `case.html`, `plan.html` and `transcript.txt` (the full
console log).

## Evidence to collect

- [ ] `transcript.txt` and the console capture of the stepwise run
- [ ] The exit code of the evaluation run (0)
- [ ] `case.html` and `plan.html` (screenshots for slides)
- [ ] `execution.json` and the `core show` output listing 8 simulated executions
- [ ] The anchor verify `OK` line and the tampered-copy `TAMPERED` / `MISMATCH` lines
- [ ] `git rev-parse --short HEAD` (the script prints it at the top)

Reference captures from 2026-10-11 are in
`%TEMP%\cyberrescue-ca3-evidence\` (`offline_eval_scenarioA.txt`,
`offline_demo_run2\`, `offline_demo_run2.console.txt`).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `running scripts is disabled on this system` | Use `powershell -ExecutionPolicy Bypass -File …` exactly as shown |
| `No repository Python found` | Create `.venv313` ([05](05-installation-user-guide.md)) or pass `-Python <path>` |
| `OutDir … already exists` | The script never overwrites evidence. Omit `-OutDir` or choose a new folder |
| `UNEXPECTED policy outcome` | Something changed in the policy or data. Read the lines above it, and do not present the run as successful |
| `ModuleNotFoundError: cyberrescue` | Run from the repository root, or reinstall with `pip install -e .` |
| Garbled characters in the console | Cosmetic. `transcript.txt` is UTF-8 |
