# CyberRescue-AI — CA3 submission package

Status labels used throughout this package:

| Label | Meaning |
|---|---|
| **VERIFIED (offline)** | Run on 2026-10-11 in this repository with `.venv313`; output captured. |
| **SYNTHETIC** | Generated test data or fixtures (telemetry, transcripts). Not real incidents. |
| **SIMULATED** | Response actions are recorded, never performed on a real system. |
| **MOCKED** | A test double replaces an external service (Band REST client, importer). |
| **UNVERIFIED (live)** | Needs real Band accounts and LLM keys. Not yet run as part of this work. |

| # | Document | What it covers |
|---|---|---|
| 01 | [Project synopsis](01-project-synopsis.md) | Problem, approach, and current state |
| 02 | [System design](02-system-design.md) | Components, trust boundaries, data flow |
| 03 | [Architecture diagram](03-architecture-diagram.md) | Agents, handoffs, tools, Core integration |
| 04 | [Agent I/O definitions](04-agent-io-definitions.md) | Inputs, tools, and outputs for each agent, with examples |
| 05 | [Installation and user guide](05-installation-user-guide.md) | Setup and every command |
| 06 | [Offline demo runbook](06-offline-demo-runbook.md) | The demo that works without credentials |
| 07 | [Live demo runbook](07-live-demo-runbook.md) | Prerequisites and steps for the real four-agent run |
| 08 | [Test and verification report](08-test-verification-report.md) | Actual test and evaluation results |
| 09 | [Limitations and security](09-limitations-security.md) | Known gaps, threat model, and what is not proven |
| 10 | [Demo narration](10-demo-narration.md) | A 2–3 minute script |
| 11 | [Contribution and attribution](11-contribution-attribution.md) | What came from upstream WarRoom and what is new |
| 12 | [Rubric readiness checklist](12-rubric-readiness-checklist.md) | Honest readiness against each CA3 criterion |

Captured evidence (outside the repository, not committed):
`%TEMP%\cyberrescue-ca3-evidence\` — see [08](08-test-verification-report.md#evidence-files).
