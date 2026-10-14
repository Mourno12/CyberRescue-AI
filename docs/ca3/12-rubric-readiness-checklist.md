# 12 — CA3 rubric readiness checklist

Ratings: **Ready**, **Partial** (usable, with a gap), **Blocked** (needs
something external), **Not started**. This assessment is honest as of
2026-10-11.

| Criterion | Rating | Evidence | What is missing |
|---|---|---|---|
| **Architecture** | Ready | [03](03-architecture-diagram.md) diagram; [02](02-system-design.md) components and trust boundaries; LLM-vs-code table | — |
| **Design** | Ready | policy-v2 rules, single-action authority, human-in-the-loop approvals, append-only audit plus anchors; [04](04-agent-io-definitions.md) I/O contracts | — (live sync implemented; live behaviour NOT VERIFIED) |
| **Live demo — offline pipeline** | Ready | `scripts\demo_offline.ps1`, verified twice (exit 0); [06](06-offline-demo-runbook.md) | — |
| **Live demo — four LLM agents** | **Blocked** | runbook [07](07-live-demo-runbook.md), preflight (identities, CISO, accounts), runtime handles, `live sync`, launcher fixes | Band accounts plus 5 agent keys and the CISO identity, LLM keys, approval for paid usage; then a real run, capture and §8 checks |
| **Presentation** | Partial | [10](10-demo-narration.md) narration (offline) | Slides and screenshots (`case.html`, `plan.html`, terminal); live segment only after a verified run |
| **Documentation** | Ready | this package (12 docs), phase docs `docs/cyberrescue/phase*.md`, README updated | Refresh after any live run |
| **Engineering quality** | Ready | full offline suite passes (see [08](08-test-verification-report.md)); deterministic evaluation; fail-closed gate; secret hygiene checks | Live behaviour of sync and handles unverified |
| **Testing** | Ready (offline) / Blocked (live) | unit, security, integration tests; opt-in `tests_live/` | Live tests need credentials and a room id |
| **Individual contribution** | Partial | [11](11-contribution-attribution.md) (git-derived facts and upstream disclosure) | Your own written statement; disclosure of AI assistance per policy |
| **Dashboard** | Not started (deliberate) | — | Gated on a working live run; offline HTML exports (`case.html`, `plan.html`) exist |

## Before the presentation

1. Run `scripts\demo_offline.ps1` once on the presentation machine.
2. Take screenshots of steps 6b (wipe refused), 8 (anchor OK) and 9 (tamper
   detected), and of `case.html`.
3. Decide on live: supply the prerequisites in [07 §1](07-live-demo-runbook.md#1-external-prerequisites-you-must-supply-these),
   or present the four-agent design with the gate shown through the real
   Commander tool callables (offline tests), stated as such.
