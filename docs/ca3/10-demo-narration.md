# 10 — Demo narration (about 2.5 minutes)

This script narrates the **offline** demo (`scripts\demo_offline.ps1 -Pause`).
Every number below was observed on 2026-10-11. If a live run is later verified,
swap in §B; do not claim live collaboration otherwise.

## A. Offline narration

**[0:00 — title]**
"CyberRescue-AI is an incident-response system where AI can *propose* but only
audited, deterministic code can *authorize*. It extends WarRoom, an open-source
four-agent design, with a Core that enforces policy and keeps a tamper-evident
record. What you'll see now runs fully offline on synthetic data, and every
action is simulated."

**[0:15 — steps 1–3: evidence and detection]**
"A ransomware alert opens incident INC-C on the customer database. Because that
host holds personal data, the Core places a legal hold *by rule*, not by an AI
judgement. 225 synthetic telemetry events become hashed evidence. Deterministic
detection produces 10 findings: execution, credential abuse, lateral movement,
command-and-control to 185.220.101.47, shadow-copy deletion and mass
encryption. It also flags a partial exfiltration pattern as only an observation,
because the evidence doesn't support more."

**[0:45 — step 4: investigation]**
"The investigation is read-only. One host compromised, one accessed, one
targeted. It also lists what we *can't* see: for example, whether code ran on
srv-app-01 after the attacker logged in. Gaps are reported, not hidden."

**[1:05 — steps 5–6: plan and authorization]**
"The planner proposes eight steps and three decisions that belong to a human:
notify the regulator, restore from backup, and wipe. Now the Commander requests
each step. Five are allowed. Three containment steps on the critical database
come back REQUIRE_APPROVAL. And wiping the evidence host? Refused: tier-3 rule,
plus legal hold. The CISO approves only the three flagged steps, and the retries
now pass, each one consuming its single-use approval."

**[1:40 — step 7: simulated execution]**
"Only authorized steps are simulated, and each is recorded in the Core against
its exact request: eight records, zero refused, verified."

**[1:55 — steps 8–9: audit]**
"Every event is hash-chained: 442 in this incident. We sign the chain heads with
an external key. Then we play attacker: on a copy, we edit one audit record
directly in SQLite. Verification catches it, both the hash mismatch at sequence
427 and the anchor mismatch."

**[2:20 — close]**
"The evaluation scores all of this against ground truth: 58 of 58 malicious
events cited, 8 of 8 executions accounted for. The four LLM agents use this same
gate in enforce mode. Their live collaboration is the next step, and our runbook
documents exactly what's needed to verify it."

## B. Live segment (use only after a verified live run)

"In the Band room: Triage classifies the alert and recruits the team. Threat
Intel says wipe now; Compliance vetoes the wipe under the legal hold. The
Commander can't satisfy both, so it escalates to the human CISO. Every action the
Commander attempts goes through the Core gate, and you can see the ALLOW and DENY
decisions in the gate log, linked to the audit chain."
