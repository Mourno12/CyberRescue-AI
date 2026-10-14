# 01 — Project synopsis

## Problem

Security incident response mixes fast technical containment with slow,
high-stakes obligations: preserving evidence, meeting regulatory deadlines such
as the GDPR Art. 33 72-hour window, and getting human sign-off for destructive
actions. An AI system that only "decides and acts" is unsafe here. Every action
must be justified by evidence, authorized under an explicit policy, approved by a
human where the stakes require it, and recorded in a log that can be checked
later.

## Approach

CyberRescue-AI combines two layers:

1. **A four-agent LLM team (inherited from the upstream WarRoom project).**
   Triage, Threat Intelligence, Compliance and an Incident Commander coordinate in
   one Band chat room using @mention messages that carry a structured JSON protocol
   (`BRIEF → FINDING → QUESTION → SIGNOFF_REQUEST → SIGNOFF/VETO → ESCALATION →
   ACTION → RESOLUTION`). The agents run on three frameworks (LangGraph, Pydantic AI
   and Anthropic) across two Band accounts. A human CISO decides deadlocks.

2. **CyberRescue Core and a deterministic pipeline (built on the
   `cyberrescue-ai` branch).** This is a SQLite system of record with:
   - hash-chained audit logs;
   - evidence ingestion of SYNTHETIC telemetry;
   - rule-based detection and correlation;
   - read-only investigation (timeline, scope, gaps);
   - advisory response planning with MITRE ATT&CK mapping;
   - a deterministic policy engine;
   - a SIMULATED executor with accountability records;
   - keyed external audit anchors.

   A hook in the Commander's action tools asks the Core before every action. In
   `enforce` mode the Commander acts only when the Core returns ALLOW.

## Design principle

The LLM layer can propose. Only deterministic, audited code can authorize. A
message saying "the CISO approved" grants nothing. Approvals come only from
`CoreService.grant_approval` called by a registered human approver. Sign-offs
count only from rostered specialist identities taken from transport metadata,
never from message text.

## Current state (2026-10-11)

| Area | State |
|---|---|
| Offline pipeline (detection → audit anchoring) | **VERIFIED (offline).** Scenario A: 10 findings, 58/58 malicious events, 8-step plan with 3 decision points, 8/8 simulated executions recorded and verified |
| Offline test suite | **VERIFIED.** Full suite passes; see [08](08-test-verification-report.md) |
| Live four-agent collaboration | **UNVERIFIED.** No `agent_config.yaml`, `.env` or `.env.local` exists in this checkout, so no live run was made during this work |
| Live sign-offs/vetoes reaching Core authorization | `live sync` implemented and offline-tested with MOCKED Band; **live NOT VERIFIED** ([02 §6](02-system-design.md#6-live-integration-gap-and-how-it-is-addressed)) |
| Agent identities | Handles configured in `agent_config.yaml` and rendered into the unchanged upstream prompts at load time |
| Dashboard | Not built. It was gated on a working live run, which has not happened |
