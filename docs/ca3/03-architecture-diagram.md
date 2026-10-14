# 03 — Architecture diagram

Mermaid source (renders on GitHub and in VS Code with a Mermaid extension).
Solid arrows are messages or calls. Dashed arrows are records written to the Core.

```mermaid
flowchart LR
  subgraph BAND["Band chat room (one per incident) — @mention routing"]
    direction TB
    H["Human CISO<br/>(Band user)"]
    T["Triage<br/>LangGraph · gpt-4o"]
    TI["Threat Intel<br/>LangGraph · gpt-4o"]
    C["Compliance<br/>Pydantic AI · gpt-4o<br/>(2nd Band account)"]
    CMD["Commander<br/>Anthropic · Claude"]
    F["Facilitator<br/>watchdog, no LLM"]
  end

  ALERT["Alert (injector prints it;<br/>pasted into intake room)"] --> T
  T -- "BRIEF (recruits)" --> TI & C & CMD
  TI -- "FINDING / QUESTION" --> CMD
  C -- "FINDING / QUESTION" --> CMD
  TI <-- "QUESTION" --> C
  CMD -- "SIGNOFF_REQUEST" --> TI & C
  TI -- "SIGNOFF" --> CMD
  C -- "SIGNOFF / VETO" --> CMD
  CMD -- "ESCALATION" --> H
  H -- "ruling (text)" --> CMD
  F -. "nudge if idle" .-> CMD

  subgraph TOOLS["Deterministic domain tools (shared/mock_env)"]
    TT["classify_alert · lookup_asset"]
    TIT["lookup_ioc · assess_spread_risk · analyze_incident"]
    CT["check_regulatory_triggers · evidence_preservation_requirements<br/>start_notification_clock · regulatory_clock_status"]
    AT["isolate_host · preserve_disk_image<br/>wipe_host · notify_stakeholders"]
  end
  T --- TT
  TI --- TIT
  C --- CT
  CMD -- "action tool call" --> AT

  subgraph CORE["CyberRescue Core (SQLite, deterministic)"]
    GATE["Commander gate<br/>shadow | enforce"]
    POL["Policy engine policy-v2<br/>P0–P9"]
    ING["ProtocolIngestor<br/>(roster-based identity)"]
    AUD[("Hash-chained audit log<br/>+ approvals · sign-offs · vetoes · holds")]
    ANC["Keyed external anchor<br/>(HMAC, key outside repo)"]
  end
  AT -- "check_commander_action()" --> GATE
  GATE --> POL
  POL -. "GATE_DECISION" .-> AUD
  GATE -- "ALLOW → actions_log.jsonl<br/>DENY → blocked_by_policy" --> AT
  OP["Operator CLI<br/>core approve (human)"] -. "approval" .-> AUD
  EXP["live sync / export-band (read-only)<br/>→ import_band_context"] --> ING
  BAND -. "room history" .-> EXP
  ING -. "SIGNOFF / VETO / ESCALATION / ruling" .-> AUD
  AUD --> ANC

  subgraph OFF["Offline deterministic pipeline (no LLM)"]
    direction TB
    TEL["SYNTHETIC telemetry"] --> EV["Evidence (SHA-256)"] --> DET["Detection + correlation"]
    DET --> INV["Investigation case (read-only)"] --> PLAN["Response plan (advisory)"]
    PLAN -- "request_action per step" --> POL
    POL --> EXE["SIMULATED executor"]
  end
  EXE -. "execution_records" .-> AUD
```

## Plain-text fallback

```text
 Alert ──► Triage ──BRIEF──► Threat Intel ─┐   (all messages in ONE Band room,
                     │                     ├─FINDING/QUESTION──► Commander
                     └─────► Compliance ───┘                       │
          Commander ──SIGNOFF_REQUEST──► specialists ──SIGNOFF/VETO──┘
          Commander ──ESCALATION──► Human CISO ──ruling──► Commander
          Commander ──action tool──► Core gate ──► policy engine ──► ALLOW / DENY
                                                    │
 Band history ─(export-band, read-only)─(core import-band)─► ingestor ─► audit log ─► anchor
 SYNTHETIC telemetry ─► evidence ─► detection ─► investigation ─► plan ─► requests ─► SIMULATED executor
```

## Status of each arrow

| Arrow | Status |
|---|---|
| Agent ↔ agent messages, tool calls | Code present (upstream). Live run **UNVERIFIED** in this work |
| Action tool → Core gate → policy | **VERIFIED offline** (tests call the real Commander tool callables) |
| Band history → export-band → import-band | **VERIFIED offline with MOCKED Band clients.** Live **UNVERIFIED** |
| Live messages → Core *during* the run | `live sync`: **VERIFIED offline with MOCKED Band clients**; live **NOT VERIFIED** ([02 §6](02-system-design.md#6-live-integration-gap-and-how-it-is-addressed)) |
| Offline pipeline end to end | **VERIFIED offline** (see [08](08-test-verification-report.md)) |
