# WarRoom — Implementation Plan
### Multi-Agent Cybersecurity Incident Response through Band
**Track 3: Regulated & High-Stakes Workflows · Band of Agents Hackathon**

---

## 0. What you are building (one paragraph)

A security alert fires. A Triage agent (LangGraph) classifies it, creates a Band war room, and recruits three specialists into it: a Threat Intel agent (OpenAI SDK), a Compliance Officer agent (Pydantic AI) with veto power and ownership of the regulatory clock, and an Incident Commander (Anthropic/Claude) that synthesizes findings and must collect explicit @mentioned sign-offs before executing any response action. When Threat Intel ("isolate and wipe the host now") and Compliance ("veto — that host is forensic evidence and PII exposure starts our 72-hour notification clock") deadlock, the Commander escalates by adding the human CISO to the room, who rules in one message. The system then executes the approved actions (mocked) and exports the full room transcript as a timestamped, regulator-ready incident report. Four agents, four frameworks, one human, one Band room — and the audit trail is the conversation itself.

---

## 1. Architecture overview

```
                       ┌──────────────────────────────────────────┐
   [alert_injector.py] │            BAND PLATFORM                 │
        │              │                                          │
        ▼              │   Room: warroom-INC-2026-0042            │
  ┌───────────┐  WS/   │  ┌────────────────────────────────────┐  │
  │  TRIAGE   │◄─REST─►│  │ @Triage @ThreatIntel @Compliance   │  │
  │ LangGraph │        │  │ @Commander @CISO(human)            │  │
  └───────────┘        │  │                                    │  │
  ┌───────────┐        │  │  All coordination = @mention       │  │
  │THREAT INTEL│◄─────►│  │  messages in this room             │  │
  │ OpenAI SDK│        │  └────────────────────────────────────┘  │
  └───────────┘        └──────────────────────────────────────────┘
  ┌───────────┐                          ▲
  │COMPLIANCE │◄────────────────────────►│   (Compliance runs under a
  │Pydantic AI│   2nd Band account       │    second account → demos
  └───────────┘   via contacts flow      │    cross-org contacts flow)
  ┌───────────┐                          │
  │ COMMANDER │◄────────────────────────►┘
  │ Anthropic │
  └───────────┘
        │
        ▼
  [report_exporter.py] → incident-report-INC-2026-0042.md (+ optional PDF)
```

Key platform facts the design relies on (verify in Phase 0):
- Remote agents connect via the Band SDK: REST out, WebSocket in. Install: `uv add "band-sdk[langgraph]"` (or `[crewai]`, `[anthropic]`, `[pydantic-ai]`, `[openai]`...). Import from `thenvoi`.
- Each agent = registered on app.band.ai as an **External Agent** → gets an **Agent UUID + API key** (key shown once — save it immediately).
- Messages route by **@mention only**. Non-mentioned agents see nothing. Therefore: every message that needs an audience must @mention that audience explicitly. The protocol in Phase 4 is written around this.
- Agents automatically receive **platform tools**: `thenvoi_send_message`, `thenvoi_send_event`, `thenvoi_add_participant`, `thenvoi_remove_participant`, `thenvoi_get_participants`, `thenvoi_lookup_peers`, `thenvoi_create_chatroom`. The LLM decides when to call them — your system prompts must instruct it when.

---

## 2. Repository layout

```
warroom/
├── README.md                      # judges read this — write it well (Phase 8)
├── docker-compose.yml             # one service per agent + injector + dashboard
├── .env.example                   # LLM keys (OpenAI, Anthropic) — never commit real keys
├── agent_config.yaml.example      # Band agent UUIDs + API keys per agent
├── shared/
│   ├── schemas.py                 # pydantic models: Finding, Vote, Escalation, ActionRequest
│   ├── protocol.md                # the collaboration protocol (single source of truth)
│   └── mock_env/
│       ├── alerts/                # 3 scripted incident JSONs
│       ├── ioc_db.json            # mock threat-intel indicators
│       ├── asset_inventory.json   # hosts, data classes (PII flags), owners
│       └── reg_rules.json         # GDPR 72h, SEC 4-business-day, HIPAA rules
├── agents/
│   ├── triage/        (LangGraph)    main.py, prompt.md, tools.py
│   ├── threat_intel/  (OpenAI)       main.py, prompt.md, tools.py
│   ├── compliance/    (Pydantic AI)  main.py, prompt.md, tools.py
│   └── commander/     (Anthropic)    main.py, prompt.md, tools.py
├── injector/
│   └── inject_alert.py            # fires an alert at the Triage agent
├── exporter/
│   └── export_report.py           # room history → incident report artifact
└── demo/
    ├── demo_script.md             # the 3-minute run-of-show
    └── backup_video.mp4
```

Design rule: **all domain tools are mocks reading from `shared/mock_env/`**. Judges score the collaboration layer, not your forensics. An "isolate_host" tool that writes a log line is enough.

---

## 3. The phases

> Phases are dependency-ordered. Each has an explicit exit criterion — do not start the next phase until it passes. Phases 3 and 5 can be parallelized across teammates once Phase 2 is done.

---

### PHASE 0 — Platform verification (de-risk everything else)

The single highest-leverage phase. Every assumption gets confirmed against the real platform before any agent code exists.

1. Create the primary Band account; create a **second account** (different email) for the Compliance agent's "external counsel" org.
2. Read `docs.band.ai/llms-full.txt` end to end. Also read: Chat Rooms & Routing, Agents, Contacts & Discovery, the SDK tutorials for your four adapters, and the API Reference (room history / messages endpoints — the exporter depends on these).
3. Register one throwaway External Agent, run the quickstart `my_agent.py` verbatim, talk to it in a room from the web UI.
4. **Answer these questions in writing** (drop answers into `shared/protocol.md`):
   - Exact @mention semantics: can one message mention multiple agents? Does the sender see replies it isn't mentioned in? What does a human in the room see (everything, or only their mentions)?
   - Can an agent create a room and add participants via `thenvoi_create_chatroom` + `thenvoi_add_participant`? Can it add a *human* user? Can it add an agent from another account once contacts are approved?
   - How does the contacts request/approve flow work between your two accounts?
   - Which REST endpoint returns full room history (for the exporter), and what's in a message object (sender, timestamp, mentions, body)?
   - Rate limits / message size limits on the free tier (free tier reportedly retains data only 24h — confirm; if true, export transcripts immediately after each run and never rely on old rooms for the demo).
5. Decide fallbacks now for anything unsupported (e.g., if agents can't add humans to rooms, the human pre-joins and the Commander @mentions them; if cross-account adding fails, run Compliance on the main account and cut the contacts demo).

**Exit criterion:** quickstart agent responds in a room; every question above has a verified written answer; fallback decisions recorded.

---

### PHASE 1 — Walking skeleton: two agents converse through Band

Prove agent↔agent @mention dialogue end-to-end before building anything real.

1. Scaffold the repo (layout above). One `uv` project per agent directory; shared package installed editable.
2. Stand up **Triage (LangGraph)** and **Commander (Anthropic adapter)** as minimal agents with placeholder prompts.
3. Script the smoke test: human posts `@Triage ping the commander`; Triage must use `thenvoi_send_message` to @mention Commander; Commander replies @mentioning Triage; three round trips without human input.
4. Add structured logging in every agent process (`[AGENT] received / sent / tool-called`) — these terminal windows are part of your demo's cross-framework proof.
5. Write `docker-compose.yml` now, while there are only two services. `docker compose up` must bring the skeleton up cold.

**Exit criterion:** two agents on two different frameworks complete a multi-turn @mention conversation in one Band room, launched via docker compose.

---

### PHASE 2 — Full roster: four frameworks connected

1. Add **Threat Intel (OpenAI adapter)** and **Compliance (Pydantic AI adapter)**, each registered as its own External Agent with its own UUID/key.
2. Register Compliance under the **second account**; complete the contact request/approve flow so the main account's agents can add it to rooms. (If Phase 0 found this brittle: fallback, same account, move on.)
3. Group smoke test: human posts one kickoff message; each agent, when mentioned, replies and @mentions the next — a full round-robin across all four.
4. Pin model choices per agent (e.g., gpt-4o for Triage/Intel, Claude for Commander) and confirm each adapter's tool-calling works with its model.

**Exit criterion:** four agents on four frameworks, all in one room, completing a round-robin; Compliance participates from the second account.

---

### PHASE 3 — Domain layer: mock environment + agent tools

Now make the agents *security* agents. Pure Python, no Band dependency — parallelizable.

1. **Mock data** (`shared/mock_env/`):
   - `ioc_db.json`: ~15 indicators (hashes, IPs, domains) with threat actor, malware family, confidence.
   - `asset_inventory.json`: ~8 hosts with role, criticality, and `data_classes` (mark one server `["customer_pii"]` — the demo hinges on it).
   - `reg_rules.json`: machine-readable rules — GDPR: PII breach → notify within 72h; SEC: material incident → 8-K within 4 business days; HIPAA: PHI rules. Each with trigger conditions.
   - Three alert files: `INC-A-malware-clean.json` (clean containment, no PII), `INC-B-false-positive.json` (closed at triage — shows the system doesn't over-escalate), `INC-C-ransomware-pii.json` (**the contested demo incident**: ransomware indicators on the PII server).
2. **Per-agent tools** (each agent gets only its own — asymmetric knowledge is what forces them to talk):
   - Triage: `classify_alert`, `lookup_asset`
   - Threat Intel: `lookup_ioc`, `assess_spread_risk`
   - Compliance: `check_regulatory_triggers`, `start_notification_clock`, `evidence_preservation_requirements`
   - Commander: `isolate_host`, `preserve_disk_image`, `wipe_host`, `notify_stakeholders` — every action tool just appends to `actions_log.jsonl` with a timestamp; that log is "execution."
3. Unit-test tools standalone, then wire into each adapter (`additional_tools=[...]` pattern) and verify each agent calls its tools when asked in-room.

**Exit criterion:** each agent answers a domain question in-room using its own tools; all three alert files load; action tools write to the log.

---

### PHASE 4 — The collaboration protocol (the heart of the project)

This phase is prompt engineering + message schema design. Budget the most iteration time here — it's what judges are scoring.

1. **Message schema** (`shared/schemas.py`, mirrored in every prompt): agents post human-readable text followed by a fenced JSON block:
   ```json
   {"type": "FINDING|QUESTION|SIGNOFF_REQUEST|SIGNOFF|VETO|ESCALATION|ACTION|RESOLUTION",
    "incident": "INC-...", "severity": "...", "summary": "...",
    "evidence": [...], "deadline_utc": null, "decision": null}
   ```
   Human-readable for the live demo; JSON for the exporter. The schema makes "structured context sharing" undeniable.
2. **Protocol rules** (encode in `shared/protocol.md`, then into each `prompt.md`):
   - **Kickoff:** Triage receives the alert → classifies → calls `thenvoi_create_chatroom` (or uses the prepared room per Phase 0 findings) → `thenvoi_lookup_peers` + `thenvoi_add_participant` to **recruit** Intel, Compliance, Commander → posts the incident brief @mentioning all three. Recruitment must be reasoned ("PII asset involved → adding Compliance"), not hardcoded.
   - **Parallel analysis:** Intel and Compliance investigate with their tools and post FINDINGs @mentioning Commander (+ each other when relevant). Since non-mentioned agents see nothing, the prompts must say *exactly who to @mention on every message type*.
   - **Cross-examination:** each specialist must ask at least one substantive QUESTION of another specialist when information is missing (e.g., Intel asks Compliance whether the host's data class changes containment options). This is the visible agent↔agent collaboration.
   - **Sign-off:** Commander drafts a response plan and posts SIGNOFF_REQUEST @mentioning both specialists. Plan executes only after SIGNOFF from **both**.
   - **Veto:** Compliance may post VETO with a cited regulation. A veto blocks execution unconditionally.
   - **Escalation:** if Commander holds a VETO and a conflicting SIGNOFF, or no consensus after 2 negotiation rounds, it posts ESCALATION @mentioning the human CISO with a ≤5-line neutral summary of both positions and a concrete decision request. The CISO's reply is final; Commander executes accordingly and posts RESOLUTION.
   - **Anti-loop guards:** max 2 negotiation rounds before forced escalation; every agent instructed never to re-litigate after RESOLUTION; Commander is the only agent allowed to call action tools.
3. **The scripted conflict (INC-C):** verify the data forces it — IOC db says active ransomware, lateral movement risk high → Intel recommends immediate isolate+wipe; asset inventory marks the host PII → Compliance's tools return "GDPR clock + evidence preservation required" → VETO on wipe. The conflict emerges from the agents' own tools, not from a hardcoded script — say this out loud in the demo, it's the difference between theater and a system.
4. Run INC-C end-to-end repeatedly (human playing CISO). Tune prompts until: recruitment is reasoned, ≥2 cross-examination exchanges occur, the veto fires, escalation summary is crisp, and the flow completes in ≤ ~15 room messages. Then run INC-A (must complete with sign-offs, **no** escalation) and INC-B (Triage closes it without recruiting anyone) to prove proportionality.

**Exit criterion:** all three incidents run end-to-end with correct, distinct behavior; INC-C reliably produces cross-examination → veto → escalation → human ruling → resolution.

---

### PHASE 5 — Human-in-the-loop, hardened

1. Confirm the CISO experience in Band's UI: they're in the room (added by the Commander if Phase 0 confirmed that works; pre-joined otherwise), get the escalation @mention, reply in one message.
2. Make the Commander robust to messy human input — "do both, isolate but image the disk first" must parse into an action sequence; an ambiguous reply must trigger exactly one clarifying question, not a loop.
3. Add the **regulatory clock** drama: when Compliance's `check_regulatory_triggers` fires, it posts the deadline and includes "T-minus" reminders in subsequent messages. Cheap to build, lands hard in the demo.
4. Failure modes: kill one agent mid-incident and restart it — document what recovers (executions are room-scoped; Phase 0 notes apply). Decide and document demo recovery behavior.

**Exit criterion:** non-team member playing CISO can resolve INC-C with one or two natural-language messages; clock messaging appears; agent restart doesn't strand the incident.

---

### PHASE 6 — Audit trail exporter (the "real-world value" artifact)

1. `export_report.py`: pull full room history via the REST endpoint verified in Phase 0 → parse JSON blocks → generate `incident-report-{id}.md`:
   - Executive summary (incident, severity, outcome)
   - **Decision timeline**: every FINDING/VETO/ESCALATION/RESOLUTION with timestamp, actor, and evidence
   - Regulatory section: triggered obligations, clock start, deadline, notification status
   - Actions taken (from `actions_log.jsonl`), human decisions highlighted
   - Appendix: verbatim transcript
2. Closing line on the report and in your pitch: *"This report was not written after the incident. It is the incident — generated from the room where the decisions were made."*
3. Optional polish: render to PDF; have the Commander auto-trigger export on RESOLUTION so the artifact appears live during the demo.

**Exit criterion:** one command (or auto-trigger) turns a finished room into a clean, timestamped incident report.

---

### PHASE 7 — Demo engineering

1. Write `demo/demo_script.md` — the 3-minute run-of-show:
   - 0:00 problem framing (2 sentences: SOC overload + regulatory deadlines)
   - 0:20 fire `inject_alert.py INC-C` — screen shows the Band room **plus a terminal grid with four visibly different framework logs** (the cross-framework proof)
   - 0:40 narrate recruitment: "Triage decided who to hire — nothing is hardcoded"
   - 1:10 findings + cross-examination land
   - 1:40 **the moment**: Intel says wipe, Compliance vetoes citing GDPR, clock starts
   - 2:10 escalation → human CISO (a teammate, or a judge if you're brave) rules in one message
   - 2:30 resolution executes; incident report appears; close on the audit-trail line
2. Rehearse ≥5 full runs. Note every flake and fix or script around it. Pre-create the contacts approval and any other one-time setup so nothing administrative happens live.
3. **Record the backup video** of a clean run. Non-negotiable — live LLM demos fail at the worst moment.
4. Prepare INC-A as the "skeptical judge" encore: proof the system doesn't escalate everything to a human.

**Exit criterion:** three consecutive clean rehearsals; backup video recorded; a teammate can run the demo without you.

---

### PHASE 8 — Submission package

1. **README.md**: what it is (3 sentences), architecture diagram, the protocol summary table (message types → who @mentions whom), quickstart (`docker compose up` + inject), and an explicit "How Band is used" section mapping each platform capability (rooms, @mention routing, recruitment via `thenvoi_add_participant`, cross-account contacts, human participant, history API) to where it appears in the workflow — make the judges' checklist trivially easy to tick.
2. Sample artifacts committed: one exported incident report + one transcript.
3. Pitch deck (≤6 slides): problem → why multi-agent is *necessary* here → live demo → the audit-trail artifact → real-world value (SOC staffing crisis, GDPR/SEC deadlines, "the report is a side effect of the work") → what's next (real SIEM webhook ingestion, more specialist agents recruited on demand).
4. Submission text per the hackathon's required format; double-check the "minimum 3 agents collaborating through Band" framing is stated explicitly (you have 4 + a human).

**Exit criterion:** a judge who never saw the demo can clone, run, and understand the project from the README alone.

---

## 4. Phase dependency map

```
P0 ──► P1 ──► P2 ──┬──► P4 ──► P5 ──► P7 ──► P8
                   │     ▲
                   └► P3 ┘        P6 (after P4; parallel with P5)
```
With two people: one takes P3 (domain/mocks) while the other does P2; both converge on P4. P6 can be built by whoever is free once the message schema (P4.1) is frozen.

## 5. Risk register

| Risk | Mitigation |
|---|---|
| A platform-tool assumption is wrong (room creation, adding humans, cross-account) | Phase 0 verifies all of them before code; fallbacks pre-decided |
| Free-tier 24h data retention wipes demo rooms | Export transcripts after every run; demo always uses a fresh injected incident |
| Agents loop or talk past each other | Hard caps (2 negotiation rounds), single action-authority (Commander), forced-escalation rule |
| One adapter is broken/immature | Phase 2 surfaces it early; any agent can fall back to the LangGraph or Anthropic adapter — 3 frameworks still beats the requirement |
| Live demo flake | 5+ rehearsals, scripted incident, backup video |
| The conflict doesn't fire naturally | INC-C's data is *constructed* so both agents' own tools force opposing recommendations; tune data, not just prompts |

## 6. Definition of done

- [ ] 4 agents, 4 frameworks, in one Band room, plus a human participant
- [ ] Recruitment, findings, cross-examination, sign-off, veto, escalation, resolution — all as @mention messages through Band, no side channels
- [ ] Compliance agent participates cross-account via contacts (or documented fallback)
- [ ] Three incidents demonstrate proportional behavior (close / approve / contest-and-escalate)
- [ ] One-command incident report export from room history
- [ ] `docker compose up` cold start, README, deck, backup video, submission filed
