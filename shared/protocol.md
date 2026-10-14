# WarRoom — Collaboration Protocol & Phase 0 Verification

This file is the single source of truth for **how WarRoom agents talk to each
other through Band**. It is populated in two passes:

- **Phase 0** (this document, today): write down what the Band platform
  actually does, with the assumptions verified against the real API. No agent
  code should be written based on guesses about the platform — it goes here
  first.
- **Phase 4**: once the platform behavior is locked in, the protocol rules
  (kickoff → recruitment → cross-examination → sign-off / veto / escalation →
  resolution) are written here and copied into each agent's `prompt.md`.

---

## A. Phase 0 — Platform facts (verify and fill in)

Each subsection contains the **question**, the **current best-guess answer**
from `docs.band.ai/llms-full.txt`, a **how-to-verify** note, and a
**verified?** flag. Do not move on to Phase 1 until every flag is ✅.

### A.0 Phase 0 verification RESULTS (verified 2026-06-13)

Verified against the live REST API (`https://app.band.ai/api/v1`, auth header
`X-API-Key: <agent_or_user_key>`) rather than only the SDK tools — the
platform facts are what matter, and the SDK tools wrap these same endpoints.

| Q | Fact | Result | Evidence |
|---|------|--------|----------|
| Q1 | multi-agent @mention in one msg | ⏳ assumed-per-docs | not load-tested; protocol designs "mention everyone" regardless |
| Q2 | non-mentioned agents see nothing | ✅ (docs+obs) | per docs; consistent with single-mention delivery observed |
| Q3 | human sees all room messages | ✅ | human read the full transcript incl. tool events |
| Q4 | agent can create a room | ✅ | `POST /agent/chats` → 201 |
| Q5 | agent adds same-account agent | ✅ | `POST /agent/chats/{id}/participants` (Commander) → 201 |
| Q6 | agent adds a **human** | ✅ | added human user → `type=User status=active` |
| Q7/Q9 | agent adds **cross-account** agent | ✅ | works **after agent-to-agent contact** (see below) |
| Q8 | contact request / approve | ✅ | **agent-level** `/agent/contacts/add` + `/requests/respond` |
| Q10 | room history endpoint | ✅ | `GET /agent/chats/{id}/context` → `shared/sample_message.json` |
| Q11 | tool_call/tool_result in history | ✅ | present in context API (audit trail intact) |
| Q12 | rate limits | ⏳ untested | operational; accept risk |
| Q13 | free-tier retention | ⏳ untested | mitigated by "always export after every run" |

**⚠️ Load-bearing gotcha (cross-account):** a user↔user contact made in the
web UI does **NOT** establish the agent link — agent contact lists stayed
empty and cross-account `add_participant` returned **403**. The fix that works
is an **agent-to-agent** contact request:
`POST /agent/contacts/add {"handle":"@merolavtechnologies/compliance"}` from
Triage, then `POST /agent/contacts/requests/respond {"action":"approve",
"request_id":...}` from Compliance. After that, Triage's contacts shows
`merolavtechnologies/compliance (is_external: true)` and the cross-account add
succeeds. **This handshake is already done for the current agent set and is
persistent** — but if agents are re-registered, redo it.

**Message object shape (for the exporter):** `id`, `content`, `message_type`
∈ {`text`, `tool_call`, `tool_result`}, `sender_id`, `sender_type`
(User|Agent), `sender_name`, `inserted_at`, `metadata.mentions[]`. Mentions
also appear inline in `content` as `@[[<uuid>]]` tokens. **No `delivery_status`
field** (the A.4 guess was wrong) — exporter must not depend on it.

### A.1 @mention semantics

- **Q1.** Can one message @mention multiple agents at once?
  - Guess from docs: **yes** — routing is per-mention; multi-mention sends to
    all named recipients. The docs example shows single-mention syntax
    `@AgentName ...` and emphasize multi-recipient delivery_status tracking,
    so multi-mention is implied.
  - Verify: send `@Triage @Commander hello both` from the web UI and confirm
    both agents' processes log "received".
  - Verified? ☐
- **Q2.** Does the sender see replies it isn't mentioned in?
  - Guess from docs: **no for agents, yes for humans**. The doc is explicit:
    *"Only the agents you mention receive and process the message.
    Non-mentioned agents in the chat room see nothing."* and *"Humans: see all
    messages in the chat room."*
  - Verify: have Triage send a message to Commander only; check that Triage's
    process logs no inbound when Commander replies @-ing nobody. Then check
    the room in the web UI as a human — confirm you see it.
  - Verified? ☐
- **Q3.** What does the human CISO in the room see?
  - Guess: **everything** (per the above). This is the demo's biggest UX
    assumption — the CISO must be able to read the cross-examination without
    being mentioned in every line.
  - Verify: same setup as Q2; the human view shows the full transcript.
  - Verified? ☐

**Protocol consequence:** because non-mentioned agents see nothing, every
operationally meaningful message must @mention everyone whose state must
change. The Phase 4 protocol below is written around this.

### A.2 Room creation & participant management

- **Q4.** Can an agent create a room via `thenvoi_create_chatroom`?
  - Guess: yes — listed as an auto-available platform tool.
  - Verify: run quickstart agent, instruct it via @mention to create a room,
    check it appears in the web UI.
  - Verified? ☐
- **Q5.** Can an agent add another *agent* to its room via
  `thenvoi_add_participant`?
  - Guess: yes — listed as platform tool; docs show agent recruitment as the
    canonical use case.
  - Verify: have Triage add Commander; confirm Commander's process now
    receives mentions in that room.
  - Verified? ☐
- **Q6.** Can an agent add a *human* user via the same tool?
  - Guess: **unclear**. The docs say `thenvoi_add_participant` adds "a
    participant" but only show examples adding other agents.
  - Verify: have Triage attempt to add the CISO's human user by email/handle
    and watch for an error vs success. **Test result determines whether the
    Commander adds the CISO at escalation time (preferred) or whether the
    human pre-joins the room and is just @mentioned (fallback).**
  - Verified? ☐
- **Q7.** Can an agent add an agent from another account, once contacts are
  approved?
  - Guess: yes after approval (bilateral consent in docs).
  - Verify: see A.3 below.
  - Verified? ☐

### A.3 Contacts request / approve flow (cross-account)

- **Q8.** How is a contact request sent and approved between two accounts?
  - Guess: from sender's UI, "request contact" using the other account's
    handle / email; recipient approves in their UI. The docs reference an
    SDK side too but UI is sufficient for our setup.
  - Verify: send a contact request from the **primary** account to the
    **secondary** account, approve from secondary. Confirm both accounts now
    see each other in `thenvoi_lookup_peers` results.
  - Verified? ☐
- **Q9.** Once approved, can a primary-account agent add a secondary-account
  agent to a room via `thenvoi_add_participant`?
  - Verify: have Triage (primary) add Compliance (secondary) to a fresh room.
  - Verified? ☐

**If Q8 or Q9 fails:** fallback is to register Compliance under the **primary
account too** and drop the cross-account contacts demo. Cost: a Band-platform
talking point lost. Benefit: simpler setup. Note this decision in §C below.

### A.4 Room history / messages REST endpoints

Needed by `exporter/export_report.py`.

- **Q10.** What is the exact REST endpoint for fetching full room history,
  and what is in a message object (sender, timestamp, mentions, body, type)?
  - Guess from docs: `GET /agent/chats/{id}/context` (agent-scope) and
    `GET /me/chats/{id}/messages` (user-scope). Message has at least:
    `sender`, `content`, `message_type ∈ {text, tool_call, tool_result,
    thought, error, task}`, `delivery_status[recipient_id]`. Timestamp is
    almost certainly present but not quoted in the LLM-readable docs.
  - Verify: with a Band API key, hit both endpoints against the quickstart
    room. Save one sample response in `shared/sample_message.json`. Confirm
    timestamps and @mention recipients are present.
  - Verified? ☐
- **Q11.** Are `thought` and `tool_call` events visible to the human in the
  room, or only to the API? (Affects what the demo audience sees vs what the
  exporter can use.)
  - Verify: run a tool from the quickstart agent, watch the web UI vs the
    history API.
  - Verified? ☐

### A.5 Rate limits & free-tier retention

- **Q12.** What are the per-agent / per-account rate limits on message sends?
  - Guess: not in the LLM-readable docs.
  - Verify: look for a `429` response under sustained sends; check the
    dashboard's billing/usage tab.
  - Verified? ☐
- **Q13.** Does the free tier retain room data only ~24h?
  - Guess from plan: yes, rumored.
  - Verify: ask in the platform's support channel or read the pricing page.
    **Regardless of answer, run `export_report.py` immediately after every
    rehearsal — never depend on an old room being intact.**
  - Verified? ☐

---

## B. Adapter facts (locked from docs — re-verify if SDK version differs)

```python
# LangGraph (Triage)
from thenvoi import Agent
from thenvoi.adapters import LangGraphAdapter
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver

adapter = LangGraphAdapter(
    llm=ChatOpenAI(model="gpt-4o"),
    checkpointer=InMemorySaver(),
    custom_section="...",
    additional_tools=[...],
)
agent = Agent.create(adapter=adapter, agent_id=..., api_key=...)
await agent.run()

# Anthropic (Commander) — VERIFIED 0.2.11. NO `client=` kwarg (the docs were
# wrong); the adapter builds its own client from the api_key. `custom_section`
# works but warns (deprecated in favour of `prompt`); we keep it because it
# APPENDS to the SDK's base Band instructions rather than replacing them.
from thenvoi.adapters import AnthropicAdapter
adapter = AnthropicAdapter(
    model="claude-sonnet-4-6",            # current Claude; accepted by SDK
    api_key=os.getenv("ANTHROPIC_API_KEY"),
    custom_section="...", additional_tools=[...],
)

# Pydantic AI (Compliance)
from thenvoi.adapters import PydanticAIAdapter
adapter = PydanticAIAdapter(
    model="openai:gpt-4o",
    custom_section="...", additional_tools=[...],
)

# Threat Intel — CORRECTION (Phase 2): band-sdk 0.2.11 has **NO OpenAIAdapter**
# (the adapters/__init__ __getattr__ lists langgraph/anthropic/pydantic_ai/
# crewai/gemini/... but no openai; the `[openai]` extra only installs the
# openai lib). CrewAI was the chosen substitute but `crewai` requires
# Python <3.14 and the venv is 3.14 → can't install. So Threat Intel uses the
# **LangGraph adapter** (3 distinct frameworks across 4 agents). To restore a
# 4th framework, rebuild the venv on Python 3.13 and use CrewAI.
#
# Pydantic AI (Compliance) — PIN `pydantic-ai-slim==1.56.0`. band-sdk's adapter
# calls Agent(..., output_type=None), which pydantic-ai 1.107 rejects.
#
# Tool restriction: pass features=AdapterFeatures(include_tools=
# ["thenvoi_send_message"]) to keep agents from calling stray platform tools
# (Compliance self-removed from a room via a wrong tool call before this).
```

Install (use uv per project):

```bash
uv add "band-sdk[langgraph]==0.2.11"     # Triage
uv add "band-sdk[openai]==0.2.11"        # Threat Intel  (VERIFIED adapter name)
uv add "band-sdk[pydantic-ai]==0.2.11"   # Compliance
uv add "band-sdk[anthropic]==0.2.11"     # Commander
```

Custom tools use the LangChain `@tool` decorator and are passed via
`additional_tools=[...]` on every adapter. Tool docstrings + signatures are
the schema the LLM sees — write them carefully.

---

## C. Fallback decisions (record after Phase 0 verification)

Lock these *before* Phase 1, so we don't have to redesign mid-build.

| If verification finds… | We will… |
|---|---|
| Q6 fails: agents can't add humans | Human CISO pre-joins the WarRoom; Commander only @mentions them at escalation. |
| Q8/Q9 fails: cross-account doesn't work | Register Compliance under the **primary** account; cut the cross-account contacts beat from the demo. |
| Q4 fails: agents can't create rooms | Operator pre-creates a room per incident; `room.default_room_id` in `agent_config.yaml` is set; Triage skips `thenvoi_create_chatroom` and just recruits into the pre-built room. |
| Q10 fails: no usable history endpoint | Exporter listens to the live stream during the run and persists messages as they arrive (slower to build; keep this as worst-case). |
| Q13 confirms 24h retention | Auto-run exporter at every RESOLUTION; demo always uses a freshly injected incident — never an old room. |

Decisions made (locked 2026-06-13, updated 2026-06-14 for Option B):

- [x] Q6 path chosen: **Triage adds the CISO when creating the incident room**.
      Verified agents can add humans. The human is added to the incident room
      at creation time, not at escalation (Commander only @mentions them later).
- [x] Q8/Q9 path chosen: **Keep the cross-account demo.** Compliance stays on
      the secondary account. Requirement: the agent-to-agent contact handshake
      (see §A.0 gotcha) must be in place — it is, and is persistent.
- [x] Q4 path chosen: **Triage creates the incident room per alert** via
      `thenvoi_create_chatroom` after reading the alert. `room.default_room_id`
      stays blank (no pre-made room). The injector creates a separate intake
      room to deliver the alert to Triage.
- [x] Q10 path chosen: **Exporter pulls history** from
      `GET /agent/chats/{id}/context` (paginate via `next_cursor`). No
      `delivery_status`; use `metadata.mentions` + inline `@[[uuid]]` tokens.

---

## D. Phase 0 manual checklist (the parts requiring a human + browser)

1. **Primary Band account** — sign up at app.band.ai with your work email.
2. **Secondary Band account** — sign up with a different email (e.g.
   `+compliance` alias). This is the "external counsel" org that hosts the
   Compliance agent.
3. From the primary account → Agents → New Agent → **External Agent**:
   - Create `WarRoom-Triage` (LangGraph). Copy the API key **immediately** —
     it is shown once. Copy the Agent UUID from the settings page.
   - Repeat for `WarRoom-ThreatIntel` (OpenAI) and `WarRoom-Commander`
     (Anthropic).
4. From the **secondary** account, register `WarRoom-Compliance` (Pydantic
   AI) the same way.
5. Paste all four `(uuid, api_key)` pairs into `agent_config.yaml`
   (gitignored; the example file is `agent_config.yaml.example`).
6. From primary → Contacts → request contact with secondary's user. From
   secondary → approve. Confirm both directions in `lookup_peers`.
7. Run the quickstart in `quickstart/my_agent.py` (after filling in the
   Triage UUID + key) and chat with it from the web UI. This is the
   "platform actually works for me" gate.
8. Walk through §A.1 – §A.5 questions above and tick each ✅ when verified.
9. Make the §C fallback decisions explicit and check the box.
10. Only then begin Phase 1.

---

## E. Phase 4 — Collaboration protocol  *(the heart of the project)*

This is the single source of truth for how the four agents collaborate. It is
mirrored, condensed, into each agent's `prompt.md`. If you change a rule here,
change the affected prompt(s) too.

### E.0 The participants and their handles

Mentions route by **handle** (the `mentions=[...]` argument to
`thenvoi_send_message`). Memorise these — a wrong handle silently drops the
recipient (see [[reference-band-mentions]]):

| Role | Agent / framework | Handle | Account |
|---|---|---|---|
| Triage | LangGraph | `@merolavtech/triage` | primary |
| Threat Intel | LangGraph | `@merolavtech/threat-intel` | primary |
| Compliance | Pydantic AI | `@merolavtechnologies/compliance` | **secondary** |
| Incident Commander | Anthropic / Claude | `@merolavtech/commander` | primary |
| Human CISO | (human) | `@merolavtech` | primary |

Because non-mentioned **agents see nothing** (the human sees everything), every
message below specifies *exactly who to @mention*.

### E.1 The message format

Every operationally meaningful message = **human-readable text, then one fenced
`json` block** validating against `shared/schemas.py :: ProtocolMessage`:

```json
{"type": "FINDING|QUESTION|SIGNOFF_REQUEST|SIGNOFF|VETO|ESCALATION|ACTION|RESOLUTION|BRIEF|CLOSE",
 "incident": "INC-...", "summary": "...", "severity": "...",
 "evidence": ["..."], "deadline_utc": null, "decision": null,
 "regulation": null, "actions": [], "recruited": [], "mentions": ["@..."]}
```

Only `type`, `incident`, `summary` are required; the rest are type-specific.
The text drives the live demo; the JSON block is the audit record the exporter
parses. Tool outputs are NOT protocol blocks — the parser ignores any JSON
without a `type`.

### E.2 The flow (one incident room per alert; spawned by Triage)

The **injector creates a temporary intake room** containing **Triage only** and
posts the alert there @mentioning Triage. Triage reads the alert and then spins
up the incident room. The intake room is a throwaway kickoff mechanism; the real
incident coordination happens in the incident room Triage creates.

1. **Kickoff & room creation (Triage).** Triage receives the alert in the intake
   room, calls `classify_alert` (and `lookup_asset` if useful).
   - **False positive** → post a `CLOSE` @mentioning the human; recruit nobody.
     (INC-B.) Triage does NOT create a room for this case.
   - **Real incident** → use `thenvoi_create_chatroom` to spin up the incident
     room, then:
     - Add the **human CISO** via `thenvoi_add_participant` (so the CISO sees
       everything from the start, not just at escalation).
     - For each specialist in `recommended_specialists`, use `thenvoi_lookup_peers`
       then `thenvoi_add_participant` to recruit them (skip any already present).
     - Post a `BRIEF` @mentioning all recruited specialists (and the human).
     
     Recruitment must be **reasoned and visible** in the brief ("asset holds
     customer_pii → adding Compliance"), never hardcoded. The roster is whatever
     `classify_alert` returned: INC-C → Threat Intel + Compliance + Commander;
     INC-A → Threat Intel + Commander (no Compliance).
2. **Parallel analysis (specialists).** Each recruited specialist investigates
   with its own tools and posts a `FINDING` @mentioning the **Commander** (and
   the other specialist when relevant). Threat Intel: `lookup_ioc` per
   indicator + `assess_spread_risk`. Compliance: `check_regulatory_triggers`,
   `evidence_preservation_requirements`, and `start_notification_clock` when a
   regime fires.
3. **Cross-examination.** Each specialist must ask **≥1 substantive `QUESTION`**
   of the other when its decision depends on the other's domain — e.g. Intel
   asks Compliance whether the host's data class blocks a wipe; Compliance asks
   Intel whether isolation alone stops the spread. @mention the agent being
   asked (+ Commander). This is the visible agent↔agent collaboration.
4. **Sign-off (Commander).** Commander synthesises and posts a
   `SIGNOFF_REQUEST` with a concrete plan, @mentioning **every specialist in
   the room**. It may execute action tools **only after a `SIGNOFF` from each**.
5. **Veto (Compliance).** Compliance posts a `VETO` (with the cited
   `regulation`) for any action that violates an obligation — chiefly a
   `wipe_host` on a host under an evidence-preservation hold. A veto blocks that
   action **unconditionally**; it does not block non-destructive actions
   (isolate, image).
6. **Escalation (Commander).** If the Commander holds a `VETO` that conflicts
   with another specialist's recommendation, **or** there is no consensus after
   **2 negotiation rounds**, it posts one `ESCALATION` @mentioning the **human
   CISO** (`@merolavtech`): a ≤5-line neutral summary of both positions and a
   single concrete decision request. The CISO's reply is final.
7. **Resolution (Commander).** Commander executes the approved actions (its
   action tools), posting an `ACTION` block per executed tool, then a final
   `RESOLUTION` @mentioning the human + specialists. After RESOLUTION the
   incident is closed.

### E.3 Who @mentions whom (routing table)

| Message | Sender | @mention | Tools used |
|---|---|---|---|
| BRIEF | Triage | recruited specialists + human | classify_alert, lookup_asset, lookup_peers, create_chatroom, add_participant |
| CLOSE | Triage | human | classify_alert |
| FINDING | Intel / Compliance | Commander (+ other specialist) | own domain tools |
| QUESTION | any specialist | the asked specialist (+ Commander) | — |
| SIGNOFF_REQUEST | Commander | all specialists | — |
| SIGNOFF | Intel / Compliance | Commander | — |
| VETO | Compliance | Commander (+ Intel) | check_regulatory_triggers, evidence_preservation_requirements |
| ESCALATION | Commander | human CISO | — |
| ACTION / RESOLUTION | Commander | human + specialists | isolate_host, preserve_disk_image, wipe_host, notify_stakeholders |

### E.4 Anti-loop guards (in every prompt)

- **Action authority:** only the **Commander** calls action tools. No other
  agent has them.
- **Negotiation cap:** at most **2 rounds** of specialist back-and-forth before
  the Commander is forced to escalate. Don't restate a position you've already
  made.
- **No re-litigation:** after a `RESOLUTION` (or the CISO's ruling), no agent
  reopens the decision.
- **One purposeful message per turn:** post only when you have something new and
  are @mentioned. Never reply to messages that don't @mention you. Always send
  via `thenvoi_send_message`; raw LLM text never reaches the room.
- **Every turn ends in a `thenvoi_send_message`.** Running analysis/action tools
  is never the final step — after the tool results return, the agent MUST post
  its result in the *same* turn. Agents are purely reactive (they run only when
  @mentioned), so an agent that analyses but never posts silently stalls the whole
  incident — this was the #1 observed failure. If you didn't send, you didn't
  speak.
- **Hand off the baton.** Every operational message @mentions exactly who must
  act next and states what is needed of them. A message that names no next actor
  ends the chain and idles the room.
- **Facilitator watchdog (anti-stall).** Triage adds a silent Facilitator
  (`@merolavtech/facilitator`) to every incident room. An out-of-band driver
  (`scripts/incident_driver.py`) posts as the Facilitator: if the room goes idle
  before RESOLUTION, it @mentions the expected next actor to re-start the flow,
  and escalates to the human after repeated stalls.
  - **CC the Facilitator on every message.** On the Band free tier a non-mentioned
    agent sees nothing and the human API (full-room read) is blocked, so the
    Facilitator can only observe what it is @mentioned in. Therefore every agent
    MUST include `@merolavtech/facilitator` in its `mentions` on every message;
    the driver reads the Facilitator's message queue to infer state. This is
    best-effort — if an agent omits the CC the watchdog misses that message but
    still catches later stalls. See [[project_coordination_fix]].
- **Post each block once; never relay others' findings.** Each `FINDING` /
  `VETO` / etc. is posted exactly once per incident. Do not re-summarise or relay
  another agent's findings — each agent speaks for itself. If re-mentioned with
  nothing new, answer only the specific new `QUESTION` in ≤2 sentences or **send
  nothing** — silence is correct. (This guards against the duplicate-FINDING
  blow-up that inflates every agent's per-turn token cost; see
  [[project_aiml_swap_cost]].)

### E.5 The scripted conflict (INC-C) — emerges from the data, not a script

The contested incident is forced by the agents' **own tools**, not hardcoded:

- Threat Intel: `lookup_ioc("185.220.101.47")` → BlackHaze ransomware,
  `lateral_movement: true`; `assess_spread_risk("srv-db-01")` → critical with
  `eradication_requires_reimage: true` (a domain controller is reachable) →
  isolation **contains but does not eradicate**; the host **must be wiped +
  reimaged**.
- Compliance: `check_regulatory_triggers("INC-C")` → GDPR-ART-33 (72h) +
  SEC-8K-1.05; `evidence_preservation_requirements("srv-db-01")` →
  `requires_human_authorization_to_destroy: true` → the host is under a hold a
  forensic image does **not** release → **VETO the wipe**; only a human officer
  can authorize destruction. Isolate + image are fine; start the 72h clock.
- **Why it can't auto-resolve:** "image then wipe" does not satisfy the hold, and
  "just isolate" does not eradicate the foothold — no sequence satisfies both.
  Commander executes the agreed actions (isolate, image, notify) and **escalates
  the wipe to the human CISO**, who makes the risk call (authorize the wipe vs.
  keep the host live). Commander executes the ruling, exports the report. The
  human decision is structurally required, not optional.

INC-A completes with sign-offs and **no** escalation; INC-B is closed at triage.
That proportionality is the proof the system isn't theatre.
