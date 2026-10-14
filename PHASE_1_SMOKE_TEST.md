# Phase 1 — Walking-skeleton smoke test

**Goal:** prove two agents on two different frameworks (LangGraph + Anthropic)
complete a multi-turn @mention conversation in one Band room, launched via
`docker compose up`.

This is the exit criterion for Phase 1 and the gate to Phase 2.

## Prereqs (from Phase 0)

- ✅ Triage and Commander External Agents registered on the primary Band
  account. UUID + API key for each pasted into `agent_config.yaml`.
- ✅ `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` set in `.env` or `.env.local`.
- ✅ Either:
  - `room.default_room_id` set in `agent_config.yaml` to a room you've
    pre-created in the web UI, **or**
  - both agents added to a room you create on the fly in the web UI before
    starting the smoke test.

## Run

```bash
docker compose build
docker compose up
```

You should see, in two terminal panes (or one interleaved):

```
[TRIAGE]    [INFO] [boot]    loading config
[TRIAGE]    [INFO] [config]  framework=langgraph account=primary
[TRIAGE]    [INFO] [connect] running Band agent loop (Ctrl-C to stop)
[COMMANDER] [INFO] [boot]    loading config
[COMMANDER] [INFO] [config]  framework=anthropic account=primary
[COMMANDER] [INFO] [connect] running Band agent loop (model=claude-sonnet-4-6)
```

Distinct color prefixes — that's the demo's visual cross-framework proof.

## Drive the conversation

In the Band web UI, in a room containing **both** WarRoom-Triage and
WarRoom-Commander as participants, post:

```
@Triage ping the commander
```

Expected: three or so round trips between Triage and Commander, both
@mentioning each other every time, ending with one of them saying
"ping-pong complete". You should see no operator intervention required after
the first message.

## Exit criterion

- [ ] Both containers boot from `docker compose up` cold.
- [ ] Triage and Commander complete ≥3 round trips of @mention messages
      without further human input.
- [ ] Each agent's terminal log shows `[received] ... [sent] ...` (or
      equivalent SDK lifecycle events) for every exchange.
- [ ] Killing one container and `docker compose up <name>` brings it back
      cleanly.

If all four boxes are ✅, Phase 1 is done — proceed to Phase 2 (add Threat
Intel + Compliance, with Compliance on the second Band account).

## Known un-verified assumptions in this code

- `from thenvoi.adapters import LangGraphAdapter, AnthropicAdapter` — docs
  confirm these names; SDK version may change them. Adjust if `ImportError`
  on first boot.
- `claude-sonnet-4-6` model ID — override via `COMMANDER_MODEL` env var if
  the Anthropic SDK rejects it.
- Whether the SDK auto-logs received/sent/tool-called or whether we need to
  hook them — we'll know after the first run. If not, we'll wrap the
  send/receive paths and re-emit our own events for the demo.
