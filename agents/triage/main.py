"""Triage agent — LangGraph adapter. Phase 1 walking-skeleton.

Run locally:
    uv run python -m agents.triage.main

Or via docker-compose (preferred for the demo):
    docker compose up triage
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver
from thenvoi import Agent, AdapterFeatures
from thenvoi.adapters import LangGraphAdapter

from agents.triage.tools import langchain_tools
from shared.band_logging import LoggingPreprocessor, attach_sdk_logging
from shared.config import load_agent, render_prompt
from shared.logging import get_logger, log_event
from shared.sdk_patches import apply_sdk_patches


AGENT_NAME = "triage"
PROMPT_PATH = Path(__file__).with_name("prompt.md")


async def main() -> None:
    log = get_logger(AGENT_NAME)
    attach_sdk_logging(AGENT_NAME)
    apply_sdk_patches()  # band-sdk 0.2.11 ack-loop fixes (see shared/sdk_patches.py)
    log_event(log, "boot", "loading config")

    creds = load_agent(AGENT_NAME)
    log_event(log, "config", f"framework={creds.framework} account={creds.account}")

    model = os.getenv("TRIAGE_MODEL", "gpt-4o")
    # Cost guards (cap per-call output + per-message tool-loop turns). Triage's
    # busiest turn does ~9 tool calls (classify, create_chatroom, lookup_peers,
    # add_participant x4, send_message x2), so keep recursion_limit comfortably
    # above that; it only fires on a runaway loop.
    # Generous output cap: Triage's turn is multi-step (create room + ~5
    # add_participant calls + the BRIEF), and output tokens are a tiny fraction of
    # cost, so a tight cap only risks truncating recruitment. Env-overridable.
    max_tokens = int(os.getenv("TRIAGE_MAX_TOKENS", "4096"))
    recursion_limit = int(os.getenv("TRIAGE_RECURSION_LIMIT", "25"))
    # CyberRescue: handles in the prompt come from agent_config.yaml at load time.
    custom_section = render_prompt(PROMPT_PATH)

    adapter = LangGraphAdapter(
        llm=ChatOpenAI(model=model, max_tokens=max_tokens),
        checkpointer=InMemorySaver(),
        recursion_limit=recursion_limit,
        custom_section=custom_section,
        # Domain tools: classify_alert, lookup_asset (Phase 3).
        additional_tools=langchain_tools(),
        # Allowlist (Phase 4) — PLATFORM tools only. include_tools filters the
        # built-in thenvoi_* tools; the domain tools in additional_tools above
        # are merged unconditionally by the adapter and are NOT affected.
        # Triage's recruitment is now DETERMINISTIC: shared/sdk_patches.py
        # repurposes thenvoi_create_chatroom to recruit the whole standard team
        # into the current room in code (gpt-4o was unreliable at per-specialist
        # add_participant calls and at avoiding duplicate rooms). So Triage only
        # needs: classify -> create_chatroom (auto-recruits) -> send the BRIEF.
        # add_participant / lookup_peers are intentionally NOT exposed.
        features=AdapterFeatures(include_tools=[
            "thenvoi_send_message",
            "thenvoi_create_chatroom",
            "thenvoi_get_participants",
        ]),
    )
    agent = Agent.create(
        adapter=adapter,
        agent_id=creds.agent_id,
        api_key=creds.api_key,
        preprocessor=LoggingPreprocessor(log),
    )

    log_event(log, "connect", "running Band agent loop (Ctrl-C to stop)")
    await agent.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
