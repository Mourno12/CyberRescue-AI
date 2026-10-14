"""Threat Intel agent — LangGraph adapter. Phase 2 roster.

Intended framework was the OpenAI Agents SDK, but band-sdk 0.2.11 ships no
OpenAI adapter and CrewAI needs Python <3.14, so Threat Intel reuses the
LangGraph adapter (distinct *agent*, same framework as Triage). LLM is AIML
(OpenAI-compatible) via OPENAI_BASE_URL, same as Triage.

Run locally:
    uv run python -m agents.threat_intel.main

Or via docker-compose:
    docker compose up threat_intel
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver
from thenvoi import Agent, AdapterFeatures
from thenvoi.adapters import LangGraphAdapter

from agents.threat_intel.tools import langchain_tools
from shared.band_logging import LoggingPreprocessor, attach_sdk_logging
from shared.config import load_agent, render_prompt
from shared.logging import get_logger, log_event
from shared.sdk_patches import apply_sdk_patches


AGENT_NAME = "threat_intel"
PROMPT_PATH = Path(__file__).with_name("prompt.md")


async def main() -> None:
    log = get_logger(AGENT_NAME)
    attach_sdk_logging(AGENT_NAME)
    apply_sdk_patches()  # band-sdk 0.2.11 ack-loop fixes (see shared/sdk_patches.py)
    log_event(log, "boot", "loading config")

    creds = load_agent(AGENT_NAME)
    log_event(log, "config", f"framework={creds.framework} account={creds.account}")

    model = os.getenv("THREAT_INTEL_MODEL", "gpt-4o")
    # Cost guards: cap per-call output + per-message tool-loop turns. Threat Intel
    # only runs a few domain tools (lookup_ioc per indicator, assess_spread_risk)
    # then sends, so a tighter recursion_limit is fine.
    # Generous output cap (output tokens are a tiny fraction of cost; a tight cap
    # only risks truncating the FINDING before the send). Env-overridable.
    max_tokens = int(os.getenv("THREAT_INTEL_MAX_TOKENS", "4096"))
    recursion_limit = int(os.getenv("THREAT_INTEL_RECURSION_LIMIT", "15"))
    # CyberRescue: handles in the prompt come from agent_config.yaml at load time.
    custom_section = render_prompt(PROMPT_PATH)

    adapter = LangGraphAdapter(
        llm=ChatOpenAI(model=model, max_tokens=max_tokens),
        checkpointer=InMemorySaver(),
        recursion_limit=recursion_limit,
        custom_section=custom_section,
        # Domain tools: lookup_ioc, assess_spread_risk (Phase 3).
        additional_tools=langchain_tools(),
        # Allowlist (Phase 4) — PLATFORM tools only (the lookup_ioc /
        # assess_spread_risk domain tools in additional_tools are merged
        # unconditionally and must NOT be listed). Threat Intel only needs to
        # speak; it has no recruitment or action tools.
        features=AdapterFeatures(include_tools=["thenvoi_send_message"]),
    )
    agent = Agent.create(
        adapter=adapter,
        agent_id=creds.agent_id,
        api_key=creds.api_key,
        preprocessor=LoggingPreprocessor(log),
    )

    log_event(log, "connect", f"running Band agent loop (model={model})")
    await agent.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
