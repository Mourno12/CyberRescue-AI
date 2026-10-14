"""Incident Commander agent — Anthropic adapter. Phase 1 walking-skeleton.

Run locally:
    uv run python -m agents.commander.main

Or via docker-compose:
    docker compose up commander
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from thenvoi import Agent, AdapterFeatures
from thenvoi.adapters import AnthropicAdapter

from agents.commander.tools import anthropic_tools
from shared.band_logging import LoggingPreprocessor, attach_sdk_logging
from shared.config import load_agent, render_prompt
from shared.logging import get_logger, log_event
from shared.sdk_patches import apply_sdk_patches


AGENT_NAME = "commander"
PROMPT_PATH = Path(__file__).with_name("prompt.md")


async def main() -> None:
    log = get_logger(AGENT_NAME)
    attach_sdk_logging(AGENT_NAME)
    apply_sdk_patches()  # band-sdk 0.2.11 ack-loop fixes (see shared/sdk_patches.py)
    log_event(log, "boot", "loading config")

    creds = load_agent(AGENT_NAME)
    log_event(log, "config", f"framework={creds.framework} account={creds.account}")

    # Cheap-by-default Claude for cost control while routed through AIML (Sonnet
    # cost ~1.27M tokens in a single run). Override via env to go back to Sonnet.
    model = os.getenv("COMMANDER_MODEL", "claude-haiku-4-5-20251001")
    # Cap output tokens per call (guards against runaway generations). The
    # Commander's messages (SIGNOFF_REQUEST / ESCALATION / ACTION / RESOLUTION +
    # tool calls) are short; 1536 leaves headroom without truncating tool_use.
    max_tokens = int(os.getenv("COMMANDER_MAX_TOKENS", "1536"))
    # CyberRescue: handles in the prompt come from agent_config.yaml at load time.
    custom_section = render_prompt(PROMPT_PATH)

    # NOTE: band-sdk 0.2.11's AnthropicAdapter has NO `client` kwarg — it
    # builds its own Anthropic client from ANTHROPIC_API_KEY (loaded from
    # .env.local by load_agent()). Pass model + key directly.
    adapter = AnthropicAdapter(
        model=model,
        api_key=os.getenv("ANTHROPIC_API_KEY"),
        max_tokens=max_tokens,
        custom_section=custom_section,
        # Action tools: isolate_host / preserve_disk_image / wipe_host /
        # notify_stakeholders (Phase 3). Commander is the only agent with action
        # tools — that's the single-action-authority rule.
        additional_tools=anthropic_tools(),
        # Allowlist (Phase 4) — PLATFORM tools only. The action tools
        # (isolate/image/wipe/notify) in additional_tools are merged
        # unconditionally and must NOT be listed here. Commander is the ONLY
        # agent with action tools (single-action-authority). The platform tools
        # below let it locate/@mention the human CISO at escalation time.
        features=AdapterFeatures(include_tools=[
            "thenvoi_send_message",
            "thenvoi_get_participants",
            "thenvoi_lookup_peers",
        ]),
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
