"""Compliance agent — Pydantic AI adapter. Phase 2 roster.

Runs under the SECOND Band account (creds.account == "secondary"); the
agent-to-agent contact with the primary account is already established (see
shared/protocol.md §A.0), so primary-account agents can add it to rooms.

LLM is AIML (OpenAI-compatible) via the "openai:<model>" Pydantic AI model
string + OPENAI_BASE_URL. Holds veto power + the regulatory clock (Phase 4).

Run locally:
    uv run python -m agents.compliance.main

Or via docker-compose:
    docker compose up compliance
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from thenvoi import Agent, AdapterFeatures
from thenvoi.adapters import PydanticAIAdapter

from agents.compliance.tools import pydantic_ai_tools
from shared.band_logging import LoggingPreprocessor, attach_sdk_logging
from shared.config import load_agent, render_prompt
from shared.logging import get_logger, log_event
from shared.sdk_patches import apply_sdk_patches


AGENT_NAME = "compliance"
PROMPT_PATH = Path(__file__).with_name("prompt.md")


async def main() -> None:
    log = get_logger(AGENT_NAME)
    attach_sdk_logging(AGENT_NAME)
    apply_sdk_patches()  # band-sdk 0.2.11 ack-loop fixes (see shared/sdk_patches.py)
    log_event(log, "boot", "loading config")

    creds = load_agent(AGENT_NAME)
    log_event(log, "config", f"framework={creds.framework} account={creds.account}")

    # Pydantic AI model string. AIML is OpenAI-compatible, so "openai:<model>"
    # + OPENAI_BASE_URL (set in .env.local) routes through AIML.
    model = os.getenv("COMPLIANCE_MODEL", "openai:gpt-4o")
    # CyberRescue: handles in the prompt come from agent_config.yaml at load time.
    custom_section = render_prompt(PROMPT_PATH)

    adapter = PydanticAIAdapter(
        model=model,
        custom_section=custom_section,
        # Domain tools: check_regulatory_triggers, start_notification_clock,
        # evidence_preservation_requirements (Phase 3).
        additional_tools=pydantic_ai_tools(),
        # Allowlist (Phase 4) — PLATFORM tools only. The three regulatory tools
        # in additional_tools are merged unconditionally (not filtered here).
        # Restricting platform tools to send_message is also what stops the
        # stray remove_participant that self-removed this agent in Phase 2.
        # Compliance advises and vetoes only — no recruitment, no action tools.
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
