"""Band-SDK logging glue.

The walking-skeleton demo shows one terminal per framework and the judges
need to *see* each framework react. But band-sdk is silent by default: its
own logs go to the `thenvoi.*` loggers, which have no handler in our process,
and it emits no per-message line we control.

This module fixes both:

- `LoggingPreprocessor` wraps the SDK's DefaultPreprocessor and emits a tidy
  `[received] <type> from <sender>: <snippet>` line for every inbound message
  the agent actually acts on (self-messages and non-message events are already
  filtered out by the parent). Pass it to `Agent.create(preprocessor=...)`.
- `attach_sdk_logging()` routes the SDK's own `thenvoi` logger through our
  per-agent colored handler so lifecycle events (ExecutionContext start,
  history load, etc.) appear with the same prefix/colour. Level defaults to
  INFO; set WARROOM_SDK_LOG_LEVEL=DEBUG for full event/tool tracing.
"""

from __future__ import annotations

import logging
import os
import sys

from thenvoi.preprocessing.default import DefaultPreprocessor

from shared.logging import _AgentFormatter, log_event


class LoggingPreprocessor(DefaultPreprocessor):
    """DefaultPreprocessor + a `[received]` log line per inbound message."""

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__()
        self._log = logger

    async def process(self, ctx, event, agent_id):  # type: ignore[override]
        inp = await super().process(ctx=ctx, event=event, agent_id=agent_id)
        if inp is not None:
            m = inp.msg
            snippet = (m.content or "").replace("\n", " ").strip()
            if len(snippet) > 80:
                snippet = snippet[:80] + "..."
            sender = m.sender_name or m.sender_id
            log_event(self._log, "received", f"{m.message_type} from {sender}: {snippet}")
        return inp


def attach_sdk_logging(agent_name: str, level: int | None = None) -> None:
    """Route the band-sdk `thenvoi` logger through our colored handler."""
    if level is None:
        level = getattr(logging, os.getenv("WARROOM_SDK_LOG_LEVEL", "INFO").upper(), logging.INFO)
    sdk_logger = logging.getLogger("thenvoi")
    if getattr(sdk_logger, "_warroom_attached", False):
        sdk_logger.setLevel(level)
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_AgentFormatter(agent_name, color=sys.stdout.isatty()))
    sdk_logger.addHandler(handler)
    sdk_logger.setLevel(level)
    sdk_logger.propagate = False
    sdk_logger._warroom_attached = True  # type: ignore[attr-defined]
