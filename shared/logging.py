"""Structured per-agent logger.

The demo shows four terminal windows side by side. Every line needs a
visually distinct prefix so judges can see which framework is reacting.
Format:

    [AGENT-NAME] [LEVEL] [EVENT] message

Use `get_logger("triage")` from each agent's main.py.
"""

from __future__ import annotations

import logging
import sys


_COLORS = {
    "triage":       "\033[96m",  # cyan
    "threat_intel": "\033[93m",  # yellow
    "compliance":   "\033[95m",  # magenta
    "commander":    "\033[91m",  # red
}
_RESET = "\033[0m"


class _AgentFormatter(logging.Formatter):
    def __init__(self, agent_name: str, color: bool):
        super().__init__()
        self.agent_name = agent_name
        self.prefix = (
            f"{_COLORS.get(agent_name, '')}[{agent_name.upper()}]{_RESET}"
            if color else f"[{agent_name.upper()}]"
        )

    def format(self, record: logging.LogRecord) -> str:
        event = getattr(record, "event", "")
        event_str = f"[{event}] " if event else ""
        return f"{self.prefix} [{record.levelname}] {event_str}{record.getMessage()}"


def get_logger(agent_name: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(f"warroom.{agent_name}")
    if logger.handlers:
        return logger
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_AgentFormatter(agent_name, color=sys.stdout.isatty()))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


# Convenience helpers — keep call sites tight in agent code.
def log_event(logger: logging.Logger, event: str, msg: str = "") -> None:
    logger.info(msg, extra={"event": event})
