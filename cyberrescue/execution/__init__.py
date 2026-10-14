"""CyberRescue simulated executor (Phase 5) - deterministic, read-only, simulation only.

Takes a Phase 4 response plan and SIMULATES the steps the CyberRescue Core has
already authorized, against an in-memory environment built from the
incident's evidence, then checks the plan's success criteria. It never runs a
command, contacts a system, creates an approval, sign-off or actor, requests or
authorizes an action, writes to the Core, reads ground truth, or uses an LLM.
"""

from cyberrescue.execution.model import EXECUTION_SCHEMA, ExecutionReport

__all__ = ["EXECUTION_SCHEMA", "ExecutionReport"]
