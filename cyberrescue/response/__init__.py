"""CyberRescue response planning (Phase 4) - deterministic, read-only, proposal-only.

Turns an investigation case (Phase 3) into an advisory ``ResponsePlan``:
proposed tier-1/2 steps with evidence citations and policy *previews*, human
decision points for tier-3 actions and protected targets, and investigative
tasks. It never requests, approves, authorizes or executes an action, never
writes to the Core, and contains no LLM.
"""

from cyberrescue.response.model import PLAN_SCHEMA, ResponsePlan

__all__ = ["PLAN_SCHEMA", "ResponsePlan"]
