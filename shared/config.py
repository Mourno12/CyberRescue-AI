"""Load Band agent credentials from agent_config.yaml and LLM keys from .env.

Each agent's main.py calls `load_agent("triage")` and gets back the (uuid,
api_key, model) it needs. Env keys (OPENAI_API_KEY, ANTHROPIC_API_KEY) are
loaded into os.environ as a side effect so SDK clients pick them up.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml
from dotenv import load_dotenv


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = REPO_ROOT / "agent_config.yaml"


@dataclass(frozen=True)
class AgentCreds:
    name: str
    framework: str
    agent_id: str
    api_key: str
    account: str  # "primary" | "secondary"
    handle: str = ""  # Band handle, e.g. "@merolavtech/triage" (for mentions)


def _load_env() -> None:
    # .env.local takes precedence over .env so real secrets stay out of .env.
    for fname in (".env", ".env.local"):
        path = REPO_ROOT / fname
        if path.exists():
            load_dotenv(path, override=True)


def load_agent(name: str, config_path: Path | None = None) -> AgentCreds:
    _load_env()
    path = config_path or Path(os.getenv("AGENT_CONFIG_PATH", DEFAULT_CONFIG_PATH))
    if not path.exists():
        raise FileNotFoundError(
            f"agent_config.yaml not found at {path}. Copy "
            "agent_config.yaml.example and fill in Band UUIDs + API keys."
        )
    with path.open() as f:
        cfg = yaml.safe_load(f)
    agents = cfg.get("agents", {})
    if name not in agents:
        raise KeyError(f"agent '{name}' not in {path}. Have: {list(agents)}")
    a = agents[name]
    for required in ("agent_id", "api_key", "framework"):
        if not a.get(required) or "REPLACE" in str(a[required]):
            raise ValueError(
                f"agent '{name}' is missing {required} (or still has the "
                "REPLACE_WITH_... placeholder). Register the External Agent "
                "on app.band.ai and fill in agent_config.yaml."
            )
    return AgentCreds(
        name=name,
        framework=a["framework"],
        agent_id=a["agent_id"],
        api_key=a["api_key"],
        account=a.get("account", "primary"),
        handle=a.get("handle", ""),
    )


# --- Band handles (CyberRescue: runtime handle configuration) ----------------
#
# Upstream WarRoom (genyarko/warroom) wrote its prompts and Facilitator nudges
# against the original author's Band accounts. Those texts are kept verbatim
# (attribution, and the upstream tests that read them); the handles below are
# exactly as written there, and are replaced at load time with the handles
# configured in agent_config.yaml -- the single source of truth for identities.
UPSTREAM_HANDLES: dict[str, str] = {
    "triage": "@merolavtech/triage",
    "threat_intel": "@merolavtech/threat-intel",
    "compliance": "@merolavtechnologies/compliance",
    "commander": "@merolavtech/commander",
    "facilitator": "@merolavtech/facilitator",
    "ciso": "@merolavtech",          # the human CISO (a Band user, not an agent)
}
AGENT_HANDLE_ROLES = ("triage", "threat_intel", "compliance", "commander", "facilitator")
_AGENT_HANDLE = re.compile(r"^@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_USER_HANDLE = re.compile(r"^@[A-Za-z0-9_.-]+$")
_ANY_AGENT_HANDLE = re.compile(r"(?<![\w.])@[A-Za-z0-9_.-]+/[A-Za-z0-9_-]+")
_BARE_HANDLE = re.compile(r"(?<![\w.])@[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*(?![\w/-])")
# Words that start with "@" in the upstream prompt/driver texts but are not Band
# handles: "@mention(s/ed/ing)" (prose) and "@dataclass" (Python, driver source).
_NOT_HANDLES = re.compile(r"^@(mention\w*|dataclass)$", re.IGNORECASE)

# Placeholder values used by .env.example, agent_config.yaml.example and the
# docs: REPLACE_WITH_..., <uuid>, <key>, {{...}}, YOUR_..., "sk-..." etc. Only
# clearly-marked placeholder tokens are rejected, so an unfamiliar but real
# identifier is never refused just for its shape.
_PLACEHOLDER = re.compile(
    r"<[^<>]*>|\{\{.*?\}\}|\.\.\.$"
    r"|(^|[^a-z0-9])(replace|your|example|placeholder|changeme|todo|tbd|xxx+)([^a-z0-9]|$)",
    re.IGNORECASE)
# Documented example handle owners (agent_config.yaml.example, the runbook).
_EXAMPLE_OWNERS = frozenset({"you", "youraccount", "yoursecondaccount", "owner", "account"})


def is_placeholder(value: str | None) -> bool:
    """True for an obvious placeholder (never for a merely unfamiliar value)."""
    v = (value or "").strip()
    return bool(v) and (v in {"sk-", "sk-ant-"} or _PLACEHOLDER.search(v) is not None)


def _example_handle(handle: str) -> bool:
    owner = handle.lstrip("@").split("/", 1)[0].lower()
    return owner in _EXAMPLE_OWNERS or is_placeholder(handle)


class HandleConfigError(ValueError):
    """agent_config.yaml does not define a usable handle for every identity."""


def read_agent_config(config_path: Path | None) -> dict:
    path = config_path or Path(os.getenv("AGENT_CONFIG_PATH", DEFAULT_CONFIG_PATH))
    if not path.exists():
        raise FileNotFoundError(f"agent_config.yaml not found at {path}")
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def handles_from_config(cfg: dict) -> dict[str, str]:
    """role -> configured handle for the five agents + the CISO.

    Raises ``HandleConfigError`` naming every missing/malformed/placeholder
    entry (handles are not secrets, so they may appear in the message).
    """
    agents = cfg.get("agents") or {}
    out, problems = {}, []
    for role in AGENT_HANDLE_ROLES:
        h = str((agents.get(role) or {}).get("handle") or "").strip()
        if not _AGENT_HANDLE.match(h) or _example_handle(h):
            problems.append(f"agents.{role}.handle={h!r} (expected your real '@owner/slug')")
        else:
            out[role] = h
    humans = cfg.get("humans")
    if not isinstance(humans, dict) or not isinstance(humans.get("ciso"), dict):
        problems.append("humans.ciso is missing -- this agent_config.yaml predates CyberRescue's "
                        "identity configuration; copy the `humans: ciso: {handle, user_id}` "
                        "block from agent_config.yaml.example and fill it in")
    else:
        h = str(humans["ciso"].get("handle") or "").strip()
        if not _USER_HANDLE.match(h) or _example_handle(h):
            problems.append(f"humans.ciso.handle={h!r} (expected the CISO's real '@owner')")
        else:
            out["ciso"] = h
    if len(set(out.values())) != len(out):
        problems.append("two identities share one handle")
    if problems:
        raise HandleConfigError("agent_config.yaml handles: " + "; ".join(problems))
    return out


def load_handles(config_path: Path | None = None) -> dict[str, str]:
    return handles_from_config(read_agent_config(config_path))


def _upstream_pattern() -> re.Pattern[str]:
    alts = []
    for h in sorted(UPSTREAM_HANDLES.values(), key=len, reverse=True):
        tail = r"(?![\w-])" if "/" in h else r"(?![\w/.-])"
        alts.append(re.escape(h) + tail)
    return re.compile(r"(?<![\w.])(?:" + "|".join(alts) + ")")


_UPSTREAM_RE = _upstream_pattern()
_UPSTREAM_ROLE = {h: r for r, h in UPSTREAM_HANDLES.items()}


def render_handles(text: str, handles: dict[str, str]) -> str:
    """Replace every upstream handle in ``text`` with the configured one, in a
    single pass (a replacement is never itself rewritten, so configured handles
    that happen to equal another role's upstream handle cannot be swapped twice).
    The bare CISO handle is not matched inside a longer handle or an email."""
    return _UPSTREAM_RE.sub(lambda m: handles[_UPSTREAM_ROLE[m.group(0)]], text)


def unresolved_handles(text: str, handles: dict[str, str]) -> list[str]:
    """Handles in ``text`` that are not configured identities: ``@owner/slug``
    forms, and bare ``@owner`` forms other than the CISO / a configured owner
    (prose words such as ``@mention`` excepted)."""
    known = {h.lower() for h in handles.values()}
    owners = {h.split("/", 1)[0].lower() for h in handles.values()}
    found = {h for h in _ANY_AGENT_HANDLE.findall(text) if h.lower() not in known}
    found |= {h for h in _BARE_HANDLE.findall(text)
              if h.lower() not in owners and not _NOT_HANDLES.match(h)}
    return sorted(found)


def render_prompt(path: Path, config_path: Path | None = None) -> str:
    """Load an agent prompt with the configured handles. Fails closed: an agent
    must not start with a prompt that @mentions identities that do not exist."""
    handles = load_handles(config_path)
    text = render_handles(path.read_text(encoding="utf-8"), handles)
    left = unresolved_handles(text, handles)
    if left:
        raise HandleConfigError(f"{path.name} still mentions unconfigured handles {left}")
    return text


def ciso_user_id(cfg: dict) -> str | None:
    """The CISO's Band user id (``humans.ciso.user_id``), if configured."""
    humans = cfg.get("humans") if isinstance(cfg.get("humans"), dict) else {}
    ciso = humans.get("ciso") if isinstance(humans.get("ciso"), dict) else {}
    uid = str(ciso.get("user_id") or "").strip()
    return uid if uid and not is_placeholder(uid) else None


def default_room_id(config_path: Path | None = None) -> str | None:
    """Optional pre-created room ID (set if Phase 0 found Triage can't create
    rooms, or for the smoke test before Triage gets that capability)."""
    path = config_path or Path(os.getenv("AGENT_CONFIG_PATH", DEFAULT_CONFIG_PATH))
    if not path.exists():
        return None
    with path.open() as f:
        cfg = yaml.safe_load(f)
    room = (cfg.get("room") or {}).get("default_room_id") or None
    return room
