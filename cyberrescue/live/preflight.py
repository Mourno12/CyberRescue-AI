"""Offline readiness check for the live four-agent WarRoom runtime.

Answers "if I launch ``scripts/run_all.ps1`` now, will every agent start, and is
the Commander gate configured the way I think?" -- WITHOUT any network access,
LLM call, Band connection, or paid API usage.

Secrets: credential values are read only to classify them as ``missing``,
``placeholder`` or ``set``. No value, prefix, suffix or length is ever placed in
a check's detail text, and ``os.environ`` is never modified (``.env`` files are
read with ``dotenv_values``).

Status per check: ``ok`` | ``warn`` | ``fail``. Any ``fail`` means "do not
launch" (exit 1). ``--strict`` treats warnings as failures too.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import re
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from shared.config import (
    UPSTREAM_HANDLES,
    HandleConfigError,
    ciso_user_id,
    handles_from_config,
    is_placeholder,
    render_handles,
    unresolved_handles,
)

OK, WARN, FAIL = "ok", "warn", "fail"

# role -> (expected framework, account, agent module, tool factory)
AGENTS: dict[str, tuple[str, str, str | None, str | None]] = {
    "triage": ("langgraph", "primary", "agents.triage", "langchain_tools"),
    "threat_intel": ("langgraph", "primary", "agents.threat_intel", "langchain_tools"),
    "compliance": ("pydantic_ai", "secondary", "agents.compliance", "pydantic_ai_tools"),
    "commander": ("anthropic", "primary", "agents.commander", "anthropic_tools"),
    "facilitator": ("none", "primary", None, None),
}
LLM_ROLES = ("triage", "threat_intel", "compliance", "commander")

# (import name, distribution name or None, why)
PACKAGES: tuple[tuple[str, str | None, str], ...] = (
    ("thenvoi", "band-sdk", "Band agent SDK (all agents)"),
    ("thenvoi_rest", "thenvoi-client-rest", "Band REST client (facilitator, export)"),
    ("langchain_openai", "langchain-openai", "Triage + Threat Intel LLM"),
    ("langgraph", "langgraph", "Triage + Threat Intel adapter"),
    ("pydantic_ai", "pydantic-ai-slim", "Compliance adapter"),
    ("anthropic", "anthropic", "Commander LLM"),
    ("yaml", "PyYAML", "agent_config.yaml"),
    ("dotenv", "python-dotenv", ".env loading"),
)
PINNED = {"band-sdk": "0.2.11", "pydantic-ai-slim": "1.56.0"}

# Which credential each LLM-backed agent needs (see agents/*/main.py).
CREDENTIALS: dict[str, tuple[str, ...]] = {
    "OPENAI_API_KEY": ("triage", "threat_intel", "compliance"),
    "ANTHROPIC_API_KEY": ("commander",),
}
MODEL_ENV = {
    "TRIAGE_MODEL": "gpt-4o",
    "THREAT_INTEL_MODEL": "gpt-4o",
    "COMPLIANCE_MODEL": "openai:gpt-4o",
    "COMMANDER_MODEL": "claude-haiku-4-5-20251001",
}
ENDPOINT_ENV = ("OPENAI_BASE_URL", "ANTHROPIC_BASE_URL")
SECRET_FILES = (".env", ".env.local", "agent_config.yaml")


@dataclass
class Check:
    section: str
    name: str
    status: str
    detail: str = ""


@dataclass
class PreflightReport:
    checks: list[Check] = field(default_factory=list)

    def add(self, section: str, name: str, status: str, detail: str = "") -> None:
        self.checks.append(Check(section, name, status, detail))

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.status == FAIL]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.status == WARN]

    def ok(self, *, strict: bool = False) -> bool:
        return not self.failures and not (strict and self.warnings)

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok(), "failures": len(self.failures),
                "warnings": len(self.warnings), "checks": [asdict(c) for c in self.checks]}


# --- helpers -------------------------------------------------------------------

def classify_secret(value: str | None) -> str:
    """``missing`` | ``placeholder`` | ``set`` -- never returns the value."""
    if value is None or not value.strip():
        return "missing"
    return "placeholder" if is_placeholder(value) else "set"


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
UUID_NOTE = ("not a UUID -- the Band ids seen so far (shared/sample_message.json) are UUIDs; "
             "check it was copied correctly (format only, not proof the id exists)")


def effective_env(repo: Path, environ: Mapping[str, str]) -> tuple[dict[str, str], list[str]]:
    """Process env overlaid with .env then .env.local (same precedence as
    ``shared.config._load_env``), without touching ``os.environ``."""
    from dotenv import dotenv_values
    env = dict(environ)
    found = []
    for fname in (".env", ".env.local"):
        path = repo / fname
        if path.exists():
            found.append(fname)
            env.update({k: v for k, v in dotenv_values(path).items() if v is not None})
    return env, found


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                              text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None


# --- sections ----------------------------------------------------------------

def check_python(rep: PreflightReport, repo: Path, executable: str) -> None:
    v = sys.version_info
    status = OK if v >= (3, 11) else FAIL
    rep.add("python", "version", status, f"{v.major}.{v.minor}.{v.micro} (needs >= 3.11)")
    exe = Path(executable).resolve()
    venv313 = (repo / ".venv313").resolve()
    if venv313 in exe.parents:
        rep.add("python", "interpreter", OK, f"{exe} (.venv313, the verified environment)")
    else:
        rep.add("python", "interpreter", WARN,
                f"{exe} is not .venv313 -- the verified environment is "
                r".venv313\Scripts\python.exe")


def check_packages(rep: PreflightReport) -> None:
    for mod, dist, why in PACKAGES:
        if importlib.util.find_spec(mod) is None:
            rep.add("packages", mod, FAIL, f"not importable ({why}); "
                    r"run .venv313\Scripts\python.exe -m pip install -e .")
            continue
        version = ""
        if dist:
            try:
                version = importlib.metadata.version(dist)
            except importlib.metadata.PackageNotFoundError:
                version = "?"
        want = PINNED.get(dist or "")
        if want and version != want:
            rep.add("packages", mod, FAIL, f"{dist} {version} installed, {want} required "
                    "(pyproject.toml pin)")
        else:
            rep.add("packages", mod, OK, f"{dist} {version}".strip())


def check_credentials(rep: PreflightReport, env: Mapping[str, str], env_files: list[str]) -> None:
    rep.add("credentials", "env files", OK if env_files else WARN,
            ", ".join(env_files) + " present" if env_files else
            "no .env or .env.local -- copy .env.example to .env.local and fill in keys")
    for var, users in CREDENTIALS.items():
        state = classify_secret(env.get(var))
        rep.add("credentials", var, OK if state == "set" else FAIL,
                f"{state} (needed by {', '.join(users)})")
    for var in ENDPOINT_ENV:
        rep.add("credentials", var, OK,
                "set (custom endpoint)" if env.get(var) else "unset (provider default endpoint)")
    for var, default in MODEL_ENV.items():
        model = env.get(var) or default
        status = OK
        detail = f"{model}{'' if env.get(var) else ' (default)'}"
        if var == "COMPLIANCE_MODEL" and ":" not in model:
            status, detail = FAIL, f"{model!r} must be a Pydantic AI model string like 'openai:gpt-4o'"
        rep.add("models", var, status, detail)


def load_agent_config(path: Path) -> dict[str, Any] | None:
    import yaml
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def check_agent_config(rep: PreflightReport, cfg_path: Path,
                       cfg: dict[str, Any] | None) -> None:
    if cfg is None:
        rep.add("agent_config", "file", FAIL, f"{cfg_path} not found -- copy "
                "agent_config.yaml.example and fill in the Band UUIDs + API keys")
        return
    rep.add("agent_config", "file", OK, str(cfg_path))
    agents = cfg.get("agents") or {}
    ids: dict[str, str] = {}
    keys: dict[str, str] = {}
    for role, (framework, account, _mod, _tools) in AGENTS.items():
        a = agents.get(role)
        if not isinstance(a, dict):
            rep.add("agent_config", role, FAIL, "entry missing")
            continue
        problems, notes = [], []
        for fld in ("agent_id", "api_key"):
            state = classify_secret(str(a.get(fld) or ""))
            if state != "set":
                problems.append(f"{fld} {state}")
        agent_id = str(a.get("agent_id") or "").strip()
        if classify_secret(agent_id) == "set" and not _UUID.match(agent_id):
            notes.append(f"agent_id {UUID_NOTE}")
        if a.get("framework") != framework:
            problems.append(f"framework {a.get('framework')!r} (expected {framework!r})")
        handle = str(a.get("handle") or "")   # validated in check_identities
        if a.get("account", "primary") != account:
            notes.append(f"account {a.get('account')!r} (protocol expects {account!r})")
        if a.get("agent_id"):
            ids.setdefault(str(a["agent_id"]), role)
            if ids[str(a["agent_id"])] != role:
                problems.append(f"agent_id duplicates {ids[str(a['agent_id'])]}")
        if a.get("api_key"):
            keys.setdefault(str(a["api_key"]), role)
            if keys[str(a["api_key"])] != role:
                problems.append(f"api_key duplicates {keys[str(a['api_key'])]}'s")
        if problems:
            rep.add("agent_config", role, FAIL, "; ".join(problems + notes))
        else:
            rep.add("agent_config", role, WARN if notes else OK,
                    "; ".join(notes) or f"{handle} framework={framework} credentials set")
    room = (cfg.get("room") or {}).get("default_room_id")
    rep.add("agent_config", "room.default_room_id", OK,
            "set" if room else "empty (Triage creates the incident room; intake room is "
            "pasted into manually on the Band free tier)")


def check_secret_hygiene(rep: PreflightReport, repo: Path) -> None:
    tracked = _git(repo, "ls-files", "--", *SECRET_FILES)
    if tracked is None or tracked.returncode != 0:
        rep.add("secrets", "git", WARN, "git unavailable; could not verify tracking")
        return
    bad = [line for line in tracked.stdout.splitlines() if line.strip()]
    rep.add("secrets", "tracked secret files", FAIL if bad else OK,
            f"TRACKED by git: {', '.join(bad)}" if bad else "none of "
            f"{', '.join(SECRET_FILES)} is tracked")
    for fname in SECRET_FILES:
        ign = _git(repo, "check-ignore", "-q", fname)
        if ign is not None and ign.returncode != 0:
            rep.add("secrets", fname, FAIL, "not gitignored")


def check_agent_imports(rep: PreflightReport,
                        importer: Callable[[str], Any] = importlib.import_module,
                        repo: Path | None = None) -> None:
    """Import every agent module and build its tool list (no network, no LLM)."""
    for role, (_fw, _acct, pkg, factory) in AGENTS.items():
        if pkg is None:
            continue
        try:
            importer(f"{pkg}.main")
            tools = getattr(importer(f"{pkg}.tools"), factory)()
            prompt = Path(importer(f"{pkg}.main").__file__).with_name("prompt.md")
            if not prompt.exists() or not prompt.read_text(encoding="utf-8").strip():
                raise FileNotFoundError(f"{prompt.name} missing or empty")
            rep.add("agents", role, OK, f"{pkg}.main imports; {len(tools)} domain tool(s); "
                    "prompt.md present")
        except Exception as e:  # noqa: BLE001 -- report, never crash the preflight
            rep.add("agents", role, FAIL, f"{type(e).__name__}: {e}")
    if repo is not None:
        driver = repo / "scripts" / "incident_driver.py"
        name = "_preflight_incident_driver"
        try:
            spec = importlib.util.spec_from_file_location(name, driver)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod  # @dataclass resolves its module via sys.modules
            spec.loader.exec_module(mod)  # module level: argparse/dataclasses only
            rep.add("agents", "facilitator", OK, "scripts/incident_driver.py imports "
                    "(watchdog: no LLM)")
        except Exception as e:  # noqa: BLE001
            rep.add("agents", "facilitator", FAIL, f"{type(e).__name__}: {e}")
        finally:
            sys.modules.pop(name, None)


def _owner(handle: str) -> str:
    return handle.split("/", 1)[0].lower()


def check_identities(rep: PreflightReport, cfg: dict[str, Any] | None) -> dict[str, str] | None:
    """Five agent handles + the CISO identity, and the account mapping.

    Handles and Band ids are identities, not credentials, so they may appear in
    the report; API keys never do. Returns the resolved handles, or None.
    """
    if cfg is None:
        return None
    try:
        handles = handles_from_config(cfg)
    except HandleConfigError as e:
        rep.add("identities", "handles", FAIL, str(e))
        handles = None
    else:
        rep.add("identities", "handles", OK, ", ".join(f"{r}={h}" for r, h in handles.items()))
    uid = ciso_user_id(cfg)
    agent_ids = {str((a or {}).get("agent_id")) for a in (cfg.get("agents") or {}).values()
                 if isinstance(a, dict)}
    if uid is None:
        rep.add("identities", "humans.ciso.user_id", FAIL,
                "missing or placeholder -- the CISO's Band user id (sender_id of their "
                "messages); without it their ruling imports as 'observer'")
    elif uid in agent_ids:
        rep.add("identities", "humans.ciso.user_id", FAIL, "equals an agent_id")
    else:
        rep.add("identities", "humans.ciso.user_id", OK if _UUID.match(uid) else WARN,
                "set (format only)" if _UUID.match(uid) else UUID_NOTE)
    if handles is None:              # account mapping needs valid handles
        return None
    agents = cfg.get("agents") or {}
    primary = {_owner(handles[r]) for r, (_f, acct, _m, _t) in AGENTS.items()
               if (agents.get(r) or {}).get("account", "primary") == "primary"}
    secondary = {r: _owner(handles[r]) for r in AGENTS
                 if (agents.get(r) or {}).get("account") == "secondary"}
    problems = []
    if len(primary) > 1:
        problems.append(f"primary-account agents use different owners {sorted(primary)}")
    for r, o in secondary.items():
        if o in primary:
            problems.append(f"{r} is account 'secondary' but its handle is on the primary "
                            f"owner {o}")
    if problems:
        rep.add("identities", "account mapping", FAIL, "; ".join(problems))
    else:
        rep.add("identities", "account mapping", OK,
                f"primary {sorted(primary)}, secondary {sorted(set(secondary.values()))}")
    if primary and _owner(handles["ciso"]) not in primary:
        rep.add("identities", "humans.ciso.handle", WARN,
                f"{handles['ciso']} is not the primary account owner {sorted(primary)}")
    return handles


def check_prompt_handles(rep: PreflightReport, repo: Path,
                         handles: dict[str, str] | None) -> None:
    """Render each prompt (and the Facilitator's nudge texts) with the configured
    handles exactly as the agents will at startup; any handle left that is not
    a configured identity means mentions would reach nobody."""
    if handles is None:
        return
    targets = [(role, repo / pkg.replace(".", "/") / "prompt.md")
               for role, (_f, _a, pkg, _t) in AGENTS.items() if pkg]
    targets.append(("facilitator", repo / "scripts" / "incident_driver.py"))
    for role, path in targets:
        if not path.exists():
            continue
        raw = path.read_text(encoding="utf-8")
        rendered = render_handles(raw, handles)
        left = unresolved_handles(rendered, handles)
        if left:
            rep.add("prompts", role, FAIL, f"{path.name}: unresolved handles {', '.join(left)}")
        else:
            changed = sum(raw.count(h) for h in UPSTREAM_HANDLES.values() if h not in
                          handles.values())
            rep.add("prompts", role, OK, f"{path.name}: all handles resolve to "
                    f"agent_config.yaml ({'rendered at load time' if changed else 'as written'})")


def check_gate(rep: PreflightReport, env: Mapping[str, str], cfg: dict[str, Any] | None,
               repo: Path) -> None:
    from cyberrescue.core.gate import GATE_MODE_ENV, resolve_mode
    mode, warning = resolve_mode(env.get(GATE_MODE_ENV) or "")
    if warning:
        rep.add("gate", GATE_MODE_ENV, WARN, warning)
    elif mode.value == "shadow":
        rep.add("gate", GATE_MODE_ENV, WARN, "shadow (default): Core decisions are LOGGED but "
                "do not block the Commander; set enforce for an authorization demo")
    else:
        rep.add("gate", GATE_MODE_ENV, OK, "enforce: the Commander acts only on Core ALLOW")
    inc = env.get("CYBERRESCUE_INCIDENT")
    if inc:
        rep.add("gate", "CYBERRESCUE_INCIDENT", OK, inc)
    else:
        rep.add("gate", "CYBERRESCUE_INCIDENT", WARN if mode.value == "enforce" else OK,
                "unset: the gate binds to the most recent open incident on the target asset; "
                "set CYBERRESCUE_INCIDENT=INC-C for the demo")
    commander_id = (((cfg or {}).get("agents") or {}).get("commander") or {}).get("agent_id")
    ref = env.get("CYBERRESCUE_COMMANDER_REF") or "warroom:commander"
    if commander_id and classify_secret(str(commander_id)) == "set" \
            and ref != f"band:{commander_id}":
        rep.add("gate", "CYBERRESCUE_COMMANDER_REF", WARN,
                f"{ref!r}: gate requests will come from a different Core actor than the "
                "Commander's imported Band messages; set it to band:<commander agent_id> "
                "so the audit links them")
    else:
        rep.add("gate", "CYBERRESCUE_COMMANDER_REF", OK, ref)
    db = env.get("CYBERRESCUE_DB_PATH")
    rep.add("gate", "CYBERRESCUE_DB_PATH", OK, db or str(repo / "cyberrescue.db") + " (default)")


def check_launcher(rep: PreflightReport, repo: Path) -> None:
    script = repo / "scripts" / "run_all.ps1"
    if not script.exists():
        rep.add("launcher", "run_all.ps1", FAIL, "scripts/run_all.ps1 missing")
        return
    text = script.read_text(encoding="utf-8")
    uses_resolver = "Resolve-RepoPython" in text
    rep.add("launcher", "run_all.ps1", OK if uses_resolver else FAIL,
            "resolves .venv313 -> .venv (or -Python / CYBERRESCUE_PYTHON)" if uses_resolver
            else r"hard-codes an interpreter; expected Resolve-RepoPython")


def run_preflight(repo: Path, *, environ: Mapping[str, str] | None = None,
                  executable: str | None = None, config_path: Path | None = None,
                  import_agents: bool = True,
                  importer: Callable[[str], Any] = importlib.import_module) -> PreflightReport:
    import os
    rep = PreflightReport()
    env, env_files = effective_env(repo, os.environ if environ is None else environ)
    cfg_path = config_path or Path(env.get("AGENT_CONFIG_PATH") or repo / "agent_config.yaml")
    check_python(rep, repo, executable or sys.executable)
    check_packages(rep)
    check_credentials(rep, env, env_files)
    try:
        cfg = load_agent_config(cfg_path)
    except Exception as e:  # noqa: BLE001 -- malformed YAML is a finding, not a crash
        rep.add("agent_config", "file", FAIL, f"cannot parse {cfg_path.name}: {type(e).__name__}")
        cfg = {}
    else:
        check_agent_config(rep, cfg_path, cfg)
        check_prompt_handles(rep, repo, check_identities(rep, cfg))
    check_secret_hygiene(rep, repo)
    if import_agents:
        check_agent_imports(rep, importer, repo)
    check_gate(rep, env, cfg, repo)
    check_launcher(rep, repo)
    return rep


def render(rep: PreflightReport) -> str:
    lines = []
    section = None
    for c in rep.checks:
        if c.section != section:
            section = c.section
            lines.append(f"\n[{section}]")
        lines.append(f"  {c.status.upper():<4}  {c.name:<26} {c.detail}")
    lines.append("")
    if rep.failures:
        lines.append(f"NOT READY: {len(rep.failures)} failure(s), {len(rep.warnings)} warning(s). "
                     "Fix the FAIL lines before launching the live agents.")
    else:
        lines.append(f"READY for launch: 0 failures, {len(rep.warnings)} warning(s). "
                     "(Preflight makes no network or LLM calls; it cannot prove the "
                     "credentials are valid or that Band is reachable.)")
    return "\n".join(lines)
