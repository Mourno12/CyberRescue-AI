"""cyberrescue.live.preflight -- offline readiness check (no network, no LLM).

All configuration here is SYNTHETIC (fake ids/keys written to tmp dirs). The
agent-import section is exercised with an injected importer (MOCKED) except in
the one test that imports the real agent modules from this repository.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from cyberrescue.live.preflight import (
    FAIL,
    OK,
    WARN,
    PreflightReport,
    check_agent_imports,
    check_launcher,
    classify_secret,
    render,
    run_preflight,
)

REPO = Path(__file__).resolve().parent.parent

SECRET_OPENAI = "sk-SYNTHETIC-openai-value-7f3a"
SECRET_ANTHROPIC = "sk-ant-SYNTHETIC-anthropic-value-91bd"


def _config(**overrides):
    cfg = {"agents": {
        "triage": {"account": "primary", "framework": "langgraph", "handle": "@acme/triage",
                   "agent_id": "id-triage", "api_key": "KEY-SYNTH-triage-0001"},
        "threat_intel": {"account": "primary", "framework": "langgraph",
                         "handle": "@acme/threat-intel", "agent_id": "id-ti",
                         "api_key": "KEY-SYNTH-ti-0002"},
        "compliance": {"account": "secondary", "framework": "pydantic_ai",
                       "handle": "@counsel/compliance", "agent_id": "id-comp",
                       "api_key": "KEY-SYNTH-comp-0003"},
        "commander": {"account": "primary", "framework": "anthropic",
                      "handle": "@acme/commander", "agent_id": "id-cmd",
                      "api_key": "KEY-SYNTH-cmd-0004"},
        "facilitator": {"account": "primary", "framework": "none",
                        "handle": "@acme/facilitator", "agent_id": "id-fac",
                        "api_key": "KEY-SYNTH-fac-0005"},
    }, "humans": {"ciso": {"handle": "@acme", "user_id": "human-ciso-1"}},
       "room": {"default_room_id": ""}}
    for role, fields in overrides.items():
        (cfg["humans"] if role == "ciso" else cfg["agents"])[role].update(fields)
    return cfg


@pytest.fixture
def fake_repo(tmp_path):
    (tmp_path / "scripts").mkdir()
    shutil.copy(REPO / "scripts" / "run_all.ps1", tmp_path / "scripts" / "run_all.ps1")
    return tmp_path


def _write(repo, cfg=None, env_local=None):
    if cfg is not None:
        (repo / "agent_config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    if env_local is not None:
        (repo / ".env.local").write_text(env_local, encoding="utf-8")


def _run(repo, environ=None, **kw):
    return run_preflight(repo, environ=environ or {}, import_agents=False, **kw)


def _by(rep, section, name):
    return next(c for c in rep.checks if c.section == section and c.name == name)


# --- secret classification ------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (None, "missing"), ("", "missing"), ("   ", "missing"),
    ("sk-...", "placeholder"), ("sk-ant-...", "placeholder"),
    ("REPLACE_WITH_TRIAGE_API_KEY", "placeholder"), ("sk-", "placeholder"),
    (SECRET_OPENAI, "set"),
])
def test_classify_secret(value, expected):
    assert classify_secret(value) == expected


# --- configuration validation ---------------------------------------------------

def test_unconfigured_repo_is_not_ready(fake_repo):
    rep = _run(fake_repo)
    assert not rep.ok()
    assert _by(rep, "credentials", "OPENAI_API_KEY").status == FAIL
    assert _by(rep, "credentials", "ANTHROPIC_API_KEY").status == FAIL
    assert _by(rep, "agent_config", "file").status == FAIL


def test_complete_synthetic_config_is_ready(fake_repo):
    _write(fake_repo, _config(), f"OPENAI_API_KEY={SECRET_OPENAI}\n"
                                 f"ANTHROPIC_API_KEY={SECRET_ANTHROPIC}\n")
    rep = _run(fake_repo)
    bad = [c for c in rep.failures if c.section not in ("secrets",)]
    assert bad == [], bad
    for role in ("triage", "threat_intel", "compliance", "commander", "facilitator"):
        c = _by(rep, "agent_config", role)       # synthetic ids are not UUIDs: format warning
        assert c.status == WARN and "not a UUID" in c.detail


def test_uuid_shaped_ids_pass_format_checks_only(fake_repo):
    import uuid
    ids = {r: str(uuid.UUID(int=i + 1)) for i, r in enumerate(
        ("triage", "threat_intel", "compliance", "commander", "facilitator"))}
    cfg = _config(**{r: {"agent_id": v} for r, v in ids.items()},
                  ciso={"user_id": str(uuid.UUID(int=99))})
    _write(fake_repo, cfg, f"OPENAI_API_KEY={SECRET_OPENAI}\nANTHROPIC_API_KEY={SECRET_ANTHROPIC}\n")
    rep = _run(fake_repo)
    for role in ids:
        assert _by(rep, "agent_config", role).status == OK
    assert _by(rep, "identities", "humans.ciso.user_id").detail == "set (format only)"
    assert "cannot prove the credentials are valid" in render(rep)   # format != working


def test_example_files_are_detected_as_placeholders(fake_repo):
    shutil.copy(REPO / "agent_config.yaml.example", fake_repo / "agent_config.yaml")
    shutil.copy(REPO / ".env.example", fake_repo / ".env")
    rep = _run(fake_repo)
    assert _by(rep, "credentials", "OPENAI_API_KEY").detail.startswith("placeholder")
    assert _by(rep, "credentials", "ANTHROPIC_API_KEY").detail.startswith("placeholder")
    for role in ("triage", "threat_intel", "compliance", "commander", "facilitator"):
        c = _by(rep, "agent_config", role)
        assert c.status == FAIL and "placeholder" in c.detail
        assert f"agents.{role}.handle" in _by(rep, "identities", "handles").detail
    assert "humans.ciso.handle" in _by(rep, "identities", "handles").detail


def test_env_local_overrides_env_and_process(fake_repo):
    _write(fake_repo, _config())
    (fake_repo / ".env").write_text("OPENAI_API_KEY=sk-...\n", encoding="utf-8")
    (fake_repo / ".env.local").write_text(f"OPENAI_API_KEY={SECRET_OPENAI}\n", encoding="utf-8")
    rep = _run(fake_repo, environ={"OPENAI_API_KEY": ""})
    assert _by(rep, "credentials", "OPENAI_API_KEY").status == OK


def test_duplicate_ids_wrong_framework_and_account_are_reported(fake_repo):
    cfg = _config(threat_intel={"agent_id": "id-triage", "api_key": "KEY-SYNTH-triage-0001",
                                "framework": "openai"},
                  compliance={"account": "primary"})
    _write(fake_repo, cfg)
    rep = _run(fake_repo)
    ti = _by(rep, "agent_config", "threat_intel")
    assert ti.status == FAIL
    assert "agent_id duplicates triage" in ti.detail and "api_key duplicates" in ti.detail
    assert "framework 'openai'" in ti.detail
    comp = _by(rep, "agent_config", "compliance")
    assert comp.status == WARN and "secondary" in comp.detail


def test_missing_role_entry_fails(fake_repo):
    cfg = _config()
    del cfg["agents"]["facilitator"]
    _write(fake_repo, cfg)
    assert _by(_run(fake_repo), "agent_config", "facilitator").status == FAIL


def test_malformed_yaml_is_a_failure_not_a_crash(fake_repo):
    (fake_repo / "agent_config.yaml").write_text("agents: [unclosed\n", encoding="utf-8")
    rep = _run(fake_repo)
    assert _by(rep, "agent_config", "file").status == FAIL


def test_compliance_model_must_be_a_pydantic_ai_string(fake_repo):
    rep = _run(fake_repo, environ={"COMPLIANCE_MODEL": "gpt-4o"})
    assert _by(rep, "models", "COMPLIANCE_MODEL").status == FAIL


# --- prompt handles vs agent_config ----------------------------------------------

def _copy_prompts(repo):
    for role in ("triage", "threat_intel", "compliance", "commander"):
        d = repo / "agents" / role
        d.mkdir(parents=True)
        shutil.copy(REPO / "agents" / role / "prompt.md", d / "prompt.md")


def test_upstream_prompt_handles_render_to_configured_accounts(fake_repo):
    _copy_prompts(fake_repo)          # the real prompts (upstream handles, unedited)
    _write(fake_repo, _config())      # synthetic config: @acme/... + @counsel/compliance
    rep = _run(fake_repo)
    for role in ("triage", "threat_intel", "compliance", "commander"):
        c = _by(rep, "prompts", role)
        assert c.status == OK and "rendered at load time" in c.detail


def test_prompt_naming_an_unconfigured_identity_fails(fake_repo):
    _copy_prompts(fake_repo)
    p = fake_repo / "agents" / "commander" / "prompt.md"
    p.write_text(p.read_text(encoding="utf-8") + "\nAlso ping `@stranger/bot`.\n",
                 encoding="utf-8")
    _write(fake_repo, _config())
    c = _by(_run(fake_repo), "prompts", "commander")
    assert c.status == FAIL and "@stranger/bot" in c.detail


def test_prompts_matching_config_handles_pass(fake_repo):
    import re
    _copy_prompts(fake_repo)
    text = "".join((REPO / "agents" / r / "prompt.md").read_text(encoding="utf-8")
                   for r in ("triage", "threat_intel", "compliance", "commander"))
    used = {f"@{o}/{s}".rstrip(".") for o, s in
            re.findall(r"@([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", text)}
    by_slug = {h.split("/")[1]: h for h in used}   # Compliance is on a second account
    slugs = {"triage": "triage", "threat_intel": "threat-intel", "compliance": "compliance",
             "commander": "commander", "facilitator": "facilitator"}
    cfg = _config(**{role: {"handle": by_slug[slug]} for role, slug in slugs.items()})
    _write(fake_repo, cfg)
    rep = _run(fake_repo)
    for role in ("triage", "threat_intel", "compliance", "commander"):
        assert _by(rep, "prompts", role).status == OK


# --- secrets never leak --------------------------------------------------------

def test_no_secret_value_appears_in_any_output(fake_repo):
    _write(fake_repo, _config(), f"OPENAI_API_KEY={SECRET_OPENAI}\n"
                                 f"ANTHROPIC_API_KEY={SECRET_ANTHROPIC}\n")
    rep = _run(fake_repo, environ={"OPENAI_BASE_URL": "https://SYNTH-endpoint.invalid/v1"})
    text = render(rep) + json.dumps(rep.to_dict())
    for secret in (SECRET_OPENAI, SECRET_ANTHROPIC, "KEY-SYNTH", "SYNTH-endpoint",
                   SECRET_OPENAI[:8] + "SYN"):
        assert secret not in text


def test_preflight_does_not_modify_process_environment(fake_repo, monkeypatch):
    import os
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    _write(fake_repo, _config(), f"OPENAI_API_KEY={SECRET_OPENAI}\n")
    run_preflight(fake_repo, import_agents=False)
    assert "OPENAI_API_KEY" not in os.environ


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_tracked_secret_file_fails(fake_repo):
    _write(fake_repo, _config())
    git = ["git", "-C", str(fake_repo), "-c", "user.email=t@example.invalid", "-c", "user.name=t"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "agent_config.yaml"], check=True)
    rep = _run(fake_repo)
    assert _by(rep, "secrets", "tracked secret files").status == FAIL
    assert _by(rep, "secrets", "agent_config.yaml").status == FAIL  # not ignored either


def test_real_repository_tracks_and_ignores_secrets_correctly():
    rep = PreflightReport()
    from cyberrescue.live.preflight import check_secret_hygiene
    check_secret_hygiene(rep, REPO)
    assert all(c.status != FAIL for c in rep.checks), rep.checks


# --- gate settings ----------------------------------------------------------------

def test_gate_defaults_warn_that_shadow_does_not_enforce(fake_repo):
    rep = _run(fake_repo)
    assert _by(rep, "gate", "CYBERRESCUE_GATE_MODE").status == WARN
    assert _by(rep, "gate", "CYBERRESCUE_GATE_MODE").detail.startswith("shadow")


def test_gate_typo_never_reports_enforce(fake_repo):
    rep = _run(fake_repo, environ={"CYBERRESCUE_GATE_MODE": "enforced"})
    c = _by(rep, "gate", "CYBERRESCUE_GATE_MODE")
    assert c.status == WARN and "shadow" in c.detail


def test_enforce_without_incident_and_mismatched_commander_ref_warn(fake_repo):
    _write(fake_repo, _config())
    rep = _run(fake_repo, environ={"CYBERRESCUE_GATE_MODE": "enforce"})
    assert _by(rep, "gate", "CYBERRESCUE_GATE_MODE").status == OK
    assert _by(rep, "gate", "CYBERRESCUE_INCIDENT").status == WARN
    assert _by(rep, "gate", "CYBERRESCUE_COMMANDER_REF").status == WARN
    rep = _run(fake_repo, environ={"CYBERRESCUE_GATE_MODE": "enforce",
                                   "CYBERRESCUE_INCIDENT": "INC-C",
                                   "CYBERRESCUE_COMMANDER_REF": "band:id-cmd"})
    assert _by(rep, "gate", "CYBERRESCUE_INCIDENT").status == OK
    assert _by(rep, "gate", "CYBERRESCUE_COMMANDER_REF").status == OK


# --- agent import / initialization ----------------------------------------------------

def test_agent_import_failure_is_reported_never_raised():
    def broken(name):  # MOCKED importer
        raise ImportError(f"synthetic failure importing {name}")
    rep = PreflightReport()
    check_agent_imports(rep, importer=broken)
    roles = {c.name: c for c in rep.checks}
    assert set(roles) == {"triage", "threat_intel", "compliance", "commander"}
    assert all(c.status == FAIL and "synthetic failure" in c.detail for c in roles.values())


def test_real_agent_modules_and_facilitator_import_without_network():
    # Imports the REAL agent mains (Band SDK + adapters) and builds their tool
    # lists; never constructs an LLM client or connects to Band.
    pytest.importorskip("thenvoi")
    rep = PreflightReport()
    check_agent_imports(rep, repo=REPO)
    assert {c.name: c.status for c in rep.checks} == {
        "triage": OK, "threat_intel": OK, "compliance": OK, "commander": OK, "facilitator": OK}


# --- launcher ---------------------------------------------------------------------

def test_real_launcher_uses_the_resolver_not_a_hardcoded_venv():
    rep = PreflightReport()
    check_launcher(rep, REPO)
    assert rep.checks[0].status == OK
    text = (REPO / "scripts" / "run_all.ps1").read_text(encoding="utf-8")
    assert 'Join-Path $Repo ".venv\\Scripts\\python.exe"' not in text


def test_launcher_without_resolver_fails(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "run_all.ps1").write_text(
        '$Python = Join-Path $Repo ".venv\\Scripts\\python.exe"\n', encoding="utf-8")
    rep = PreflightReport()
    check_launcher(rep, tmp_path)
    assert rep.checks[0].status == FAIL


def test_cli_exit_codes(fake_repo, monkeypatch):
    from cyberrescue.live import cli
    monkeypatch.setattr(cli, "REPO_ROOT", fake_repo)
    assert cli.main(["preflight", "--no-import"]) == 1
    _write(fake_repo, _config(), f"OPENAI_API_KEY={SECRET_OPENAI}\n"
                                 f"ANTHROPIC_API_KEY={SECRET_ANTHROPIC}\n")
    monkeypatch.setattr("cyberrescue.live.preflight.check_secret_hygiene",
                        lambda rep, repo: None)   # fake repo is not a git checkout
    assert cli.main(["preflight", "--no-import"]) == 0
    assert cli.main(["preflight", "--no-import", "--strict"]) == 1   # shadow-mode warning
