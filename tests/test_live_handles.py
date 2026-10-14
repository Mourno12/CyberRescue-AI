"""Runtime Band-handle configuration (shared/config.py) and identity checks.

Upstream prompts and Facilitator texts are kept verbatim; handles are rendered
from agent_config.yaml at load time. All identities below are SYNTHETIC.
"""

import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from cyberrescue.live.preflight import FAIL, OK, WARN, PreflightReport, check_identities
from cyberrescue.live.roster import RosterError, build_roster
from shared.config import (
    UPSTREAM_HANDLES,
    HandleConfigError,
    ciso_user_id,
    handles_from_config,
    load_handles,
    render_handles,
    render_prompt,
    unresolved_handles,
)
from tests.test_live_preflight import _config

REPO = Path(__file__).resolve().parent.parent
PROMPTS = [REPO / "agents" / r / "prompt.md"
           for r in ("triage", "threat_intel", "compliance", "commander")]
H = {"triage": "@acme/triage", "threat_intel": "@acme/threat-intel",
     "compliance": "@counsel/compliance", "commander": "@acme/commander",
     "facilitator": "@acme/facilitator", "ciso": "@acme"}


# --- handles_from_config --------------------------------------------------------------

def test_handles_from_a_complete_config():
    assert handles_from_config(_config()) == H


@pytest.mark.parametrize("override,needle", [
    ({"triage": {"handle": ""}}, "agents.triage.handle"),
    ({"commander": {"handle": "@youraccount/commander"}}, "agents.commander.handle"),
    ({"threat_intel": {"handle": "acme/threat-intel"}}, "agents.threat_intel.handle"),
    ({"compliance": {"handle": "@counsel"}}, "agents.compliance.handle"),
    ({"ciso": {"handle": "@acme/ciso"}}, "humans.ciso.handle"),
    ({"ciso": {"handle": "@youraccount"}}, "humans.ciso.handle"),
    ({"facilitator": {"handle": "@acme/triage"}}, "share one handle"),
])
def test_bad_handles_are_named(override, needle):
    with pytest.raises(HandleConfigError, match=re.escape(needle)):
        handles_from_config(_config(**override))


def test_missing_ciso_section_is_reported():
    cfg = _config()
    del cfg["humans"]
    with pytest.raises(HandleConfigError, match="humans.ciso is missing.*agent_config.yaml.example"):
        handles_from_config(cfg)


def test_ciso_user_id_placeholder_is_none():
    assert ciso_user_id(_config()) == "human-ciso-1"
    assert ciso_user_id(_config(ciso={"user_id": "REPLACE_WITH_CISO_BAND_USER_ID"})) is None
    cfg = _config()
    del cfg["humans"]
    assert ciso_user_id(cfg) is None


# --- rendering ------------------------------------------------------------------------

@pytest.mark.parametrize("prompt", PROMPTS, ids=lambda p: p.parent.name)
def test_every_upstream_prompt_renders_to_configured_handles_only(prompt):
    raw = prompt.read_text(encoding="utf-8")
    assert "merolavtech" in raw                       # upstream text kept verbatim
    out = render_handles(raw, H)
    assert "merolavtech" not in out
    assert unresolved_handles(out, H) == []
    assert "@acme/commander" in out or prompt.parent.name == "commander"


def test_ciso_handle_does_not_clobber_longer_handles_or_emails():
    text = ("CISO `@merolavtech`, compliance @merolavtechnologies/compliance, "
            "commander @merolavtech/commander. mail ops@merolavtech.com")
    out = render_handles(text, H)
    assert out == ("CISO `@acme`, compliance @counsel/compliance, "
                   "commander @acme/commander. mail ops@merolavtech.com")


def test_rendering_with_upstream_handles_is_identity():
    up = dict(UPSTREAM_HANDLES)
    for p in PROMPTS:
        raw = p.read_text(encoding="utf-8")
        assert render_handles(raw, up) == raw


def test_render_prompt_fails_closed(tmp_path):
    cfg_path = tmp_path / "agent_config.yaml"
    cfg_path.write_text(yaml.safe_dump(_config()), encoding="utf-8")
    good = tmp_path / "prompt.md"
    good.write_text("ask `@merolavtech/commander`, escalate to `@merolavtech`", encoding="utf-8")
    assert render_prompt(good, cfg_path) == "ask `@acme/commander`, escalate to `@acme`"
    bad = tmp_path / "bad.md"
    bad.write_text("ask @stranger/bot", encoding="utf-8")
    with pytest.raises(HandleConfigError, match="@stranger/bot"):
        render_prompt(bad, cfg_path)
    with pytest.raises(FileNotFoundError):
        render_prompt(good, tmp_path / "missing.yaml")
    cfg_path.write_text(yaml.safe_dump(_config(triage={"handle": ""})), encoding="utf-8")
    with pytest.raises(HandleConfigError):
        load_handles(cfg_path)


def test_agent_mains_load_prompts_through_the_renderer():
    for p in PROMPTS:
        main = (p.parent / "main.py").read_text(encoding="utf-8")
        assert "render_prompt(PROMPT_PATH)" in main
        assert "PROMPT_PATH.read_text" not in main


# --- Facilitator driver and injector -----------------------------------------------------

def _driver():
    sys.path.insert(0, str(REPO / "scripts"))
    import incident_driver
    return incident_driver


def test_driver_nudges_render_to_configured_handles():
    d = _driver()
    asks = [d.decide_nudge([d.ParsedMsg(role=None, is_human=False, type="BRIEF")]).ask,
            d.decide_nudge([d.ParsedMsg(role="commander", is_human=False,
                                        type="SIGNOFF_REQUEST")]).ask]
    for ask in asks:
        out = render_handles(ask, H)
        assert "merolavtech" not in out and unresolved_handles(out, H) == []
    assert "@acme/commander" in render_handles(asks[0], H)


def test_driver_mentions_only_the_configured_ciso():
    d = _driver()
    parts = [SimpleNamespace(type="User", id="someone-else", handle="@other", name="Other"),
             SimpleNamespace(type="User", id="human-ciso-1", handle=None, name="CISO")]
    client = SimpleNamespace(agent_api_participants=SimpleNamespace(
        list_agent_chat_participants=lambda chat_id: SimpleNamespace(data=parts)))
    hm = d._human_mention(client, "room", "@acme", "human-ciso-1")
    assert hm == {"id": "human-ciso-1", "handle": "acme", "name": "CISO"}
    assert d._human_mention(client, "room", "@acme", "absent") is None


def test_injector_requires_a_configured_triage_handle_before_any_network_call():
    from injector.inject_alert import _post_via_rest
    with pytest.raises(ValueError, match="agents.triage.handle"):
        _post_via_rest("alert", SimpleNamespace(handle="", agent_id="id"), "k", "http://x.invalid")


# --- identity checks (preflight) and roster ------------------------------------------------

def _ident(cfg):
    rep = PreflightReport()
    check_identities(rep, cfg)
    return {c.name: c for c in rep.checks}


def test_identities_ok_for_a_complete_config():
    c = _ident(_config(ciso={"user_id": "45101ead-d0e6-4dff-aba3-6aabb9298a42"}))
    assert {k: v.status for k, v in c.items()} == {
        "handles": OK, "humans.ciso.user_id": OK, "account mapping": OK}


def test_non_uuid_ciso_id_warns_but_does_not_fail():
    c = _ident(_config())                     # "human-ciso-1": unfamiliar, not a placeholder
    assert c["humans.ciso.user_id"].status == WARN and "not a UUID" in c["humans.ciso.user_id"].detail


def test_missing_ciso_user_id_fails():
    assert _ident(_config(ciso={"user_id": ""}))["humans.ciso.user_id"].status == FAIL
    assert _ident(_config(ciso={"user_id": "id-cmd"}))["humans.ciso.user_id"].status == FAIL


def test_invalid_account_mappings_fail():
    c = _ident(_config(compliance={"handle": "@acme/compliance"}))   # secondary on primary owner
    assert c["account mapping"].status == FAIL and "secondary" in c["account mapping"].detail
    c = _ident(_config(threat_intel={"handle": "@other/threat-intel"}))
    assert c["account mapping"].status == FAIL and "different owners" in c["account mapping"].detail


def test_ciso_on_another_account_warns():
    assert _ident(_config(ciso={"handle": "@someoneelse"}))["humans.ciso.handle"].status == WARN


def test_identity_report_never_contains_api_keys():
    text = " ".join(c.detail for c in _ident(_config()).values())
    assert "KEY-SYNTH" not in text


def test_roster_takes_the_ciso_from_config_and_requires_it():
    r = build_roster(_config())
    assert r["humans"] == {"human-ciso-1": "ciso"}
    with pytest.raises(RosterError, match="humans.ciso.user_id"):
        build_roster(_config(ciso={"user_id": ""}))
    assert build_roster(_config(ciso={"user_id": ""}), require_ciso=False)["humans"] == {}
    with pytest.raises(RosterError, match="already mapped"):
        build_roster(_config(), {"human-ciso-1": "dpo"})
