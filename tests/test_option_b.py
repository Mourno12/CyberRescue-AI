"""Test suite for Option B: Triage creates incident rooms.

This validates:
1. Injector creates alert message correctly
2. REST API endpoints for room creation work
3. Triage's prompt correctly instructs room creation
4. Config/schema changes are consistent
"""

import json
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_injector_alert_message():
    """Test that injector can build the alert message."""
    from injector.inject_alert import build_alert_message

    content, alert = build_alert_message("INC-C")
    assert "@Triage" in content, "Alert should mention Triage"
    assert "INC-C-2026-0042" in content, "Alert should have incident ID"
    assert alert.get("incident_id") == "INC-C-2026-0042"
    print("[OK] Injector builds alert message with @Triage mention")


def test_triage_allowlist_has_create_chatroom():
    """Test that Triage's platform tools include create_chatroom."""
    import ast

    triage_main = (REPO_ROOT / "agents" / "triage" / "main.py").read_text()
    # Find the include_tools list in the features= argument
    tree = ast.parse(triage_main)
    found_create_chatroom = False

    for node in ast.walk(tree):
        if isinstance(node, ast.List):
            for elt in node.elts:
                if isinstance(elt, ast.Constant) and elt.value == "thenvoi_create_chatroom":
                    found_create_chatroom = True
                    break

    assert found_create_chatroom, "Triage allowlist must include create_chatroom"
    print("[OK] Triage allowlist includes thenvoi_create_chatroom")


def test_triage_prompt_instructs_room_creation():
    """Test that Triage's prompt instructs creating incident rooms."""
    triage_prompt = (REPO_ROOT / "agents" / "triage" / "prompt.md").read_text()
    assert "thenvoi_create_chatroom" in triage_prompt, "Prompt should mention create_chatroom"
    assert "incident war room" in triage_prompt.lower(), "Prompt should mention war room creation"
    assert "srv-db-01" in triage_prompt, "Prompt example should have asset reference"
    print("[OK] Triage prompt instructs room creation")


def test_protocol_consistency():
    """Test that protocol.md sections are consistent."""
    protocol = (REPO_ROOT / "shared" / "protocol.md").read_text(encoding="utf-8")

    # §C should say Triage creates rooms
    section_c = protocol[protocol.find("## C."):protocol.find("## D.")]
    assert "Triage creates the room" in section_c or "creates the incident room" in section_c, \
        "§C should document Triage creating rooms"

    # §E.2 should describe intake room pattern
    section_e2 = protocol[protocol.find("### E.2"):protocol.find("### E.3")]
    assert "intake" in section_e2.lower(), "§E.2 should mention intake room"
    assert "thenvoi_create_chatroom" in section_e2, "§E.2 should mention create_chatroom"

    # §E.3 should show create_chatroom in tools
    section_e3 = protocol[protocol.find("### E.3"):protocol.find("### E.4")]
    assert "create_chatroom" in section_e3, "§E.3 routing table should include create_chatroom"

    print("[OK] Protocol.md sections are internally consistent")


def test_injector_no_default_room_id_dependency():
    """Test that injector no longer depends on pre-made room ID."""
    injector_main = (REPO_ROOT / "injector" / "inject_alert.py").read_text()

    # Should not import default_room_id
    assert "from shared.config import load_agent" in injector_main, \
        "Injector should import load_agent"

    # Old: should have removed "default_room_id" import
    lines = injector_main.split('\n')
    for line in lines:
        if 'from shared.config import' in line:
            assert 'default_room_id' not in line, \
                "Injector should NOT import default_room_id anymore"
            assert 'load_agent' in line, "Injector should import load_agent"

    # Should not use --room argument anymore
    assert "--room" not in injector_main, "Injector should not accept --room arg"
    print("[OK] Injector has no dependency on pre-made room ID")


def test_rest_api_endpoints():
    """Test that the injector posts via the Band SDK RestClient human API.

    (Structure check. The injector was rewritten from a hand-rolled urllib
    client to ``thenvoi_rest.RestClient`` in commit de4356a — this guards
    against regressing to raw HTTP and confirms the human-API methods are used.)
    """
    injector = (REPO_ROOT / "injector" / "inject_alert.py").read_text()

    # Should post through the SDK RestClient, not raw urllib.
    assert "RestClient" in injector, "Should use thenvoi_rest.RestClient"
    assert "urllib" not in injector, "Should NOT hand-roll HTTP via urllib"

    # Should drive the human-API surface (create room, add participant, post).
    assert "human_api_chats.create_my_chat_room" in injector, \
        "Should create the intake room via human_api_chats.create_my_chat_room"
    assert "human_api_chats.add_participant" in injector, \
        "Should add Triage via human_api_chats.add_participant"
    assert "human_api_messages.send_my_chat_message" in injector, \
        "Should post the alert via human_api_messages.send_my_chat_message"

    print("[OK] Injector posts via RestClient human API")


def test_brief_message_mentions_human():
    """Test that Triage's BRIEF example mentions the human CISO."""
    triage_prompt = (REPO_ROOT / "agents" / "triage" / "prompt.md").read_text(encoding="utf-8")

    # Find the BRIEF JSON example - look for the opening brace and parse from there
    brief_json_start = triage_prompt.find('{\n "type": "BRIEF"')
    if brief_json_start < 0:
        brief_json_start = triage_prompt.find('{"type": "BRIEF"')

    # Find the matching closing brace
    brace_count = 0
    brief_json_end = brief_json_start
    for i in range(brief_json_start, len(triage_prompt)):
        if triage_prompt[i] == '{':
            brace_count += 1
        elif triage_prompt[i] == '}':
            brace_count -= 1
            if brace_count == 0:
                brief_json_end = i + 1
                break

    brief_json_str = triage_prompt[brief_json_start:brief_json_end]
    brief_json = json.loads(brief_json_str)
    mentions = brief_json.get("mentions", [])

    assert "@merolavtech" in mentions, f"BRIEF should mention human CISO (@merolavtech), got: {mentions}"
    print("[OK] Triage BRIEF example mentions human CISO")


def test_no_room_default_room_id_config():
    """Test that protocol doesn't require default_room_id anymore."""
    protocol = (REPO_ROOT / "shared" / "protocol.md").read_text(encoding="utf-8")

    # §C should NOT say "room.default_room_id stays blank" as a fallback
    # (it should stay blank because we're creating rooms, not using pre-made ones)
    section_c = protocol[protocol.find("## C."):protocol.find("## D.")]
    assert "blank" in section_c and "create" in section_c.lower(), \
        "§C should clarify room.default_room_id stays blank because Triage creates rooms"

    print("[OK] Protocol correctly states room.default_room_id stays blank (creation-based)")


if __name__ == "__main__":
    # Run tests with pytest if available, otherwise run directly
    try:
        pytest.main([__file__, "-v"])
    except ImportError:
        # Run tests manually
        tests = [
            test_injector_alert_message,
            test_triage_allowlist_has_create_chatroom,
            test_triage_prompt_instructs_room_creation,
            test_protocol_consistency,
            test_injector_no_default_room_id_dependency,
            test_rest_api_endpoints,
            test_brief_message_mentions_human,
            test_no_room_default_room_id_config,
        ]
        for test in tests:
            try:
                test()
            except AssertionError as e:
                print(f"[FAIL] {test.__name__}: {e}")
            except Exception as e:
                print(f"[ERROR] {test.__name__}: {e}")
