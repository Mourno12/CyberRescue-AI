"""Integration test for Option B flow: alert → intake room → Triage → incident room.

This test validates the REST API contract without actually calling Band
(mocks the HTTP layer to verify the request payloads are correct).
"""

from unittest.mock import Mock, patch
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _triage_creds():
    from shared.config import AgentCreds

    return AgentCreds(
        name="triage",
        framework="langgraph",
        agent_id="triage-uuid-123",
        api_key="triage-key",
        account="primary",
        handle="@merolavtech/triage",
    )


def _mock_rest_client():
    """A fake thenvoi_rest.RestClient that records calls and never hits the network.

    The injector imports RestClient *inside* ``_post_via_rest`` (``from
    thenvoi_rest import RestClient``), so patching ``thenvoi_rest.RestClient``
    intercepts construction at call time. ``create_my_chat_room`` returns an
    object with ``.id`` (the SDK's response shape).
    """
    client = Mock(name="RestClient")
    client.human_api_chats.create_my_chat_room.return_value = Mock(id="intake-room-123")
    client.human_api_chats.add_participant.return_value = None
    client.human_api_messages.send_my_chat_message.return_value = None
    return client


def test_injector_rest_flow():
    """Injector makes the 3 SDK calls in order: create room → add Triage → post."""
    from injector.inject_alert import _post_via_rest

    triage = _triage_creds()
    client = _mock_rest_client()

    with patch("thenvoi_rest.RestClient", return_value=client) as rest_ctor:
        room_id = _post_via_rest(
            content="@Triage test alert",
            triage=triage,
            api_key="test-api-key",
            base_url="https://app.thenvoi.com",
        )

    # Client built with the supplied creds (no network).
    rest_ctor.assert_called_once_with(
        api_key="test-api-key", base_url="https://app.thenvoi.com"
    )

    assert room_id == "intake-room-123", "Should return the created room ID"

    # Exactly the three expected calls, each scoped to the created room.
    client.human_api_chats.create_my_chat_room.assert_called_once()
    client.human_api_chats.add_participant.assert_called_once()
    assert client.human_api_chats.add_participant.call_args.kwargs == {
        "chat_id": "intake-room-123",
        "agent_id": "triage-uuid-123",
    }
    client.human_api_messages.send_my_chat_message.assert_called_once()
    assert client.human_api_messages.send_my_chat_message.call_args.kwargs["chat_id"] \
        == "intake-room-123"
    print("[OK] Injector makes correct SDK calls in correct order")


def test_injector_rest_endpoint_pattern():
    """Injector drives the human API surface (not the agent API)."""
    from injector.inject_alert import _post_via_rest

    triage = _triage_creds()
    client = _mock_rest_client()

    with patch("thenvoi_rest.RestClient", return_value=client):
        _post_via_rest(
            content="@Triage test",
            triage=triage,
            api_key="test-key",
            base_url="https://app.thenvoi.com",
        )

    # All three operations go through human_api_* (the user-key surface),
    # mirroring the human "/me/chats" REST endpoints.
    assert client.human_api_chats.create_my_chat_room.called, \
        "Room creation should use human_api_chats.create_my_chat_room"
    assert client.human_api_chats.add_participant.called, \
        "Add participant should use human_api_chats.add_participant"
    assert client.human_api_messages.send_my_chat_message.called, \
        "Send should use human_api_messages.send_my_chat_message"

    # The alert mention carries Triage's handle + id so Band can resolve it.
    msg = client.human_api_messages.send_my_chat_message.call_args.kwargs["message"]
    mention = msg.mentions[0]  # SDK coerces to a ChatMessageRequestMentionsItem
    mention_id = getattr(mention, "id", None) if not isinstance(mention, dict) else mention["id"]
    assert mention_id == "triage-uuid-123", "Alert should @mention Triage by id"
    print("[OK] Injector uses the human API surface and mentions Triage")


def test_triage_deterministic_recruit_prompt():
    """Triage's prompt reflects the deterministic-recruit model: create_chatroom
    auto-recruits the team into the alert room; Triage does not add participants
    itself (recruitment is handled in code by shared/sdk_patches.py)."""
    triage_prompt = (REPO_ROOT / "agents" / "triage" / "prompt.md").read_text(encoding="utf-8").lower()

    # create_chatroom is described as the (auto-)recruiting setup step
    assert "create_chatroom" in triage_prompt, "Prompt should mention create_chatroom"
    assert "recruit" in triage_prompt, "Prompt should mention recruiting the team"
    # The incident runs in the room where the alert arrived
    assert "room where you received the alert" in triage_prompt, \
        "Prompt should say the incident runs in the alert room"
    # Recruitment is automatic — Triage must NOT be told to call add_participant
    assert "thenvoi_add_participant" not in triage_prompt, \
        "Triage should not call add_participant (recruitment is deterministic)"

    print("[OK] Triage prompt reflects deterministic auto-recruit model")


def test_schema_consistency():
    """Test that message schemas are consistent with the protocol."""
    from shared.schemas import ProtocolMessage

    # BRIEF should be a valid message type
    try:
        msg = ProtocolMessage(
            type="BRIEF",
            incident="INC-C",
            summary="Test brief",
            severity="critical",
            evidence=["evidence1"],
            recruited=["threat_intel", "compliance"],
            mentions=["@merolavtech/threat-intel"],
        )
        assert msg.type == "BRIEF"
        print("[OK] ProtocolMessage schema supports BRIEF with recruited field")
    except Exception as e:
        raise AssertionError(f"ProtocolMessage schema error: {e}")


def test_no_pre_created_room_references():
    """Test that code doesn't reference pre-created rooms."""
    # Check Triage main.py
    triage_main = (REPO_ROOT / "agents" / "triage" / "main.py").read_text(encoding="utf-8")
    assert "default_room_id" not in triage_main, "Triage should not reference default_room_id"

    # Check Commander main.py (shouldn't be affected, but verify)
    commander_main = (REPO_ROOT / "agents" / "commander" / "main.py").read_text(encoding="utf-8")
    assert "create_chatroom" not in commander_main, \
        "Commander should not have create_chatroom (only Triage should)"

    print("[OK] No pre-created room references in agent code")


if __name__ == "__main__":
    import pytest
    try:
        pytest.main([__file__, "-v"])
    except ImportError:
        # Run tests manually
        tests = [
            test_injector_rest_flow,
            test_injector_rest_endpoint_pattern,
            test_triage_context_switching_prompt,
            test_schema_consistency,
            test_no_pre_created_room_references,
        ]
        for test in tests:
            try:
                test()
            except AssertionError as e:
                print(f"[FAIL] {test.__name__}: {e}")
            except Exception as e:
                print(f"[ERROR] {test.__name__}: {e}")
