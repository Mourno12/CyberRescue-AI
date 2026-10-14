"""Unit tests for the Phase 4 protocol message schema (shared/schemas.py).

Pure logic — no Band, no LLM, no network. Runs with or without pytest:

    .venv/Scripts/python.exe -m tests.test_schemas
"""

from __future__ import annotations

from shared.schemas import (
    MessageType,
    ProtocolMessage,
    Severity,
    extract_block,
    extract_blocks,
)


# --- round-trip ------------------------------------------------------------

def test_minimal_message_validates():
    m = ProtocolMessage(type="FINDING", incident="INC-C", summary="ransomware active")
    assert m.type == "FINDING"  # use_enum_values -> plain str
    assert m.evidence == [] and m.severity is None


def test_render_and_reparse_roundtrip():
    m = ProtocolMessage(
        type=MessageType.VETO,
        incident="INC-C-2026-0042",
        summary="Cannot wipe srv-db-01: forensic hold.",
        regulation="GDPR-ART-33",
        decision="BLOCK wipe_host",
        evidence=["srv-db-01 holds customer_pii", "GDPR Art.33 evidence preservation"],
        deadline_utc="2026-06-16T14:07:22+00:00",
    )
    block = m.to_json_block()
    assert block.startswith("```json") and block.rstrip().endswith("```")

    text = "I am vetoing the wipe.\n\n" + block
    parsed = extract_block(text)
    assert parsed is not None
    assert parsed.type == "VETO"
    assert parsed.regulation == "GDPR-ART-33"
    assert parsed.deadline_utc == "2026-06-16T14:07:22+00:00"
    assert "srv-db-01 holds customer_pii" in parsed.evidence


# --- extraction tolerance --------------------------------------------------

def test_extract_ignores_non_protocol_json():
    # A pasted tool dump (no "type") must NOT be treated as a protocol message.
    text = (
        "Here is the tool output:\n"
        '```json\n{"asset_id": "srv-db-01", "found": true}\n```\n'
        "And my finding:\n"
        '```json\n{"type": "FINDING", "incident": "INC-C", "summary": "pii host"}\n```'
    )
    blocks = extract_blocks(text)
    assert len(blocks) == 1
    assert blocks[0].type == "FINDING"


def test_extract_skips_malformed_json():
    text = '```json\n{"type": "FINDING", "incident": ,, broken}\n```'
    assert extract_blocks(text) == []


def test_untagged_fence_still_parses():
    text = '```\n{"type": "SIGNOFF", "incident": "INC-A", "summary": "approved"}\n```'
    parsed = extract_block(text)
    assert parsed is not None and parsed.type == "SIGNOFF"


def test_severity_enum_accepts_valid_values():
    m = ProtocolMessage(type="BRIEF", incident="INC-C", summary="brief",
                        severity=Severity.CRITICAL, recruited=["threat_intel", "compliance"])
    assert m.severity == "critical"
    assert m.to_json_block().count("critical") == 1


def test_all_message_types_constructible():
    for t in MessageType:
        m = ProtocolMessage(type=t, incident="INC-X", summary=f"{t.value} msg")
        assert extract_block(m.to_json_block()).type == t.value


# --- standalone runner -----------------------------------------------------

def _run() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run())
