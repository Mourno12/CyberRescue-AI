"""CyberRescue Phase 7 (7-1) — external anchor key handling."""

import copy
import json
import pickle
from pathlib import Path

import pytest

from cyberrescue.core.anchor import (
    KEY_BYTES,
    KEY_FILE_ENV,
    KEY_HEADER,
    AnchorKey,
    AnchorKeyError,
    generate_key,
    load_key,
    resolve_key_path,
    write_new_key,
)
from cyberrescue.core.db import REPO_ROOT


def keyfile(tmp_path, content, name="k.key"):
    p = tmp_path / name
    p.write_bytes(content if isinstance(content, bytes) else content.encode())
    return p


def hexkey(n=KEY_BYTES):
    return bytes(range(n)).hex()             # 32 distinct bytes: strong enough, deterministic


# --- generation -------------------------------------------------------------------------------

def test_generated_keys_are_32_random_bytes():
    a, b = generate_key(), generate_key()
    assert len(a) == len(b) == 32 and a != b


def test_write_new_key_round_trips(tmp_path):
    path = write_new_key(tmp_path / "sub" / "anchor.key")
    lines = path.read_text(encoding="ascii").splitlines()
    assert lines[0] == KEY_HEADER and len(bytes.fromhex(lines[1])) == 32
    key = load_key(path)
    assert isinstance(key, AnchorKey) and len(key) == 32
    assert key == load_key(path) and key != load_key(write_new_key(tmp_path / "other.key"))


def test_existing_files_are_never_overwritten(tmp_path):
    path = write_new_key(tmp_path / "anchor.key")
    before = path.read_bytes()
    with pytest.raises(AnchorKeyError, match="refusing to overwrite"):
        write_new_key(path)
    other = keyfile(tmp_path, "not a key", "notes.txt")
    with pytest.raises(AnchorKeyError, match="refusing to overwrite"):
        write_new_key(other)
    assert path.read_bytes() == before and other.read_text() == "not a key"


# --- location ---------------------------------------------------------------------------------

@pytest.mark.parametrize("rel", ["anchor.key", "docs/anchor.key", "cyberrescue/core/x.key"])
def test_key_files_inside_the_repository_are_refused(rel, monkeypatch):
    target = REPO_ROOT / rel
    assert not target.exists()
    with pytest.raises(AnchorKeyError, match="inside the repository"):
        write_new_key(target)
    assert not target.exists()
    with pytest.raises(AnchorKeyError, match="inside the repository"):
        load_key(target)
    monkeypatch.chdir(REPO_ROOT)
    with pytest.raises(AnchorKeyError, match="inside the repository"):
        write_new_key(rel)                    # relative paths are resolved first


def test_the_repository_root_check_uses_the_given_root(tmp_path):
    with pytest.raises(AnchorKeyError, match="inside the repository"):
        write_new_key(tmp_path / "k.key", repo_root=tmp_path)


# --- resolution -------------------------------------------------------------------------------

def test_key_path_comes_from_the_flag_or_the_env_var(tmp_path, monkeypatch):
    a, b = write_new_key(tmp_path / "a.key"), write_new_key(tmp_path / "b.key")
    monkeypatch.setenv(KEY_FILE_ENV, str(a))
    assert resolve_key_path() == a and load_key() == load_key(a)
    assert resolve_key_path(b) == b                 # explicit flag wins
    monkeypatch.delenv(KEY_FILE_ENV)
    with pytest.raises(AnchorKeyError, match="no anchor key"):
        load_key()
    monkeypatch.setenv(KEY_FILE_ENV, "   ")
    with pytest.raises(AnchorKeyError, match="no anchor key"):
        load_key()


def test_a_raw_key_in_the_environment_is_not_accepted(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_FILE_ENV, hexkey())       # a key, not a path: treated as a path
    monkeypatch.chdir(tmp_path)
    with pytest.raises(AnchorKeyError, match="does not exist"):
        load_key()
    monkeypatch.chdir(REPO_ROOT)
    with pytest.raises(AnchorKeyError, match="inside the repository"):
        load_key()


# --- rejection --------------------------------------------------------------------------------

def test_missing_and_non_file_keys_are_refused(tmp_path):
    with pytest.raises(AnchorKeyError, match="does not exist"):
        load_key(tmp_path / "nope.key")
    with pytest.raises(AnchorKeyError, match="does not exist"):
        load_key(tmp_path)


def test_unreadable_keys_are_refused(tmp_path, monkeypatch):
    path = write_new_key(tmp_path / "a.key")

    def deny(self):
        raise PermissionError(f"denied: {path.read_text()}")
    monkeypatch.setattr(Path, "read_bytes", deny)
    with pytest.raises(AnchorKeyError, match="cannot be read") as e:
        load_key(path)
    assert e.value.__cause__ is None and e.value.__suppress_context__


@pytest.mark.parametrize("content", [
    "", "\n", hexkey(), f"{KEY_HEADER}\n", f"{KEY_HEADER}\nzz{hexkey()[2:]}\n",
    f"{KEY_HEADER}\n{hexkey().upper()}\n", f"{KEY_HEADER}\n{hexkey()}0\n",
    f"cyberrescue-anchor-key/2\n{hexkey()}\n", f"{KEY_HEADER}\n{hexkey()}\nextra\n",
    f" {KEY_HEADER}\n{hexkey()}\n", f"{KEY_HEADER}\n{hexkey()} \n",
    "x" * 5000, b"\xff\xfe" + hexkey().encode()])
def test_malformed_keys_are_refused(tmp_path, content):
    with pytest.raises(AnchorKeyError, match="malformed"):
        load_key(keyfile(tmp_path, content))


def test_crlf_line_endings_are_accepted(tmp_path):
    assert len(load_key(keyfile(tmp_path, f"{KEY_HEADER}\r\n{hexkey()}\r\n"))) == 32


@pytest.mark.parametrize("raw", [bytes(range(16)), b"\x00" * 32, b"\xab" * 64,
                                 bytes(range(8)) * 4])
def test_weak_keys_are_refused(tmp_path, raw):
    with pytest.raises(AnchorKeyError, match="too short|weak"):
        load_key(keyfile(tmp_path, f"{KEY_HEADER}\n{raw.hex()}\n"))
    with pytest.raises(AnchorKeyError):
        AnchorKey(raw)


def test_empty_and_non_bytes_keys_are_refused():
    for bad in (b"", "a" * 64, None):
        with pytest.raises(AnchorKeyError):
            AnchorKey(bad)


# --- non-disclosure ---------------------------------------------------------------------------

def test_the_key_is_never_printed_or_serialised(tmp_path):
    path = write_new_key(tmp_path / "a.key")
    secret = path.read_text().splitlines()[1]
    key = load_key(path)
    for text in (repr(key), str(key), f"{key}", f"{key!r}"):
        assert secret not in text and "redacted" in text
    with pytest.raises(TypeError):
        pickle.dumps(key)
    with pytest.raises(TypeError):
        copy.copy(key)
    with pytest.raises(TypeError):
        json.dumps(key)
    with pytest.raises(AttributeError):
        key.x = 1
    assert not hasattr(key, "__dict__")


def test_error_messages_never_echo_key_material(tmp_path):
    secret = generate_key().hex()
    for content in (f"{KEY_HEADER}\n{secret}\nextra\n", f"WRONG\n{secret}\n", secret,
                    f"{KEY_HEADER}\n{secret[:40]}\n"):
        with pytest.raises(AnchorKeyError) as e:
            load_key(keyfile(tmp_path, content, f"{abs(hash(content))}.key"))
        text = str(e.value) + repr(e.value)
        assert secret not in text and secret[:16] not in text
        assert e.value.__cause__ is None
