"""scripts/Resolve-RepoPython.ps1 -- launcher interpreter selection.

Runs the real PowerShell helper against a fake repo whose "python.exe" files
are empty placeholders (never executed). Skipped where PowerShell is absent.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
HELPER = REPO / "scripts" / "Resolve-RepoPython.ps1"
PWSH = shutil.which("powershell") or shutil.which("pwsh")

pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell not available")


def _resolve(repo: Path, explicit: str = "", env_python: str | None = None):
    env = {k: v for k, v in os.environ.items() if k != "CYBERRESCUE_PYTHON"}
    if env_python is not None:
        env["CYBERRESCUE_PYTHON"] = env_python
    cmd = (f". '{HELPER}'; $r = Resolve-RepoPython -Repo '{repo}' -Explicit '{explicit}'; "
           "Write-Output \"$($r.Source)|$($r.Path)\"")
    p = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", cmd],
                       capture_output=True, text=True, env=env, timeout=60)
    return p.returncode, p.stdout.strip(), p.stderr


def _venv(repo: Path, name: str) -> Path:
    exe = repo / name / "Scripts" / "python.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"")
    return exe


def test_prefers_venv313_over_venv(tmp_path):
    _venv(tmp_path, ".venv")
    _venv(tmp_path, ".venv313")
    code, out, _ = _resolve(tmp_path)
    assert code == 0 and out.startswith(".venv313|") and out.endswith(r".venv313\Scripts\python.exe")


def test_falls_back_to_venv(tmp_path):
    _venv(tmp_path, ".venv")
    code, out, _ = _resolve(tmp_path)
    assert code == 0 and out.startswith(".venv|")


def test_env_and_explicit_override_in_order(tmp_path):
    _venv(tmp_path, ".venv313")
    env_py = _venv(tmp_path, "envpy")
    explicit = _venv(tmp_path, "explicit")
    assert _resolve(tmp_path, env_python=str(env_py))[1].startswith("CYBERRESCUE_PYTHON|")
    assert _resolve(tmp_path, str(explicit), str(env_py))[1].startswith("-Python parameter|")


def test_missing_explicit_or_env_python_is_an_error_not_a_fallback(tmp_path):
    _venv(tmp_path, ".venv313")
    code, out, err = _resolve(tmp_path, str(tmp_path / "nope.exe"))
    assert code != 0 and ".venv313" not in out and "not found" in err
    code, out, err = _resolve(tmp_path, env_python=str(tmp_path / "nope.exe"))
    assert code != 0 and "CYBERRESCUE_PYTHON" in err


def test_no_venv_at_all_is_an_error(tmp_path):
    code, _, err = _resolve(tmp_path)
    assert code != 0 and "No repository Python" in err
