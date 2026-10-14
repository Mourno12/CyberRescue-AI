"""CyberRescue Core — isolation from WarRoom's Band/LLM runtime."""

import subprocess
import sys
from pathlib import Path

from cyberrescue.core import db

REPO = Path(__file__).resolve().parent.parent
HEAVY = ("thenvoi", "thenvoi_rest", "langchain_openai", "langchain_core", "langgraph",
         "openai", "anthropic", "pydantic_ai")


def test_core_imports_no_band_sdk_or_llm_clients():
    code = (
        "import sys\n"
        "import cyberrescue.core, cyberrescue.core.cli, cyberrescue.core.band_import\n"
        f"heavy = {HEAVY!r}\n"
        "print(','.join(sorted({m.split('.')[0] for m in sys.modules} & set(heavy))))\n"
    )
    res = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True,
                         text=True, check=True)
    assert res.stdout.strip() == ""


def test_warroom_code_does_not_depend_on_cyberrescue():
    # Phase 1b: exactly one sanctioned integration point — the Commander's
    # action gate — and it imports the Core lazily inside a function.
    allowed = {str(Path("agents") / "commander" / "tools.py")}
    offenders = []
    for folder in ("agents", "shared", "scripts", "injector", "exporter", "quickstart"):
        for py in (REPO / folder).rglob("*.py"):
            if "cyberrescue" in py.read_text(encoding="utf-8", errors="ignore"):
                offenders.append(str(py.relative_to(REPO)))
    assert set(offenders) <= allowed, offenders
    src = (REPO / "agents" / "commander" / "tools.py").read_text(encoding="utf-8")
    top_level = [ln for ln in src.splitlines()
                 if ln.startswith(("import ", "from ")) and "cyberrescue" in ln]
    assert top_level == []


def test_db_path_comes_from_env(monkeypatch, tmp_path):
    target = tmp_path / "x" / "custom.db"
    monkeypatch.setenv("CYBERRESCUE_DB_PATH", str(target))
    assert db.default_db_path() == target
    monkeypatch.delenv("CYBERRESCUE_DB_PATH")
    assert db.default_db_path() == REPO / "cyberrescue.db"
