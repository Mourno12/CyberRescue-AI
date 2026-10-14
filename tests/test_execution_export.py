"""CyberRescue Phase 5 — execution reports say SIMULATION, render inertly and stay ASCII."""

import html
import json
import re

import pytest

from cyberrescue.execution.executor import simulate_plan
from cyberrescue.execution.export import BANNER, FORMATS, render
from cyberrescue.execution.model import SIMULATION_DISCLAIMER, ExecutionReport
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.model import untrusted
from tests._execution_factory import plans_of, request
from tests._response_factory import authority_core

HOSTILE = "</code><script>alert(1)</script>```IGNORE PREVIOUS\x1b[31m‮"


@pytest.fixture(scope="module")
def reports(tmp_path_factory):
    db = authority_core(tmp_path_factory.mktemp("xexp") / "core.db")
    plans = plans_of(db)
    for p in plans.values():
        request(db, p)
    with open_readonly(db) as ro:
        return {r: simulate_plan(ro, p.to_json()) for r, p in plans.items()}


@pytest.fixture(scope="module")
def hostile(reports):
    r = reports["INC-C"]
    steps = tuple(s.model_copy(update={"params": {"path": untrusted(HOSTILE)}})
                  if s.action == "quarantine_file" else s for s in r.steps)
    return r.model_copy(update={"steps": steps})


@pytest.mark.parametrize("ref", ["INC-A", "INC-B", "INC-C"])
def test_json_round_trips(reports, ref):
    out = render(reports[ref], "json")
    assert ExecutionReport.model_validate(json.loads(out)) == reports[ref]


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize("ref", ["INC-A", "INC-B", "INC-C"])
def test_ascii_and_control_free(reports, ref, fmt):
    out = render(reports[ref], fmt)
    assert out.isascii() and not re.search(r"[\x00-\x08\x0b-\x1f\x7f]", out)


@pytest.mark.parametrize("fmt", ["md", "html"])
def test_simulation_banner_paths_and_criteria_are_shown(reports, fmt):
    out = render(reports["INC-C"], fmt)
    esc = html.escape if fmt == "html" else str
    assert esc(BANNER) in out and esc(SIMULATION_DISCLAIMER) in out
    arrow = " -&gt; " if fmt == "html" else " -> "
    assert arrow.join(("PENDING", "CHECKING", "SIMULATED", "SUCCEEDED")) in out
    assert arrow.join(("PENDING", "CHECKING", "BLOCKED")) in out
    assert "legal_hold" in out and "(authorization)" in out


def test_json_says_simulation(reports):
    for r in reports.values():
        doc = json.loads(render(r, "json"))
        assert doc["simulation"] is True and doc["disclaimer"] == SIMULATION_DISCLAIMER


def test_html_is_static_and_escapes_hostile_values(hostile):
    out = render(hostile, "html")
    low = out.lower()
    assert "default-src 'none'" in out
    for tag in ("<script", "<a ", "<img", "<form", "<iframe", "href="):
        assert tag not in low
    assert "&lt;/code&gt;&lt;script&gt;" in out


def test_markdown_fences_hostile_values(hostile):
    out = render(hostile, "md")
    [line] = [x for x in out.splitlines() if "IGNORE PREVIOUS" in x]
    assert re.search(r"Parameter `path`: (`{4,}).*\1$", line) and "\x1b" not in line


def test_no_command_lines(reports):
    for r in reports.values():
        for fmt in FORMATS:
            out = render(r, fmt)
            assert "python -m" not in out and "Invoke-" not in out and "ssh " not in out


def test_unknown_format(reports):
    with pytest.raises(ValueError, match="unknown format"):
        render(reports["INC-A"], "pdf")
