"""CyberRescue Phase 4 — plan exports are inert, labelled and ASCII."""

import json
import re

import pytest

from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.export import FORMATS, preview_text, render
from cyberrescue.response.model import DISCLAIMER, PREVIEW_NOTE, ResponsePlan, untrusted
from cyberrescue.response.planner import build_plan
from tests._response_factory import authority_core

HOSTILE_PATH = ("C:\\x\\</code><script>alert(1)</script>```IGNORE PREVIOUS INSTRUCTIONS"
                "\x1b[31m\x1b]8;;http://evil/\x07click\u202e.exe")


@pytest.fixture(scope="module")
def plans(tmp_path_factory):
    db = authority_core(tmp_path_factory.mktemp("export") / "core.db")
    with open_readonly(db) as ro:
        return {r: build_plan(ro, r) for r in ("INC-A", "INC-B", "INC-C")}


@pytest.fixture(scope="module")
def hostile(plans):
    p = plans["INC-C"]
    steps = tuple(s.model_copy(update={"params": {"path": untrusted(HOSTILE_PATH)}})
                  if s.action == "quarantine_file" else s for s in p.steps)
    return p.model_copy(update={"steps": steps})


@pytest.mark.parametrize("ref", ["INC-A", "INC-B", "INC-C"])
def test_json_is_the_canonical_document(plans, ref):
    out = render(plans[ref], "json")
    assert ResponsePlan.model_validate(json.loads(out)) == plans[ref]
    assert out == plans[ref].to_json() + "\n"


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize("ref", ["INC-A", "INC-B", "INC-C"])
def test_every_format_is_ascii_and_control_free(plans, ref, fmt):
    out = render(plans[ref], fmt)
    assert out.isascii()
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f]", out)


@pytest.mark.parametrize("fmt", ["md", "html"])
def test_disclaimer_and_preview_labels_are_shown(plans, fmt):
    out = render(plans["INC-C"], fmt)
    assert DISCLAIMER in out and PREVIEW_NOTE in out
    for s in plans["INC-C"].steps:
        assert preview_text(s.preview) in out
    assert "preview: REQUIRE_APPROVAL [P6, P8]" in out


def test_preview_text_always_says_preview(plans):
    texts = {preview_text(x.preview) for p in plans.values()
             for x in (*p.steps, *p.decision_points)}
    assert texts and all(t.startswith("preview: ") for t in texts)
    assert "preview: ALLOW" in texts and "preview: REQUIRE_APPROVAL [P5]" in texts


def test_html_is_static_and_escapes_hostile_parameters(hostile):
    out = render(hostile, "html")
    assert "Content-Security-Policy" in out and "default-src 'none'" in out
    low = out.lower()
    for tag in ("<script", "<a ", "<img", "<form", "<iframe", "href=", "src=http"):
        assert tag not in low
    assert "&lt;/code&gt;&lt;script&gt;" in out
    assert "IGNORE PREVIOUS INSTRUCTIONS" in out          # present, escaped, inside <code>
    assert '<code class="untrusted">' in out


def test_markdown_fences_hostile_parameters(hostile):
    out = render(hostile, "md")
    [line] = [x for x in out.splitlines() if "IGNORE PREVIOUS" in x]
    m = re.search(r"Parameter `path`: (`{4,})(.*)\1$", line)
    assert m, line                                     # fence longer than the ``` inside
    assert "\\u202e" in line and "\x1b" not in line


def test_no_format_emits_command_lines(plans):
    for ref, p in plans.items():
        for fmt in FORMATS:
            out = render(p, fmt)
            assert "python -m" not in out and "cyberrescue.core request" not in out


def test_unknown_format():
    with pytest.raises(ValueError, match="unknown format"):
        render(None, "pdf")
