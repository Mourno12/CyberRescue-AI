"""CyberRescue Phase 3 — case exports render hostile evidence inertly."""

import json
import re
from html.parser import HTMLParser

import pytest

from cyberrescue.detection.engine import detect
from cyberrescue.detection.publisher import persist
from cyberrescue.investigation.builder import build_case, verify_case
from cyberrescue.investigation.export import md_code, render
from cyberrescue.investigation.model import Case
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.telemetry.importer import import_events
from tests._detection_factory import scenario_core

SHA = "9f2c4e7a1b8d3056c4a9e1f7b2d6803a5e9c1742f8b3a6d40e2c7f9a1b3d5e6c"
PAYLOADS = ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>',
            "![p](http://evil.example/p.png)", "[click](javascript:alert(1))",
            "```\n# injected heading\n```", "| a | b |", "\x1b[31mANSI",
            "</code></td></tr></table><script>x</script>"]
RAW_ONLY = "RAWONLY-<b>marker</b>"


def xss_telemetry():
    base = {"dataset": "xss", "timestamp": "2026-06-13T14:06:40Z", "vendor": "X"}
    p = " ".join(PAYLOADS)
    return [
        base | {"event_id": "x-1", "sensor": "edr", "category": "process",
                "action": "process_start", "host": "srv-db-01", "user": PAYLOADS[1],
                "message": RAW_ONLY + p,
                "fields": {"process.executable": "C:\\ProgramData\\<script>x.exe",
                           "process.name": "<script>x.exe", "process.hash.sha256": SHA,
                           "process.command_line": p}},
        base | {"event_id": "x-2", "sensor": "edr", "category": "alert",
                "action": "edr_detection", "host": PAYLOADS[0], "message": RAW_ONLY,
                "fields": {"rule.name": p}},
        base | {"event_id": "x-3", "sensor": "web", "category": "log", "action": "http_access",
                "host": "srv-db-01", "message": RAW_ONLY,
                "fields": {"source.ip": "203.0.113.66", "url.path": PAYLOADS[3],
                           "http.response.status_code": 200, "user_agent.original": p}},
    ]


@pytest.fixture(scope="module")
def cases(tmp_path_factory):
    path = tmp_path_factory.mktemp("export") / "core.db"
    svc, col = scenario_core(path, keys=("A",))
    import_events(svc, "INC-C", xss_telemetry(), collector_id=col.id)
    det = svc.register_actor("system", "detector", "d", "detector:x")
    persist(svc, "INC-C", detect(svc, "INC-C"), detector_id=det.id)
    svc.conn.close()
    with open_readonly(path) as ro:
        yield {"plain": build_case(ro, "INC-C"),
               "raw": build_case(ro, "INC-C", include_raw=True), "path": path}


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.attrs = set(), set()

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag)
        self.attrs |= {a for a, _ in attrs}


ALLOWED_TAGS = {"html", "head", "meta", "title", "style", "body", "h1", "h2", "p", "table",
                "thead", "tbody", "tr", "th", "td", "code"}
ALLOWED_ATTRS = {"lang", "charset", "http-equiv", "content", "name", "class"}


def strip_code_spans(md: str) -> str:
    return re.sub(r"(`+)(?:(?!\1).)+?\1", "", md)


@pytest.mark.parametrize("variant", ["plain", "raw"])
def test_html_contains_only_inert_markup(cases, variant):
    out = render(cases[variant], "html")
    p = _Tags()
    p.feed(out)
    assert p.tags <= ALLOWED_TAGS, p.tags - ALLOWED_TAGS
    assert p.attrs <= ALLOWED_ATTRS, p.attrs - ALLOWED_ATTRS
    low = out.lower()
    assert "<script" not in low and "<img" not in low and "javascript:" not in \
        re.sub(r"<code[^>]*>.*?</code>", "", low, flags=re.S)
    assert "&lt;script&gt;" in out
    assert "Content-Security-Policy" in out and "default-src 'none'" in out
    assert "\x1b" not in out


@pytest.mark.parametrize("variant", ["plain", "raw"])
def test_markdown_dynamic_text_stays_in_code_spans(cases, variant):
    md = render(cases[variant], "md")
    rest = strip_code_spans(md)
    for bad in ("<script", "<img", "![", "](", "javascript:", "\x1b", "onerror"):
        assert bad not in rest, bad
    assert not any(line.startswith("# injected") for line in md.splitlines())
    assert "<script>alert(1)</script>" in md          # present, but only as data


def test_md_code_fences_survive_backticks():
    assert md_code("a`b") == "``a`b``"
    assert md_code("```x```") == "```` ```x``` ````"   # CommonMark padding
    assert md_code("`edge`") == "`` `edge` ``"
    assert md_code(None) == "-" and md_code("line1\nline2") == "`line1 \\n line2`"


def test_raw_lines_only_with_include_raw(cases):
    for fmt in ("md", "html", "json"):
        assert "RAWONLY" not in render(cases["plain"], fmt)
        assert "RAWONLY" in render(cases["raw"], fmt)
    assert "RAWONLY-&lt;b&gt;marker&lt;/b&gt;" in render(cases["raw"], "html")


def test_hostile_values_are_untrusted_in_json(cases):
    doc = json.loads(render(cases["plain"], "json"))
    assert {"untrusted": "<script>x.exe"} in [e["process"] for e in doc["timeline"]["entries"]]
    assert {"untrusted": "C:\\ProgramData\\<script>x.exe"} in \
        [n["label"] for n in doc["graph"]["nodes"]]
    assert all(set(r["raw"]) == {"untrusted"} for r in
               json.loads(render(cases["raw"], "json"))["raw_evidence"])


def test_json_export_round_trips_and_verifies(cases):
    out = render(cases["plain"], "json")
    assert Case.model_validate(json.loads(out)) == cases["plain"]
    with open_readonly(cases["path"]) as ro:
        assert verify_case(ro, out).ok
        assert verify_case(ro, render(cases["raw"], "json")).ok


def test_renderers_are_deterministic_and_ascii(cases):
    for fmt in ("json", "md", "html"):
        a, b = render(cases["plain"], fmt), render(cases["plain"], fmt)
        assert a == b and a.isascii()


def test_unknown_format(cases):
    with pytest.raises(ValueError, match="unknown format"):
        render(cases["plain"], "pdf")
