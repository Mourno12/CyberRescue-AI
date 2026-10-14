"""Render an ExecutionReport as JSON, Markdown or static HTML.

Reuses the Phase 3/4 machinery (``md_code``/``h`` escaping, ASCII-only output,
the script-free Content-Security-Policy and table helper). Every format opens
with SIMULATION ONLY and the fixed disclaimer, prints each step's full state
path, and shows success criteria as the plan's expectation next to what the
simulation observed. No format emits command lines.
"""

from __future__ import annotations

import html

from cyberrescue.execution.model import ExecutionReport
from cyberrescue.investigation.export import h, md_code
from cyberrescue.response.export import _CSP, _table, preview_text

FORMATS = ("json", "md", "html")
BANNER = "SIMULATION ONLY - nothing was executed against any real system."
_STYLE = ("body{font-family:system-ui,sans-serif;margin:24px;max-width:1200px;color:#111}"
          "code{background:#f3f3f3;padding:0 3px;word-break:break-all}"
          "code.untrusted{background:#fff3e0}table{border-collapse:collapse;width:100%}"
          "td,th{border:1px solid #ccc;padding:3px 6px;text-align:left;vertical-align:top}"
          ".banner{border:3px solid #1d4ed8;padding:8px;background:#eff6ff;font-weight:bold}")


def _auth(a) -> str:
    if a is None:
        return "none"
    return (f"request {a.request_id} ({a.binding}, by {a.requested_by_role}"
            f"{', approval ' + a.approval_id if a.approval_id else ''})")


def _target(t) -> str:
    return f"{t.kind}:{t.value}" if t.value else t.kind


def render_markdown(r: ExecutionReport) -> str:
    c = md_code
    lines = [f"# Simulated execution {c(r.run_id)}", "", f"> **{BANNER}**", "",
             f"> {r.disclaimer}", "",
             f"- Incident: {c(r.incident_id)}; as of {c(r.as_of)}",
             f"- Plan: {c(r.plan_id)} plan_sha256 {c(r.plan_sha256)}",
             f"- report_sha256: {c(r.report_sha256)}",
             f"- Summary: {', '.join(f'{k} {v}' for k, v in r.summary.items()) or 'nothing to do'}",
             "", "## Plan integrity", ""]
    lines += [f"- {'PASS' if x.passed else 'FAIL'} {c(x.check)}: {c(x.detail)}"
              for x in r.plan_integrity] or ["- none"]
    lines += ["", "## Steps", ""]
    if not r.steps:
        lines.append("- none")
    for s in r.steps:
        lines += [f"### {s.order}. {c(s.action)} on {c(_target(s.target))}: **{s.status}**"
                  f"{' (' + s.block_category + ')' if s.block_category else ''}", "",
                  f"- Path: {' -> '.join(s.path)}",
                  f"- Reason: {c(s.reason)}",
                  f"- Core authorization: {c(_auth(s.authorization))}",
                  *([f"- Policy now: {c(preview_text(s.current_policy))}"]
                    if s.current_policy else []),
                  *(f"- Parameter {c(k)}: {c(v)}" for k, v in s.params.items()),
                  *(f"- Check {'PASS' if x.passed else 'FAIL'} {c(x.check)}: {c(x.detail)}"
                    for x in s.checks),
                  *([f"- Simulated effect ({'applied' if s.effect.applied else 'NOT applied'})"
                     f": {c(s.effect.description)}"] if s.effect else []),
                  *(f"- Criterion {'MET' if x.satisfied else 'NOT MET'} {c(x.check)}: "
                    f"expected {c(x.expected)}; observed {c(x.observed)}" for x in s.criteria),
                  f"- Evidence cited by the step: {len(s.evidence_ids)}", ""]
    lines += ["## Human decision points (never simulated)", ""]
    lines += [f"- {c(d.action)} on {c(_target(d.target))}: **{d.status}**"
              f"{' (' + d.block_category + ')' if d.block_category else ''}; policy now "
              f"{c(preview_text(d.current_policy))}: {c(d.reason)}"
              for d in r.decisions] or ["- none"]
    return "\n".join(lines) + "\n"


def render_html(r: ExecutionReport) -> str:
    parts = [
        f"<h1>Simulated execution {h(r.run_id)}</h1>",
        f"<p class=\"banner\">{html.escape(BANNER)}</p>",
        f"<p>{html.escape(r.disclaimer)}</p>",
        _table(["Field", "Value"], [
            ["Incident", h(r.incident_id)], ["As of", h(r.as_of)],
            ["Plan", f"{h(r.plan_id)} {h(r.plan_sha256)}"],
            ["report_sha256", h(r.report_sha256)],
            ["Summary", " ".join(h(f"{k}={v}") for k, v in r.summary.items()) or "-"]]),
        "<h2>Plan integrity</h2>",
        _table(["Check", "Result", "Detail"],
               [[h(x.check), h("PASS" if x.passed else "FAIL"), h(x.detail)]
                for x in r.plan_integrity]),
        "<h2>Steps</h2>",
        _table(["#", "Action", "Target", "Parameters", "Status", "Path", "Reason",
                "Core authorization", "Policy now", "Simulated effect", "Success criteria"],
               [[h(s.order), h(s.action), h(_target(s.target)),
                 " ".join(f"{h(k)}={h(v)}" for k, v in s.params.items()) or "-",
                 h(s.status + (f" ({s.block_category})" if s.block_category else "")),
                 h(" -> ".join(s.path)), h(s.reason), h(_auth(s.authorization)),
                 h(preview_text(s.current_policy)) if s.current_policy else "-",
                 h(s.effect.description) if s.effect else "-",
                 " ".join(h(f"{'MET' if x.satisfied else 'NOT MET'}: {x.observed}")
                          for x in s.criteria) or "-"] for s in r.steps]),
        "<h2>Human decision points (never simulated)</h2>",
        _table(["Action", "Target", "Status", "Policy now", "Reason"],
               [[h(d.action), h(_target(d.target)),
                 h(d.status + (f" ({d.block_category})" if d.block_category else "")),
                 h(preview_text(d.current_policy)), h(d.reason)] for d in r.decisions]),
    ]
    title = html.escape(f"Simulated execution {r.run_id} - {r.incident_id}", quote=True)
    return ("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta http-equiv=\"Content-Security-Policy\" content=\"{_CSP}\">"
            "<meta name=\"referrer\" content=\"no-referrer\">"
            f"<title>{title}</title><style>{_STYLE}</style></head><body>"
            + "".join(parts) + "</body></html>\n")


def render(report: ExecutionReport, fmt: str) -> str:
    if fmt == "json":
        return report.to_json() + "\n"
    if fmt == "md":
        return render_markdown(report)
    if fmt == "html":
        return render_html(report)
    raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
