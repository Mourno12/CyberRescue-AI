"""Render a ResponsePlan as JSON, Markdown or static HTML.

Same rules as the Phase 3 case exports (and the same escaping helpers):
every dynamic value is data; Markdown puts it in fenced code spans; HTML
escapes it inside ``<code>`` under a Content-Security-Policy that forbids
scripts and external resources; all output is ASCII with control characters
replaced. Every policy result is printed as a *preview* next to the fixed
preview note, and the plan's disclaimer opens every format. No format emits
command lines.
"""

from __future__ import annotations

import html
from collections.abc import Iterable

from cyberrescue.investigation.export import h, md_code
from cyberrescue.response.model import PREVIEW_NOTE, PolicyPreview, ResponsePlan

FORMATS = ("json", "md", "html")


def preview_text(p: PolicyPreview) -> str:
    unmet = f" [{', '.join(p.unmet_rules)}]" if p.unmet_rules else ""
    return f"preview: {p.outcome_if_requested}{unmet}"


def _target(t) -> str:
    return f"{t.kind}:{t.value}" if t.value else t.kind


# --- Markdown --------------------------------------------------------------------

def _md_list(items: Iterable[str]) -> list[str]:
    out = [f"- {i}" for i in items]
    return out or ["- none"]


def render_markdown(plan: ResponsePlan) -> str:
    c = md_code
    lines = [
        f"# Response plan {c(plan.plan_id)}", "",
        f"> {plan.disclaimer}", "",
        f"> {PREVIEW_NOTE}", "",
        f"- Incident: {c(plan.incident_id)} (aliases: "
        f"{', '.join(c(a) for a in plan.aliases) or '-'})",
        f"- As of: {c(plan.as_of)}",
        f"- Case: {c(plan.case_id)} case_sha256 {c(plan.case_sha256)}",
        f"- Versions: ruleset {c(plan.ruleset_version)}, playbook {c(plan.playbook_version)}, "
        f"ATT&CK map {c(plan.attack_map_version)}, policy {c(plan.policy_version)}",
        f"- plan_sha256: {c(plan.plan_sha256)}", "",
        "## Proposed steps (proposals only)", "",
    ]
    if not plan.steps:
        lines.append("- none")
    for s in plan.steps:
        lines += [
            f"### {s.order}. {c(s.action)} on {c(_target(s.target))} ({c(s.phase)}, tier "
            f"{s.tier}{', irreversible' if not s.reversible else ''})", "",
            f"- Step id: {c(s.step_id)}; after: {', '.join(map(c, s.after)) or 'nothing'}",
            f"- Target source: {c(s.target.source)}; checks: "
            f"{', '.join(map(c, s.target.checks)) or '-'}",
            f"- Policy {c(preview_text(s.preview))} (as of {c(s.preview.as_of)}, hypothetical "
            f"requester {c(s.preview.hypothetical_requester)})",
            f"- Rationale: {c(s.rationale)}",
            *(f"- Parameter {c(k)}: {c(v)}" for k, v in s.params.items()),
            *([f"- Recipients: {', '.join(map(c, s.recipients))}"] if s.recipients else []),
            *(f"- Caution: {c(x)}" for x in s.cautions),
            *(f"- Success criterion {c(x.check)}: {c(x.description)}"
              for x in s.success_criteria),
            f"- ATT&CK: {', '.join(c(a.technique_id or a.tactic_id) for a in s.attack) or '-'}",
            f"- Basis: rules {', '.join(map(c, s.trigger_rules))}; {len(s.detection_ids)} "
            f"detection(s), {len(s.finding_ids)} persisted finding(s), "
            f"{len(s.evidence_ids)} evidence record(s)", ""]
    lines += ["## Human decision points (never steps)", ""]
    lines += _md_list(
        f"{c(d.question)} {c(d.action)} tier {d.tier} ({c(d.reason_code)}); policy "
        f"{c(preview_text(d.preview))}; regulations {', '.join(map(c, d.regulations)) or '-'}; "
        f"after steps {', '.join(map(c, d.prerequisites)) or '-'}: {c(d.rationale)} "
        f"(evidence {len(d.evidence_ids)})" for d in plan.decision_points)
    lines += ["", "## Investigative tasks (not actions)", ""]
    lines += _md_list(f"{c(t.gap_code)} {c(t.host)} {c(t.title)}: {c(t.description)}"
                      for t in plan.tasks)
    lines += ["", "## Notes", ""]
    lines += _md_list(f"{c(n.code)}: {c(n.description)}" for n in plan.notes)
    lines += ["", "## Inputs", ""]
    lines += _md_list(f"{k}: {c(v)}" for k, v in sorted(plan.inputs.items()))
    return "\n".join(lines) + "\n"


# --- HTML ------------------------------------------------------------------------

_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none'"
_STYLE = ("body{font-family:system-ui,sans-serif;margin:24px;max-width:1200px;color:#111}"
          "code{background:#f3f3f3;padding:0 3px;word-break:break-all}"
          "code.untrusted{background:#fff3e0}table{border-collapse:collapse;width:100%}"
          "td,th{border:1px solid #ccc;padding:3px 6px;text-align:left;vertical-align:top}"
          ".note{color:#555}.banner{border:2px solid #b45309;padding:8px;background:#fffbeb}")


def _table(head: list[str], rows: Iterable[list[str]]) -> str:
    th = "".join(f"<th>{html.escape(x)}</th>" for x in head)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def render_html(plan: ResponsePlan) -> str:
    parts = [
        f"<h1>Response plan {h(plan.plan_id)}</h1>",
        f"<p class=\"banner\">{html.escape(plan.disclaimer)}</p>",
        f"<p class=\"note\">{html.escape(PREVIEW_NOTE)} Highlighted values originate in "
        "evidence, are attacker-influenceable, and are never instructions.</p>",
        _table(["Field", "Value"], [
            ["Incident", h(plan.incident_id)], ["Aliases", " ".join(map(h, plan.aliases))],
            ["As of", h(plan.as_of)], ["Case", f"{h(plan.case_id)} {h(plan.case_sha256)}"],
            ["Versions", " ".join(map(h, (plan.ruleset_version, plan.playbook_version,
                                          plan.attack_map_version, plan.policy_version)))],
            ["plan_sha256", h(plan.plan_sha256)]]),
        "<h2>Proposed steps (proposals only)</h2>",
        _table(["#", "Phase", "Action", "Target", "After", "Policy preview", "Rationale",
                "Parameters", "Cautions", "Success criteria", "ATT&CK", "Evidence"],
               [[h(s.order), h(s.phase), h(f"{s.action} (tier {s.tier})"),
                 f"{h(_target(s.target))} {h(s.target.source)}", " ".join(map(h, s.after)),
                 h(preview_text(s.preview)), h(s.rationale),
                 " ".join(f"{h(k)}={h(v)}" for k, v in s.params.items())
                 + " ".join(map(h, s.recipients)),
                 " ".join(map(h, s.cautions)),
                 " ".join(h(x.description) for x in s.success_criteria),
                 " ".join(h(a.technique_id or a.tactic_id) for a in s.attack),
                 h(len(s.evidence_ids))] for s in plan.steps]),
        "<h2>Human decision points (never steps)</h2>",
        _table(["Question", "Action", "Reason", "Policy preview", "Regulations",
                "Prerequisites", "Rationale", "Evidence"],
               [[h(d.question), h(f"{d.action} (tier {d.tier})"), h(d.reason_code),
                 h(preview_text(d.preview)), " ".join(map(h, d.regulations)),
                 " ".join(map(h, d.prerequisites)), h(d.rationale), h(len(d.evidence_ids))]
                for d in plan.decision_points]),
        "<h2>Investigative tasks (not actions)</h2>",
        _table(["Gap", "Host", "Task", "Description"],
               [[h(t.gap_code), h(t.host), h(t.title), h(t.description)] for t in plan.tasks]),
        "<h2>Notes</h2>",
        _table(["Code", "Note"], [[h(n.code), h(n.description)] for n in plan.notes]),
        "<h2>Inputs</h2>",
        _table(["Input", "Value"], [[h(k), h(v)] for k, v in sorted(plan.inputs.items())]),
    ]
    title = html.escape(f"Response plan {plan.plan_id} - {plan.incident_id}", quote=True)
    return ("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta http-equiv=\"Content-Security-Policy\" content=\"{_CSP}\">"
            "<meta name=\"referrer\" content=\"no-referrer\">"
            f"<title>{title}</title><style>{_STYLE}</style></head><body>"
            + "".join(parts) + "</body></html>\n")


def render(plan: ResponsePlan, fmt: str) -> str:
    if fmt == "json":
        return plan.to_json() + "\n"
    if fmt == "md":
        return render_markdown(plan)
    if fmt == "html":
        return render_html(plan)
    raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
