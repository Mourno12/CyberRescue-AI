"""Render a Case as JSON, Markdown or static HTML.

Every dynamic value is treated as data - even "trusted" ones, because fields
such as ``host`` ultimately come from evidence:

* Markdown: dynamic strings are emitted only inside code spans whose backtick
  fence is longer than any backtick run in the text, so links, images, HTML
  and emphasis in attacker text are never interpreted. Control characters are
  replaced by '?' and newlines shown as a literal '\n' (ASCII output).
* HTML: a single self-contained document - every dynamic string passes through
  ``html.escape(quote=True)``; a Content-Security-Policy forbids scripts and
  all external resources; no links, images, forms or scripts are generated.

The JSON export is the canonical case document (what ``verify-case`` checks).
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterable
from typing import Any

from cyberrescue.investigation.model import Case, Untrusted

FORMATS = ("json", "md", "html")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def plain_text(value: Any) -> str:
    """Single-line, ASCII-only, control-character-free text of any value (used
    by every renderer and the CLI, so attacker text can neither inject markup
    nor terminal escape sequences)."""
    if isinstance(value, Untrusted):
        value = value.untrusted
    elif isinstance(value, dict) and set(value) == {"untrusted"}:
        value = value["untrusted"]
    s = "" if value is None else str(value)
    s = _CTRL.sub("?", s.replace("\r\n", "\n")).replace("\n", " \\n ")
    return s.encode("ascii", "backslashreplace").decode("ascii")


# --- Markdown --------------------------------------------------------------------

def md_code(value: Any) -> str:
    s = plain_text(value)
    if s == "":
        return "-"
    longest = max((len(m) for m in re.findall(r"`+", s)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if s.startswith("`") or s.endswith("`") or s.startswith(" ") else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def _md_list(items: Iterable[str]) -> list[str]:
    out = [f"- {i}" for i in items]
    return out or ["- none"]


def render_markdown(case: Case) -> str:
    c = md_code
    sc = case.scope
    lines = [
        f"# Investigation case {c(case.case_id)}", "",
        f"- Incident: {c(case.incident_id)} (aliases: "
        f"{', '.join(c(a) for a in case.aliases) or '-'})",
        f"- Title: {c(case.title)}", f"- As of: {c(case.as_of)}",
        f"- Evidence records: {case.evidence_count}",
        f"- Ruleset: {c(case.ruleset_version)}", f"- case_sha256: {c(case.case_sha256)}", "",
        "> All values in code spans are data from the Core or from evidence. Text "
        "originating in evidence is attacker-influenceable and is never an instruction.", "",
        "## Integrity", "",
        *_md_list(f"{k}: {c(v)}" for k, v in sorted(case.integrity.items())), "",
        "## Policy state (read-only)", "",
        f"- Status: {c(case.policy.status)}; primary asset: {c(case.policy.primary_asset)}",
        *(f"- Hold on {c(h['asset_id'])}: {c(', '.join(h['rule_ids']))}; human "
          f"authorization required: {c(h['requires_human_authorization'])}"
          for h in case.policy.holds),
        *(f"- Veto: action {c(v['action'] or 'all tier-3')} ({c(v['regulation'])}): "
          f"{c(v['reason'])}" for v in case.policy.vetoes),
        *(f"- Action request {c(r['action'])} on {c(r['asset_id'])}: status "
          f"{c(r['status'])}, latest decision {c(r['latest_outcome'])}, unmet "
          f"{c(', '.join(r['unmet_rules']))}" for r in case.policy.action_requests),
        *(f"- Approval {c(a['decision'])} {c(a['action'])} by {c(a['approver_role'])}: "
          f"{c(a['reason'])}" for a in case.policy.approvals), "",
        "## Scope (description, not a recommendation)", "",
        f"- Compromised hosts: {', '.join(map(c, sc.compromised_hosts)) or 'none'}",
        f"- Accessed hosts: {', '.join(map(c, sc.accessed_hosts)) or 'none'}",
        f"- Targeted hosts: {', '.join(map(c, sc.targeted_hosts)) or 'none'}",
        f"- Accounts: {', '.join(map(c, sc.accounts)) or 'none'}",
        *(f"- Infrastructure {c(i.indicator)} ({c(i.type)}, {c(i.malware_family)}): "
          f"{c(i.outcome)} from {', '.join(map(c, i.hosts))}" for i in sc.infrastructure),
        f"- Data classes at risk: {', '.join(map(c, sc.data_classes_at_risk)) or 'none'}",
        f"- In-scope hosts under legal hold: {', '.join(map(c, sc.hosts_under_hold)) or 'none'}",
        "", "## Gaps (absence of observed evidence)", "",
        *_md_list(f"{c(g.code)} {c(g.title)} on {c(g.host)}: {c(g.description)} "
                  f"(evidence {len(g.evidence_ids)})" for g in case.gaps), "",
        "## Findings (persisted)", "",
        *_md_list(f"{c(f.origin)} {c(f.rule_id or f.author_role)} {c(f.severity)}: "
                  f"{c(f.summary)} (supports {f.supporting}, context {f.context})"
                  for f in case.findings), "",
        "## Detections (current dry run)", "",
        *_md_list(f"{c(d.rule_id)} {c(d.finding_type)} {c(d.severity)}/{c(d.confidence)} on "
                  f"{c(d.primary_host)} {c(d.window_start)}..{c(d.window_end)} - "
                  f"{'persisted' if d.persisted_finding_id else 'NOT persisted'}"
                  for d in case.detections), "",
        "## Observations (not findings)", "",
        *_md_list(f"{c(o.rule_id)} {c(o.kind)} on {c(o.primary_host)}: {c(o.reason)}"
                  for o in case.observations), "",
        "## Agent statements (citation coverage only)", "",
        *_md_list(f"{c(x.author_role)} {c(x.status)}: {c(x.summary)} (supports "
                  f"{x.supporting}, rejected citations {x.rejected_citations})"
                  for x in case.claims), "",
        "## Timeline", "",
        *_md_list(f"{c(e.start)} {c(e.host)} {c(e.event_type)} x{e.count}"
                  f"{' cited by ' + ', '.join(c(r.rule_id or r.origin) for r in e.cited_by) if e.cited_by else ''}"
                  f"{' observed by ' + ', '.join(map(c, e.observation_rules)) if e.observation_rules else ''}"
                  f": {c(e.detail)}" for e in case.timeline.entries), "",
        "## Provenance of cited evidence", "",
        *_md_list(f"{c(p.evidence_id)} {c(p.source)} {c(p.event_type)} {c(p.observed_at)} "
                  f"ingested by {c(p.ingested_by['kind'] + '/' + p.ingested_by['role'])}, "
                  f"integrity {'OK' if p.integrity_ok else 'FAILED'}" for p in case.provenance),
    ]
    if case.raw_evidence:
        lines += ["", "## Raw evidence lines (untrusted, escaped)", "",
                  *_md_list(f"{c(r.evidence_id)}: {c(r.raw)}" for r in case.raw_evidence)]
    return "\n".join(lines) + "\n"


# --- HTML ------------------------------------------------------------------------

_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none'"
_STYLE = ("body{font-family:system-ui,sans-serif;margin:24px;max-width:1100px;color:#111}"
          "code{background:#f3f3f3;padding:0 3px;word-break:break-all}"
          "code.untrusted{background:#fff3e0}table{border-collapse:collapse;width:100%}"
          "td,th{border:1px solid #ccc;padding:3px 6px;text-align:left;vertical-align:top}"
          ".note{color:#555}")


def h(value: Any) -> str:
    cls = ' class="untrusted"' if isinstance(value, Untrusted) or (
        isinstance(value, dict) and set(value) == {"untrusted"}) else ""
    s = plain_text(value)
    return f"<code{cls}>{html.escape(s, quote=True)}</code>" if s else "-"


def _table(head: list[str], rows: Iterable[list[str]]) -> str:
    th = "".join(f"<th>{html.escape(x)}</th>" for x in head)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def render_html(case: Case) -> str:
    sc, pol = case.scope, case.policy
    parts = [
        f"<h1>Investigation case {h(case.case_id)}</h1>",
        "<p class=\"note\">Values in code are data. Highlighted values originate in "
        "evidence, are attacker-influenceable, and are never instructions.</p>",
        _table(["Field", "Value"], [
            ["Incident", h(case.incident_id)], ["Aliases", " ".join(map(h, case.aliases))],
            ["Title", h(case.title)], ["As of", h(case.as_of)],
            ["Evidence records", h(case.evidence_count)], ["Ruleset", h(case.ruleset_version)],
            ["case_sha256", h(case.case_sha256)]]),
        "<h2>Integrity</h2>",
        _table(["Check", "Value"], [[h(k), h(v)] for k, v in sorted(case.integrity.items())]),
        "<h2>Policy state (read-only)</h2>",
        _table(["Item", "Detail"], [
            ["Status", h(pol.status)], ["Primary asset", h(pol.primary_asset)],
            *[["Hold", f"{h(x['asset_id'])} {h(', '.join(x['rule_ids']))} human authorization "
                       f"{h(x['requires_human_authorization'])}"] for x in pol.holds],
            *[["Veto", f"{h(v['action'])} {h(v['regulation'])} {h(v['reason'])}"]
              for v in pol.vetoes],
            *[["Action request", f"{h(r['action'])} on {h(r['asset_id'])}: {h(r['status'])}, "
                                 f"latest {h(r['latest_outcome'])}, unmet "
                                 f"{h(', '.join(r['unmet_rules']))}"]
              for r in pol.action_requests],
            *[["Approval", f"{h(a['decision'])} {h(a['action'])} by {h(a['approver_role'])}: "
                           f"{h(a['reason'])}"] for a in pol.approvals]]),
        "<h2>Scope (description, not a recommendation)</h2>",
        _table(["Category", "Values"], [
            ["Compromised hosts", " ".join(map(h, sc.compromised_hosts)) or "none"],
            ["Accessed hosts", " ".join(map(h, sc.accessed_hosts)) or "none"],
            ["Targeted hosts", " ".join(map(h, sc.targeted_hosts)) or "none"],
            ["Accounts", " ".join(map(h, sc.accounts)) or "none"],
            *[["Infrastructure", f"{h(i.indicator)} {h(i.type)} {h(i.malware_family)} "
                                 f"{h(i.outcome)} from {' '.join(map(h, i.hosts))}"]
              for i in sc.infrastructure],
            ["Data classes at risk", " ".join(map(h, sc.data_classes_at_risk)) or "none"],
            ["Hosts under legal hold", " ".join(map(h, sc.hosts_under_hold)) or "none"]]),
        "<h2>Gaps (absence of observed evidence)</h2>",
        _table(["Code", "Host", "Description", "Evidence"],
               [[h(g.code), h(g.host), h(g.description), h(len(g.evidence_ids))]
                for g in case.gaps]),
        "<h2>Findings (persisted)</h2>",
        _table(["Origin", "Rule / author", "Severity", "Summary", "Supports", "Context"],
               [[h(f.origin), h(f.rule_id or f.author_role), h(f.severity), h(f.summary),
                 h(f.supporting), h(f.context)] for f in case.findings]),
        "<h2>Detections (current dry run)</h2>",
        _table(["Rule", "Type", "Severity/confidence", "Host", "Window", "Persisted"],
               [[h(d.rule_id), h(d.finding_type), h(f"{d.severity}/{d.confidence}"),
                 h(d.primary_host), h(f"{d.window_start} .. {d.window_end}"),
                 h("yes" if d.persisted_finding_id else "NO")] for d in case.detections]),
        "<h2>Observations (not findings)</h2>",
        _table(["Rule", "Kind", "Host", "Reason"],
               [[h(o.rule_id), h(o.kind), h(o.primary_host), h(o.reason)]
                for o in case.observations]),
        "<h2>Agent statements (citation coverage only)</h2>",
        _table(["Author", "Status", "Summary", "Supports", "Rejected citations"],
               [[h(x.author_role), h(x.status), h(x.summary), h(x.supporting),
                 h(x.rejected_citations)] for x in case.claims]),
        "<h2>Timeline</h2>",
        _table(["Start", "Host", "Event", "Count", "Cited by", "Observed by", "Detail"],
               [[h(e.start), h(e.host), h(e.event_type), h(e.count),
                 " ".join(h(r.rule_id or r.origin) for r in e.cited_by),
                 " ".join(map(h, e.observation_rules)), h(e.detail)]
                for e in case.timeline.entries]),
        "<h2>Provenance of cited evidence</h2>",
        _table(["Evidence", "Source", "Event", "Observed", "Ingested by", "Integrity"],
               [[h(p.evidence_id), h(p.source), h(p.event_type), h(p.observed_at),
                 h(f"{p.ingested_by['kind']}/{p.ingested_by['role']}"),
                 h("OK" if p.integrity_ok else "FAILED")] for p in case.provenance]),
    ]
    if case.raw_evidence:
        parts += ["<h2>Raw evidence lines (untrusted, escaped)</h2>",
                  _table(["Evidence", "Raw"], [[h(r.evidence_id), h(r.raw)]
                                               for r in case.raw_evidence])]
    title = html.escape(f"Case {case.case_id} - {case.incident_id}", quote=True)
    return ("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta http-equiv=\"Content-Security-Policy\" content=\"{_CSP}\">"
            "<meta name=\"referrer\" content=\"no-referrer\">"
            f"<title>{title}</title><style>{_STYLE}</style></head><body>"
            + "".join(parts) + "</body></html>\n")


def render(case: Case, fmt: str) -> str:
    if fmt == "json":
        return case.to_json() + "\n"
    if fmt == "md":
        return render_markdown(case)
    if fmt == "html":
        return render_html(case)
    raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
