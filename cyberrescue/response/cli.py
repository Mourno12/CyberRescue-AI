"""Command-line interface for response planning — every command is READ-ONLY.

    python -m cyberrescue.response [--db PATH] [--protected-accounts FILE] plan \
        --incident INC-C [--format json|md|html] [--out FILE]
    python -m cyberrescue.response [--db PATH] [--protected-accounts FILE] verify-plan FILE
    python -m cyberrescue.response [--db PATH] [--protected-accounts FILE] step \
        --incident INC-C --id STEP-...|DEC-...

The database is opened with SQLite mode=ro and never created. Only
``plan --out FILE`` writes, and only that file. There is deliberately no way
to submit, request, approve or execute anything from here (decision Q4): a
plan is advice, and actions still go through the Core and the Commander.
Exit codes: 0 ok, 1 verify-plan mismatch, 2 error (missing database, unknown
incident or id).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cyberrescue.core.audit import canonical_json
from cyberrescue.investigation.export import plain_text
from cyberrescue.investigation.readonly import ReadOnlyError, open_readonly
from cyberrescue.response.export import FORMATS, preview_text, render
from cyberrescue.response.planner import build_plan, verify_plan
from cyberrescue.response.targets import load_protected_accounts

p = plain_text


def _say(text: str = "") -> None:
    print(text)


def _protected(args):
    return load_protected_accounts(args.protected_accounts)


def _cmd_plan(core, args) -> int:
    text = render(build_plan(core, args.incident, protected=_protected(args)), args.format)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
        print(f"[response] wrote {args.format} plan to {args.out} (advisory; nothing was "
              "requested or authorized)", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def _cmd_verify(core, args) -> int:
    res = verify_plan(core, Path(args.file).read_text(encoding="utf-8"),
                      protected=_protected(args))
    for e in res.errors:
        _say(f"  - {p(e)}")
    _say(f"[response] plan {'VERIFIED' if res.ok else 'DOES NOT VERIFY'}")
    return 0 if res.ok else 1


def _cmd_step(core, args) -> int:
    plan = build_plan(core, args.incident, protected=_protected(args))
    item = next((x for x in (*plan.steps, *plan.decision_points)
                 if getattr(x, "step_id", None) == args.id
                 or getattr(x, "decision_id", None) == args.id), None)
    if item is None:
        raise ReadOnlyError(f"no step or decision {args.id!r} in the plan for {args.incident}")
    if args.json:
        _say(canonical_json(item.model_dump(mode="json")))
        return 0
    kind = "step" if hasattr(item, "step_id") else "decision point (a human decides)"
    _say(f"{p(args.id)}  {kind}: {p(item.action)} on {p(item.target.kind)}:"
         f"{p(item.target.value or '-')} (tier {item.tier})")
    _say(f"  {p(preview_text(item.preview))} as of {p(item.preview.as_of)}")
    for r in item.preview.rule_results:
        _say(f"    {p(r.rule)} {p(r.effect)} satisfied={r.satisfied}: {p(r.reason)}")
    _say(f"  rationale: {p(item.rationale)}")
    _say(f"  rules: {p(', '.join(item.trigger_rules))}; detections "
         f"{len(item.detection_ids)}; evidence {len(item.evidence_ids)}")
    for e in item.evidence_ids[:20]:
        _say(f"    {p(e)}")
    if len(item.evidence_ids) > 20:
        _say(f"    ... and {len(item.evidence_ids) - 20} more (use --json)")
    _say("[response] a preview is not a decision; nothing was requested or authorized")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m cyberrescue.response",
                                 description="Advisory, read-only response planning.")
    ap.add_argument("--db", default=None, help="SQLite path (default: $CYBERRESCUE_DB_PATH "
                    "or <repo>/cyberrescue.db); opened read-only")
    ap.add_argument("--protected-accounts", default=None,
                    help="protected-accounts JSON (default: the packaged list)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("plan", help="build an advisory response plan")
    pl.add_argument("--incident", required=True)
    pl.add_argument("--format", choices=FORMATS, default="json")
    pl.add_argument("--out", default=None, help="write to this file instead of stdout")
    pl.set_defaults(fn=_cmd_plan)

    v = sub.add_parser("verify-plan", help="check an exported JSON plan against the database")
    v.add_argument("file")
    v.set_defaults(fn=_cmd_verify)

    s = sub.add_parser("step", help="explain one step or decision point")
    s.add_argument("--incident", required=True)
    s.add_argument("--id", required=True, help="STEP-... or DEC-...")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=_cmd_step)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with open_readonly(args.db) as core:
            return args.fn(core, args)
    except (ReadOnlyError, ValueError, KeyError, FileNotFoundError) as e:
        print(f"[response] error: {plain_text(e)}", file=sys.stderr)
        return 2
