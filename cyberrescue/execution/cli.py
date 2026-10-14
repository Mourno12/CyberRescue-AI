"""Command-line interface for the SIMULATED executor.

    python -m cyberrescue.execution [--db PATH] [--protected-accounts FILE] simulate \
        --plan PLAN.json [--format json|md|html] [--out FILE] \
        [--record --recorder <system/executor actor id>]
    python -m cyberrescue.execution [--db PATH] [--protected-accounts FILE] show \
        --plan PLAN.json --id STEP-...|DEC-... [--json]
    python -m cyberrescue.execution [--db PATH] [--protected-accounts FILE] verify \
        --report REPORT.json --plan PLAN.json                 # exit 1 on mismatch

There is deliberately no command that executes anything for real, and none
that requests, approves or authorizes: authorizations come only from the
Core (``python -m cyberrescue.core request`` / ``approve``, or the Commander
gate). The database is opened mode=ro and never created. Writes happen only
with an explicit flag: ``simulate --out FILE`` writes that file, and
``simulate --record`` (Phase 6) asks the Core to record each simulated step
through ``CoreService.record_simulated_execution`` (mode ``simulated``; the
Core re-checks everything and refuses replays). Every run prints the
SIMULATION ONLY banner on stderr. Exit codes: 0 ok, 1 verify mismatch or a
refused record, 2 error (missing database, invalid plan, unknown id).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cyberrescue.core.audit import canonical_json
from cyberrescue.execution.executor import simulate_plan, verify_report
from cyberrescue.execution.export import BANNER, FORMATS, render
from cyberrescue.execution.model import ExecutionReport
from cyberrescue.execution.recorder import record_plan
from cyberrescue.execution.records import recorded_for, verify_recorded
from cyberrescue.investigation.export import plain_text
from cyberrescue.investigation.readonly import ReadOnlyError, open_readonly
from cyberrescue.response.export import preview_text
from cyberrescue.response.targets import load_protected_accounts

p = plain_text


def _say(text: str = "") -> None:
    print(text)


def _protected(args):
    return load_protected_accounts(args.protected_accounts)


def _plan_text(args) -> str:
    return Path(args.plan).read_text(encoding="utf-8")


def _cmd_simulate(core, args) -> int:
    code = 0
    if args.record:
        if not args.recorder:
            raise ValueError("--record needs --recorder <id of the Core's system/executor actor>")
        result = record_plan(args.db, _plan_text(args), recorder_actor_id=args.recorder,
                             protected=_protected(args))
        report = result.report
        for o in result.outcomes:
            print(f"[simulation] {'recorded' if o.recorded else 'NOT recorded'} "
                  f"{p(o.step_id)}: {p(o.record_id or o.reason)}", file=sys.stderr)
        print(f"[simulation] recorded {len(result.recorded)} simulated execution(s) in the "
              f"Core (mode simulated); {len(result.refused)} refused", file=sys.stderr)
        code = 1 if result.refused else 0
    else:
        report = simulate_plan(core, _plan_text(args), protected=_protected(args))
    text = render(report, args.format)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
        print(f"[simulation] wrote {args.format} report to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return code


def _cmd_show(core, args) -> int:
    report = simulate_plan(core, _plan_text(args), protected=_protected(args))
    item = next((x for x in (*report.steps, *report.decisions)
                 if getattr(x, "step_id", None) == args.id
                 or getattr(x, "decision_id", None) == args.id), None)
    if item is None:
        raise ReadOnlyError(f"no step or decision {args.id!r} in this plan")
    if args.json:
        _say(canonical_json(item.model_dump(mode="json")))
        return 0
    _say(f"{p(args.id)}  {p(item.action)} on {p(item.target.kind)}:"
         f"{p(item.target.value or '-')}  -> {item.status}"
         f"{' (' + item.block_category + ')' if item.block_category else ''}")
    _say(f"  path: {' -> '.join(item.path)}")
    _say(f"  reason: {p(item.reason)}")
    for c in getattr(item, "checks", ()):
        _say(f"  check {'PASS' if c.passed else 'FAIL'} {p(c.check)}: {p(c.detail)}")
    if item.current_policy is not None:
        _say(f"  policy now: {p(preview_text(item.current_policy))}")
    effect = getattr(item, "effect", None)
    if effect is not None:
        _say(f"  simulated effect ({'applied' if effect.applied else 'NOT applied'}): "
             f"{p(effect.description)}")
    for c in getattr(item, "criteria", ()):
        _say(f"  criterion {'MET' if c.satisfied else 'NOT MET'} {p(c.check)}: "
             f"{p(c.observed)}")
    return 0


def _cmd_verify(core, args) -> int:
    report_text = Path(args.report).read_text(encoding="utf-8")
    try:
        recorded = recorded_for(core, ExecutionReport.model_validate_json(report_text))
    except ValueError:
        recorded = []
    if recorded:                       # Phase 6: a recorded run - cross-check the Core
        res = verify_recorded(core, report_text, _plan_text(args))
        what = f"recorded run ({res.records} Core execution record(s))"
    else:
        res = verify_report(core, report_text, _plan_text(args), protected=_protected(args))
        what = "report"
    for e in res.errors:
        _say(f"  - {p(e)}")
    _say(f"[simulation] {what} {'VERIFIED' if res.ok else 'DOES NOT VERIFY'}")
    return 0 if res.ok else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m cyberrescue.execution",
                                 description="SIMULATED, read-only execution of a response plan.")
    ap.add_argument("--db", default=None, help="SQLite path (default: $CYBERRESCUE_DB_PATH "
                    "or <repo>/cyberrescue.db); opened read-only")
    ap.add_argument("--protected-accounts", default=None,
                    help="protected-accounts JSON (default: the packaged list)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("simulate", help="simulate a plan's Core-authorized steps")
    s.add_argument("--plan", required=True, help="a JSON plan from `cyberrescue.response plan`")
    s.add_argument("--format", choices=FORMATS, default="json")
    s.add_argument("--out", default=None, help="write to this file instead of stdout")
    s.add_argument("--record", action="store_true",
                   help="also record each simulated step in the Core (ACTION_EXECUTED / "
                        "ACTION_VERIFIED, mode simulated); the Core re-checks every step")
    s.add_argument("--recorder", default=None,
                   help="id of the Core's registered system/executor actor (with --record)")
    s.set_defaults(fn=_cmd_simulate)

    sh = sub.add_parser("show", help="explain one step or decision point of a simulation")
    sh.add_argument("--plan", required=True)
    sh.add_argument("--id", required=True, help="STEP-... or DEC-...")
    sh.add_argument("--json", action="store_true")
    sh.set_defaults(fn=_cmd_show)

    v = sub.add_parser("verify", help="check a JSON report against the database and plan")
    v.add_argument("--report", required=True)
    v.add_argument("--plan", required=True)
    v.set_defaults(fn=_cmd_verify)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(f"[simulation] {BANNER}", file=sys.stderr)
    try:
        with open_readonly(args.db) as core:
            return args.fn(core, args)
    except (ReadOnlyError, ValueError, KeyError, FileNotFoundError) as e:
        print(f"[simulation] error: {plain_text(e)}", file=sys.stderr)
        return 2
