"""python -m cyberrescue.evaluation run [--scenario A] [--json] [--investigation] [--response]
                                         [--execution] [--accountability]

Runs each scenario in a temporary Core (the operational database is never
touched) and prints per-scenario metrics. Exit status 1 if any scenario has an
unexpected finding, a missed stage, a fact mismatch, (with --investigation)
a case-check mismatch, (with --response) a plan-check mismatch, or (with
--execution) an execution-check mismatch, or (with --accountability) an
accountability-check mismatch.
"""

from __future__ import annotations

import argparse
import json
import sys

from cyberrescue.evaluation.harness import run_scenario
from cyberrescue.evaluation.metrics import ScenarioEvaluation, evaluate
from cyberrescue.telemetry.catalog import CATALOG


def _frac(a: int, b: int) -> str:
    return f"{a}/{b}"


def _print(ev: ScenarioEvaluation) -> None:
    print(f"== Scenario {ev.scenario} ({ev.incident_id}) ground truth: {ev.verdict}, "
          f"{ev.events} events, {ev.malicious_events} malicious")
    print(f"   findings: {len(ev.findings)}  unexpected: {len(ev.unexpected_findings)} "
          f"{ev.unexpected_findings or ''}")
    print(f"   malicious evidence cited as support: "
          f"{_frac(ev.malicious_supported, ev.malicious_events)}"
          f"  (incl. context: {_frac(ev.malicious_cited_any, ev.malicious_events)})")
    for s in ev.stages:
        print(f"   stage {s.stage:<26} {'DETECTED' if s.detected else 'MISSED':<8} "
              f"evidence {_frac(s.supported, s.events):<6} context-only {s.context_only:<3}"
              f" type-agreement={'yes' if s.type_agreement else 'no':<3} {','.join(s.rules)}")
    for f in ev.findings:
        print(f"   finding {f.rule_id:<12} {f.finding_type:<20} {f.severity}/{f.confidence:<6} "
              f"precision {_frac(f.malicious_supporting, f.supporting)}"
              f"{'' if f.expected else '  UNEXPECTED'}")
    for rule, kind in ev.observations:
        print(f"   observation {rule:<12} {kind}")
    for fr in ev.facts:
        print(f"   fact {fr.fact:<32} {fr.status:<13} expected={fr.expected!r} "
              f"observed={fr.observed!r}")


def _cmd_run(args) -> int:
    keys = [args.scenario.upper()] if args.scenario else list(CATALOG)
    results = [evaluate(run_scenario(k)) for k in keys]
    cases = []
    if args.investigation:
        from cyberrescue.evaluation.investigation import evaluate_case, run_case
        cases = [evaluate_case(*run_case(k)) for k in keys]
    plans = []
    if args.response:
        from cyberrescue.evaluation.response import evaluate_plan, run_plan
        plans = [evaluate_plan(run_plan(k)) for k in keys]
    runs = []
    if args.execution:
        from cyberrescue.evaluation.execution import evaluate_execution, run_execution
        runs = [evaluate_execution(*run_execution(k)) for k in keys]
    acc = []
    if args.accountability:
        from cyberrescue.evaluation.accountability import (
            evaluate_accountability,
            run_accountability,
        )
        acc = [evaluate_accountability(run_accountability(k)) for k in keys]
    if args.json:
        doc: object = [r.to_dict() for r in results]
        if args.investigation or args.response or args.execution or args.accountability:
            doc = {"detection": doc}
            if args.investigation:
                doc["investigation"] = [c.to_dict() for c in cases]
            if args.response:
                doc["response"] = [x.to_dict() for x in plans]
            if args.execution:
                doc["execution"] = [x.to_dict() for x in runs]
            if args.accountability:
                doc["accountability"] = [x.to_dict() for x in acc]
        print(json.dumps(doc, sort_keys=True, indent=2))
    else:
        for r in results:
            _print(r)
        for c in cases:
            print(f"== Investigation case {c.case_id} (scenario {c.scenario})")
            for ch in c.checks:
                print(f"   check {ch.check:<30} {ch.status:<13} expected={ch.expected!r} "
                      f"observed={ch.observed!r}")
        for x in plans:
            print(f"== Response plan {x.plan_id} (scenario {x.scenario}): {x.steps} steps, "
                  f"{x.decision_points} decision points, {x.tasks} tasks")
            for ch in x.checks:
                print(f"   check {ch.check:<30} {ch.status:<13} expected={ch.expected!r} "
                      f"observed={ch.observed!r}")
        for x in runs:
            print(f"== Simulated execution (scenario {x.scenario}) - SIMULATION ONLY")
            for regime, counts in x.outcomes.items():
                shown = ", ".join(f"{k} {v}" for k, v in counts.items() if v) or "nothing"
                print(f"   {regime:<16} {shown}")
            for ch in x.checks:
                print(f"   check {ch.check:<30} {ch.status:<13} expected={ch.expected!r} "
                      f"observed={ch.observed!r}")
        for x in acc:
            print(f"== Execution accountability (scenario {x.scenario}) - SIMULATION ONLY: "
                  f"{x.recorded} recorded, {x.refused} refused, {x.replayed} on replay")
            for ch in x.checks:
                print(f"   check {ch.check:<30} {ch.status:<13} expected={ch.expected!r} "
                      f"observed={ch.observed!r}")
    bad = [r.scenario for r in results if r.unexpected_findings or r.missed_stages
           or any(f.status == "mismatch" for f in r.facts)]
    bad += [c.scenario for c in (*cases, *plans, *runs, *acc)
            if any(ch.status == "mismatch" for ch in c.checks)]
    if bad:
        print(f"[evaluation] attention needed: {', '.join(bad)}", file=sys.stderr)
    return 1 if bad else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyberrescue.evaluation",
                                description="Evaluate detection against ground truth.")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="evaluate one or all scenarios")
    r.add_argument("--scenario", default=None)
    r.add_argument("--json", action="store_true")
    r.add_argument("--investigation", action="store_true",
                   help="also evaluate the Phase 3 investigation case")
    r.add_argument("--response", action="store_true",
                   help="also evaluate the Phase 4 response plan")
    r.add_argument("--execution", action="store_true",
                   help="also evaluate the Phase 5 simulated executor")
    r.add_argument("--accountability", action="store_true",
                   help="also evaluate Phase 6 execution accountability (records)")
    r.set_defaults(fn=_cmd_run)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (KeyError, ValueError) as e:
        print(f"[evaluation] error: {e}", file=sys.stderr)
        return 2
