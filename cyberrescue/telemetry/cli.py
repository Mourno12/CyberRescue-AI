"""Command-line interface for synthetic telemetry scenarios.

    python -m cyberrescue.telemetry list
    python -m cyberrescue.telemetry generate [--root DIR]
    python -m cyberrescue.telemetry check [--root DIR]          # exit 1 on any difference
    python -m cyberrescue.telemetry show --scenario A [--root DIR]
    python -m cyberrescue.telemetry [--db PATH] open-incident --scenario A
    python -m cyberrescue.telemetry [--db PATH] ingest --scenario A --collector <actor-id>
    python -m cyberrescue.telemetry [--db PATH] ingest --file events.jsonl \
        --incident INC-C --collector <actor-id>

``open-incident`` is an explicit operator step: it opens the scenario's
*existing* WarRoom incident in the Core from its mock alert
(``shared/mock_env/alerts``), exactly as an analyst would. Ingestion never
opens, binds or changes an incident. No command prints ground truth.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

from cyberrescue.core.service import ApprovalError, CoreError, CoreService
from cyberrescue.telemetry.adapter import load_telemetry_jsonl
from cyberrescue.telemetry.catalog import CATALOG, scenario_info, telemetry_path
from cyberrescue.telemetry.importer import import_file, import_scenario
from cyberrescue.telemetry.schema import TelemetryError


def _cmd_list(args) -> int:
    for info in CATALOG.values():
        p = telemetry_path(info.key, args.root)
        n = len(load_telemetry_jsonl(p)) if p.is_file() else 0
        print(f"{info.key}  {info.dataset:<11} {info.incident_alias} ({info.incident_id})  "
              f"{n:>4} events  {info.title}")
    return 0


def _cmd_generate(args) -> int:
    from cyberrescue.telemetry import datasets          # generators: offline tooling only
    for p in datasets.write(args.root):
        print(f"[telemetry] wrote {p}")
    return 0


def _cmd_check(args) -> int:
    from cyberrescue.telemetry import datasets
    problems = datasets.check(args.root)
    for p in problems:
        print(f"[telemetry] {p}")
    print(f"[telemetry] datasets {'DIFFER' if problems else 'OK (byte-identical)'}")
    return 1 if problems else 0


def _cmd_show(args) -> int:
    info = scenario_info(args.scenario)
    events = load_telemetry_jsonl(telemetry_path(info.key, args.root))
    print(f"scenario {info.key} ({info.dataset}) -> {info.incident_alias} "
          f"({info.incident_id}): {info.title}")
    if events:
        print(f"  {len(events)} events, {events[0].timestamp} .. {events[-1].timestamp}")
    for label, counter in (("category", Counter(e.category.value for e in events)),
                           ("sensor", Counter(e.sensor for e in events)),
                           ("host", Counter(e.host or "-" for e in events))):
        print(f"  by {label}: " + ", ".join(f"{k}={v}" for k, v in sorted(counter.items())))
    return 0


def _cmd_open_incident(args) -> int:
    from shared.mock_data import load_alert
    info = scenario_info(args.scenario)
    svc = _svc(args)
    try:
        existing = svc.store.resolve_incident(info.incident_alias)
        if existing:
            print(f"[telemetry] {existing} already open in the Core (status "
                  f"{svc.store.get_incident(existing).status.value}); nothing changed")
            return 0
        alert = load_alert(info.incident_alias)
        if svc.store.get_asset(alert["asset_id"]) is None:
            n = svc.seed_assets_from_mock()
            print(f"[telemetry] seeded {n} mock asset(s) (provenance: simulated)")
        inc = svc.open_incident(alert["incident_id"], title=alert["title"],
                                category=alert.get("category_hint"),
                                severity=alert.get("severity_hint"),
                                primary_asset_id=alert["asset_id"], source="cli")
        print(f"[telemetry] opened {inc.id} ({info.incident_alias}) on {inc.primary_asset_id}")
        return 0
    finally:
        svc.conn.close()


def _cmd_ingest(args) -> int:
    svc = _svc(args)
    try:
        if args.scenario:
            if args.incident:
                raise CoreError("a scenario is bound to its catalogue incident; "
                                "use --file to ingest into another incident")
            rep = import_scenario(svc, args.scenario, collector_id=args.collector,
                                  root=args.root)
        else:
            if not args.incident:
                raise CoreError("--file needs --incident")
            rep = import_file(svc, args.file, args.incident, collector_id=args.collector)
        print(f"[telemetry] {rep.incident_id}: {rep.events} event(s) -> "
              f"{len(rep.ingested)} evidence record(s) ingested, "
              f"{len(rep.duplicates)} duplicate(s)")
        return 0
    finally:
        svc.conn.close()


def _svc(args) -> CoreService:
    return CoreService.open(args.db)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m cyberrescue.telemetry",
                                description="CyberRescue synthetic telemetry scenarios.")
    p.add_argument("--db", default=None, help="SQLite path (default: $CYBERRESCUE_DB_PATH "
                   "or <repo>/cyberrescue.db)")
    p.add_argument("--root", default=None, help="dataset root (default: "
                   "datasets/cyberrescue/synthetic)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list scenarios and their incidents").set_defaults(fn=_cmd_list)
    sub.add_parser("generate", help="regenerate the committed datasets deterministically"
                   ).set_defaults(fn=_cmd_generate)
    sub.add_parser("check", help="verify datasets are byte-identical to a fresh render"
                   ).set_defaults(fn=_cmd_check)

    s = sub.add_parser("show", help="summarise a scenario's telemetry (no ground truth)")
    s.add_argument("--scenario", required=True)
    s.set_defaults(fn=_cmd_show)

    o = sub.add_parser("open-incident", help="open the scenario's existing incident in the "
                       "Core from its mock alert (operator step)")
    o.add_argument("--scenario", required=True)
    o.set_defaults(fn=_cmd_open_incident)

    i = sub.add_parser("ingest", help="ingest telemetry as evidence (all-or-nothing)")
    src = i.add_mutually_exclusive_group(required=True)
    src.add_argument("--scenario")
    src.add_argument("--file")
    i.add_argument("--incident", default=None, help="target incident (with --file only)")
    i.add_argument("--collector", required=True,
                   help="registered SYSTEM collector or human operator actor id")
    i.set_defaults(fn=_cmd_ingest)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (CoreError, ApprovalError, PermissionError, TelemetryError, ValueError, KeyError,
            FileNotFoundError) as e:
        print(f"[telemetry] error: {e}", file=sys.stderr)
        return 2
