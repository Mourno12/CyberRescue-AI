"""``python -m cyberrescue.live`` -- live-runtime preparation commands.

    preflight   [--json] [--strict] [--no-import]      offline; exit 0 ready / 1 not ready
    roster      --out FILE [--human <band-user-id>=<role> ...]   CISO from agent_config.yaml
    export-band --room ID --out FILE                   READ-ONLY Band network access
    sync        --room ID --incident INC-C [...]       READ-ONLY Band polling -> Core import
    verify-sync --export F --log F --incident INC-C    read-only consistency check, no network
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from cyberrescue.core.db import REPO_ROOT


def _cmd_preflight(args) -> int:
    from cyberrescue.live.preflight import render, run_preflight
    rep = run_preflight(REPO_ROOT, import_agents=not args.no_import)
    print(json.dumps(rep.to_dict(), indent=2) if args.json else render(rep))
    return 0 if rep.ok(strict=args.strict) else 1


def _agent_config() -> dict:
    import os

    from cyberrescue.live.preflight import effective_env, load_agent_config
    env, _ = effective_env(REPO_ROOT, os.environ)
    cfg_path = Path(env.get("AGENT_CONFIG_PATH") or REPO_ROOT / "agent_config.yaml")
    cfg = load_agent_config(cfg_path)
    if cfg is None:
        raise ValueError(f"{cfg_path} not found")
    return cfg


class RuntimePathError(ValueError):
    """A runtime artifact (database, log, lock, roster, export) would be written
    inside the repository, where it could be committed by accident."""


def inside_repo(path: Path, repo: Path | None = None) -> bool:
    """True if ``path`` resolves inside the repository (case/separator
    normalised, ``..`` and symlinks resolved) -- same rule as the anchor-key check."""
    root = os.path.normcase(str((repo or REPO_ROOT).resolve()))
    p = os.path.normcase(str(Path(path).resolve()))
    return p == root or p.startswith(root.rstrip(os.sep) + os.sep)


def require_outside_repo(path: Path, what: str) -> Path:
    if inside_repo(path):
        raise RuntimePathError(f"{what} {path} resolves inside the repository; use a run "
                               "folder outside it (e.g. %TEMP%\\cyberrescue-live-<timestamp>)")
    return Path(path)


def _cmd_roster(args) -> int:
    from cyberrescue.live.roster import build_roster, parse_human, write_roster
    require_outside_repo(Path(args.out), "roster file")
    roster = build_roster(_agent_config(), dict(parse_human(h) for h in args.human))
    write_roster(Path(args.out), roster)
    print(f"[live] wrote roster ({len(roster['agents'])} agents, {len(roster['humans'])} "
          f"human(s) incl. the CISO from humans.ciso.user_id) to {args.out}")
    return 0


def _cmd_export_band(args) -> int:
    from cyberrescue.live.band_export import collect_room, real_clients, write_export
    require_outside_repo(Path(args.out), "export file")
    clients, skipped = real_clients()
    if not clients:
        print("[live] no usable agent credentials in agent_config.yaml", file=sys.stderr)
        return 2
    doc = collect_room(clients, args.room)
    doc["views_skipped_no_credentials"] = skipped
    write_export(Path(args.out), doc)
    failed = [r for r, v in doc["views"].items() if not v.get("ok")]
    print(f"[live] exported {doc['message_count']} message(s) from room {args.room} "
          f"({len(clients) - len(failed)}/{len(clients)} agent views read) -> {args.out}")
    print(f"[live] message types: {doc['message_types']}")
    if failed or skipped:
        print(f"[live] WARNING: incomplete union -- failed views {failed}, "
              f"no credentials for {skipped}", file=sys.stderr)
    return 0 if doc["message_count"] and not failed else 1


def _load_roster(args):
    from cyberrescue.core.band_import import Roster
    from cyberrescue.live.roster import build_roster
    if args.roster:
        return Roster.from_file(args.roster)
    return Roster.from_mapping(build_roster(_agent_config()))


def _cmd_sync(args) -> int:
    from cyberrescue.core.db import default_db_path
    from cyberrescue.core.service import CoreService
    from cyberrescue.live.band_export import collect_room, real_clients
    from cyberrescue.live.sync import EXIT_CONFIG, LiveSync, SyncSettings
    settings = SyncSettings(
        room_id=args.room, incident_ref=args.incident, interval=args.interval,
        max_polls=1 if args.once else args.max_polls, max_minutes=args.max_minutes,
        settle_seconds=args.settle, max_consecutive_errors=args.max_errors,
        stop_when_terminal=not args.keep_running_after_terminal,
        db_lock_attempts=args.db_lock_attempts, db_lock_timeout=args.db_lock_timeout)
    settings.validate()
    db = require_outside_repo(Path(default_db_path()), "Core database "
                              "(set CYBERRESCUE_DB_PATH)")
    log = require_outside_repo(
        Path(args.log) if args.log else db.with_name(f"live_sync_{args.room[:8]}.jsonl"),
        "sync log")
    lock = db.with_name(db.name + ".live-sync.lock")
    roster = _load_roster(args)
    clients, skipped = real_clients()
    if not clients or skipped:
        print(f"[sync] refusing to start: no usable credentials for {skipped or 'any agent'} "
              "-- every agent view is needed for a complete transcript", file=sys.stderr)
        return EXIT_CONFIG
    print(f"[sync] Core database: {db}")
    sync = LiveSync(settings, roster, open_core=lambda: CoreService.open(db),
                    collect=lambda: collect_room(clients, args.room), log_path=log,
                    lock_path=lock)
    return sync.run().exit_code


def _cmd_verify_sync(args) -> int:
    from cyberrescue.core.db import default_db_path
    from cyberrescue.live.verify import verify_sync
    db = Path(args.db) if args.db else Path(default_db_path())
    chk = verify_sync(db=db, export=Path(args.export), log=Path(args.log),
                      incident_ref=args.incident)
    for k, v in chk.facts.items():
        print(f"[verify-sync] {k}: {v}")
    for p in chk.problems:
        print(f"[verify-sync] PROBLEM: {p}")
    print(f"[verify-sync] {'CONSISTENT' if chk.ok else 'NOT CONSISTENT'} "
          f"({len(chk.problems)} problem(s))")
    return 0 if chk.ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m cyberrescue.live",
                                description="Live four-agent runtime: preflight and capture.")
    sub = p.add_subparsers(dest="cmd", required=True)
    pf = sub.add_parser("preflight", help="offline readiness check (no network, no LLM)")
    pf.add_argument("--json", action="store_true")
    pf.add_argument("--strict", action="store_true", help="warnings also fail")
    pf.add_argument("--no-import", action="store_true",
                    help="skip importing the agent modules")
    pf.set_defaults(fn=_cmd_preflight)
    ro = sub.add_parser("roster", help="write the Band-id -> role roster for core import-band")
    ro.add_argument("--out", required=True)
    ro.add_argument("--human", action="append", default=[],
                    help="<band-user-id>=<role>, e.g. the CISO (repeatable)")
    ro.set_defaults(fn=_cmd_roster)
    ex = sub.add_parser("export-band", help="READ-ONLY: export a Band room as import JSON")
    ex.add_argument("--room", required=True)
    ex.add_argument("--out", required=True)
    ex.set_defaults(fn=_cmd_export_band)
    sy = sub.add_parser("sync", help="READ-ONLY Band polling -> idempotent Core import "
                        "(never approves, requests or executes anything)")
    sy.add_argument("--room", required=True)
    sy.add_argument("--incident", required=True, help="Core incident id or alias, e.g. INC-C")
    sy.add_argument("--roster", default=None,
                    help="roster file (default: built from agent_config.yaml)")
    sy.add_argument("--interval", type=float, default=10.0, help="seconds between polls (2-600)")
    sy.add_argument("--max-polls", type=int, default=360, help="stop after N polls (<=10000)")
    sy.add_argument("--max-minutes", type=float, default=60.0, help="stop after M minutes (<=240)")
    sy.add_argument("--settle", type=float, default=5.0,
                    help="import only messages older than this many seconds (0-120)")
    sy.add_argument("--max-errors", type=int, default=3,
                    help="halt after N consecutive failed polls (1-20)")
    sy.add_argument("--db-lock-attempts", type=int, default=5,
                    help="attempts per poll while SQLite is locked (1-20)")
    sy.add_argument("--db-lock-timeout", type=float, default=30.0,
                    help="seconds per poll across those attempts (<=300)")
    sy.add_argument("--once", action="store_true", help="a single poll")
    sy.add_argument("--keep-running-after-terminal", action="store_true")
    sy.add_argument("--log", default=None, help="JSONL sync log (default: next to the DB)")
    sy.set_defaults(fn=_cmd_sync)
    vs = sub.add_parser("verify-sync", help="read-only: cross-check export, sync log and Core")
    vs.add_argument("--export", required=True, help="export-band JSON")
    vs.add_argument("--log", required=True, help="sync JSONL log")
    vs.add_argument("--incident", required=True)
    vs.add_argument("--db", default=None, help="Core DB (default: $CYBERRESCUE_DB_PATH)")
    vs.set_defaults(fn=_cmd_verify_sync)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (ValueError, OSError) as e:
        print(f"[live] error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 -- CLI boundary: never a silent traceback/exit 0
        print(f"[live] unexpected error: {type(e).__name__}: {str(e)[:300]}", file=sys.stderr)
        return 1
