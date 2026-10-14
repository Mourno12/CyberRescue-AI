"""Command-line interface to the CyberRescue Core.

    python -m cyberrescue.core [--db PATH] init
    python -m cyberrescue.core seed-assets
    python -m cyberrescue.core register-actor --kind human --role ciso --name "Dana"
    python -m cyberrescue.core import-band room.json --incident INC-C --roster roster.json
    python -m cyberrescue.core request --incident INC-C --action wipe_host \
        --asset srv-db-01 --requester <actor-id> [--plan-step STEP-<12 hex>]
    python -m cyberrescue.core approve --incident INC-C --action wipe_host \
        --asset srv-db-01 --approver <actor-id> --reason "..." [--override-hold] \
        [--override-veto] [--deny] [--ttl 60]
    python -m cyberrescue.core register-actor --kind system --role collector --name "syn"
    python -m cyberrescue.core ingest-evidence events.jsonl --incident INC-C \
        --collector <actor-id>
    python -m cyberrescue.core evidence --incident INC-C [--kind network] [--host srv-db-01]
    python -m cyberrescue.core verify [--incident INC-C] [--anchor FILE [--key-file KEY]]
    python -m cyberrescue.core show --incident INC-C
    python -m cyberrescue.core anchor-keygen --out KEY_FILE
    python -m cyberrescue.core anchor --out ANCHOR_FILE [--key-file KEY]

The database defaults to ``$CYBERRESCUE_DB_PATH`` or ``<repo>/cyberrescue.db``.
``approve`` is the minimal Phase 1 human-approval path; it calls
``CoreService.grant_approval`` and is subject to all of its checks.

``request --plan-step`` (Phase 6) binds the request to one step of a Phase 4
response plan: the id is format-checked and stored as ``params.plan_step`` in
the request and its audited ACTION_PROPOSED event, on the incident's chain. It
changes nothing about the policy decision; it only says which plan step an
authorization is for (required to record kill_process / quarantine_file /
block_ip / disable_account executions).

External audit anchors (Phase 7, ``core/anchor.py``):

* ``anchor-keygen`` writes a NEW key file (refuses to overwrite, refuses paths
  inside the repository; the key is never printed);
* ``anchor`` reads every audit chain head through a READ-ONLY connection and
  writes a signed anchor file (never overwritten); it creates no audit event
  and never creates a database;
* ``verify --anchor`` prints the unchanged ``verify`` report, then compares
  the database with the authenticated anchor (growth after the anchor is
  valid; rewritten, truncated, missing or broken chains are not).

The key comes from ``--key-file`` or ``$CYBERRESCUE_ANCHOR_KEY_FILE`` only.
Exit codes: 0 verified; 1 the database does not match (or ``verify`` found
tampering); 2 malformed input, missing/invalid key, an anchor that is
malformed or fails its HMAC (altered, or a different key), or usage errors.
Without ``--anchor``, ``verify`` behaves exactly as before.
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from pathlib import Path

from cyberrescue.core import db
from cyberrescue.core.anchor import (
    KEY_FILE_ENV,
    MAX_ANCHOR_CHARS,
    AnchorError,
    AnchorFormatError,
    build_checkpoint,
    load_key,
    open_signed,
    sign_checkpoint,
    verify_checkpoint,
    write_new_key,
)
from cyberrescue.core.band_import import Roster, import_band_context
from cyberrescue.core.evidence import load_envelopes_jsonl
from cyberrescue.core.models import ApprovalDecision
from cyberrescue.core.service import ApprovalError, CoreError, CoreService


def _incident(svc: CoreService, ref: str) -> str:
    iid = svc.store.resolve_incident(ref)
    if iid is None:
        raise CoreError(f"no Core incident for {ref!r}")
    return iid


def _cmd_init(svc, args) -> int:
    print(f"[core] database ready (schema v{db.schema_version(svc.conn)})")
    return 0


def _cmd_seed(svc, args) -> int:
    n = svc.seed_assets_from_mock()
    print(f"[core] seeded {n} new asset(s); {len(svc.store.list_assets())} in inventory "
          "(provenance: simulated)")
    return 0


def _cmd_register(svc, args) -> int:
    a = svc.register_actor(args.kind, args.role, args.name or "", args.ref)
    print(f"[core] actor {a.id}  kind={a.kind.value} role={a.role} ref={a.external_ref}")
    return 0


def _cmd_import(svc, args) -> int:
    rep = import_band_context(svc, args.file, incident_ref=args.incident,
                              roster=Roster.from_file(args.roster))
    print(f"[core] {rep.incident_id}: imported {rep.imported} message(s) "
          f"({rep.protocol_valid} protocol, {rep.unstructured} unstructured, "
          f"{rep.human} human), {rep.duplicates} duplicate(s), "
          f"{rep.skipped_non_text} non-text skipped")
    return 0


PLAN_STEP_RE = re.compile(r"^(?:STEP|DEC)-[0-9a-f]{12}$")


def _plan_step(value: str) -> str:
    if not PLAN_STEP_RE.match(value):
        raise argparse.ArgumentTypeError(
            "must be a plan step or decision id: STEP-<12 hex> or DEC-<12 hex>")
    return value


def _cmd_request(svc, args) -> int:
    params = {"plan_step": args.plan_step} if args.plan_step else None
    out = svc.request_action(_incident(svc, args.incident), args.action, args.asset,
                             args.requester, params=params, source="cli")
    d = out.decision
    print(f"[core] {d.outcome.value}: {args.action} on {args.asset or '-'} "
          f"(request {out.request.id}, policy {d.policy_version})")
    for reason in d.reasons:
        print(f"  - {reason}")
    if d.approval_id:
        print(f"  used approval {d.approval_id}")
    if args.plan_step:
        print(f"  bound to plan step {args.plan_step}")
    return 0


def _cmd_approve(svc, args) -> int:
    ap = svc.grant_approval(
        _incident(svc, args.incident), action=args.action, asset_id=args.asset,
        approver_actor_id=args.approver, reason=args.reason,
        decision=ApprovalDecision.DENY if args.deny else ApprovalDecision.APPROVE,
        overrides_hold=args.override_hold, overrides_veto=args.override_veto,
        ttl_minutes=args.ttl, source="cli")
    print(f"[core] {ap.decision.value} {ap.id}: {ap.action} on {ap.asset_id or '-'} "
          f"by {ap.approver_role}, expires {ap.expires_at}")
    return 0


def _printable(value: str) -> str:
    """Chain ids come from the database: print them as ASCII without control chars."""
    return "".join(c if 32 <= ord(c) < 127 else f"\\u{ord(c):04x}" for c in str(value))


def _cmd_verify(svc, args) -> int:
    if args.anchor is None:
        return _verify_core(svc, args)
    # Phase 7: authenticate the anchor and load the key BEFORE any output, so a
    # missing key or an invalid anchor exits 2 without a partial report.
    key = load_key(args.key_file)
    text = _read_anchor(args.anchor)
    checkpoint = open_signed(text, key)
    iid = _incident(svc, args.incident) if args.incident else None
    if iid is not None and iid not in checkpoint.chains:
        raise AnchorError("the anchor does not cover that incident's chain")
    code = _verify_core(svc, args)                       # unchanged output first
    res = verify_checkpoint(svc.conn, text, key, incident=iid)
    print(f"[core] anchor {_printable(args.anchor)} (created {res.created_at}): "
          f"{'OK' if res.ok else 'MISMATCH'}")
    if not res.schema_ok:
        print(f"  - schema version is {res.current_schema_version}, the anchor recorded "
              f"{res.anchored_schema_version}")
    for c in res.chains:
        seqs = f"anchored seq {c.anchored_seq if c.anchored_seq is not None else '-'}, " \
               f"now {c.current_seq if c.current_seq is not None else '-'}"
        print(f"[core]   {_printable(c.chain)}: {c.status} ({seqs})"
              + (f" - {_printable(c.detail)}" if c.detail else ""))
    return 0 if code == 0 and res.ok else 1


def _read_anchor(path: str) -> str:
    try:
        raw = Path(path).read_bytes()
    except OSError:
        raise AnchorFormatError("the anchor file cannot be read") from None
    if len(raw) > MAX_ANCHOR_CHARS:
        raise AnchorFormatError("the anchor document is malformed: too large")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        raise AnchorFormatError("the anchor document is malformed: not ASCII") from None


def _cmd_anchor_keygen(args) -> int:
    path = write_new_key(args.out)
    print(f"[core] wrote a new anchor key to {_printable(path)} - keep it outside the "
          "repository and away from the database; it is never printed")
    return 0


def _cmd_anchor(args) -> int:
    key = load_key(args.key_file)                        # fail before touching anything
    target = Path(args.db) if args.db else db.default_db_path()
    if not target.is_file():
        raise CoreError(f"no Core database at {target} (anchor never creates one)")
    conn = sqlite3.connect(target.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        checkpoint = build_checkpoint(conn)              # read-only connection
    except sqlite3.DatabaseError:
        raise CoreError(f"{target} is not a readable Core database") from None
    finally:
        conn.close()
    if checkpoint.schema_version != db.SCHEMA_VERSION:
        # Every other core command migrates on open; an anchor of an older schema would
        # be invalidated by that migration. Same rule as the read-only layers.
        raise CoreError(f"database schema v{checkpoint.schema_version}, expected "
                        f"v{db.SCHEMA_VERSION}; run `python -m cyberrescue.core init` first")
    signed = sign_checkpoint(checkpoint, key)
    try:
        with open(args.out, "x", encoding="ascii", newline="\n") as f:
            f.write(signed)
    except FileExistsError:
        raise CoreError("refusing to overwrite an existing anchor file; choose a new path") \
            from None
    print(f"[core] anchored {len(checkpoint.chains)} chain(s) (schema "
          f"v{checkpoint.schema_version}) at {checkpoint.created_at} -> "
          f"{_printable(args.out)}")
    return 0


def _verify_core(svc, args) -> int:
    results = ({args.incident: svc.verify_audit(_incident(svc, args.incident))}
               if args.incident else svc.audit.verify_all())
    ok = True
    for chain, res in results.items():
        print(f"[core] {chain}: {'OK' if res.ok else 'TAMPERED'} ({res.checked} events)")
        for e in res.errors:
            print(f"  - {e}")
        ok &= res.ok
    # Evidence: recompute both hashes and cross-check against the audit trail.
    incidents = ([_incident(svc, args.incident)] if args.incident else
                 [r[0] for r in svc.conn.execute(
                     "SELECT DISTINCT incident_id FROM audit_events WHERE event_type = ? "
                     "ORDER BY incident_id", ("EVIDENCE_INGESTED",))])
    for iid in incidents:
        res = svc.verify_evidence(iid)
        if res.checked or res.errors:
            print(f"[core] evidence {iid}: {'OK' if res.ok else 'TAMPERED'} "
                  f"({res.checked} records)")
            for e in res.errors:
                print(f"  - {e}")
            ok &= res.ok
    return 0 if ok else 1


def _cmd_ingest_evidence(svc, args) -> int:
    envelopes = load_envelopes_jsonl(args.file)
    rep = svc.ingest_evidence_batch(args.incident, envelopes, collector_id=args.collector,
                                    source="cli")
    print(f"[core] {rep.incident_id}: ingested {len(rep.ingested)} evidence record(s), "
          f"{len(rep.duplicates)} duplicate(s)")
    return 0


def _cmd_evidence(svc, args) -> int:
    records = svc.list_evidence(args.incident, kind=args.kind, host=args.host)
    for r in records:
        print(f"{r.id}  {r.observed_at}  {r.kind.value:<8} {r.host or '-':<14} "
              f"{r.event_type:<16} {r.provenance.value}  sha256={r.content_sha256[:12]}")
    print(f"[core] {len(records)} evidence record(s)")
    return 0


def _cmd_show(svc, args) -> int:
    iid = _incident(svc, args.incident)
    inc = svc.store.get_incident(iid)
    print(f"{inc.id}  status={inc.status.value}  severity={inc.severity}  "
          f"asset={inc.primary_asset_id}  aliases={svc.store.aliases_of(iid)}")
    print(f"  recruited: {inc.recruited_roles}")
    for h in svc.store.active_holds(inc.primary_asset_id) if inc.primary_asset_id else []:
        print(f"  hold: {h.asset_id} {h.rule_ids} human_auth={h.requires_human_authorization}")
    for v in svc.store.active_vetoes(iid):
        print(f"  veto: {v.action or 'ALL tier-3'} ({v.regulation})")
    for r in svc.store.action_requests(iid):
        print(f"  action: {r.action:<20} {r.asset_id or '-':<12} {r.status.value}")
    for x in svc.store.execution_records(iid):
        print(f"  simulated execution: {x.action:<20} {x.asset_id or '-':<12} {x.outcome:<9} "
              f"request {x.action_request_id} step {x.step_id} (mode {x.mode})")
    print(f"  evidence records: {len(svc.list_evidence(iid))}")
    print(f"  audit events: {len(svc.audit.events(iid))}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m cyberrescue.core",
                                description="CyberRescue Core — deterministic IR source of truth.")
    p.add_argument("--db", default=None, help="SQLite path (default: $CYBERRESCUE_DB_PATH "
                   "or <repo>/cyberrescue.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create/upgrade the database").set_defaults(fn=_cmd_init)
    sub.add_parser("seed-assets", help="load the mock asset inventory").set_defaults(fn=_cmd_seed)

    r = sub.add_parser("register-actor", help="register an agent, human or system collector")
    r.add_argument("--kind", choices=["agent", "human", "system"], required=True)
    r.add_argument("--role", required=True)
    r.add_argument("--name", default="")
    r.add_argument("--ref", default=None, help="external ref, e.g. band:<sender_id>")
    r.set_defaults(fn=_cmd_register)

    i = sub.add_parser("import-band", help="import a saved Band room history")
    i.add_argument("file")
    i.add_argument("--incident", required=True)
    i.add_argument("--roster", required=True, help="JSON/YAML: {agents: {id: role}, "
                   "humans: {id: role}}")
    i.set_defaults(fn=_cmd_import)

    q = sub.add_parser("request", help="ask the policy engine to authorize an action")
    q.add_argument("--incident", required=True)
    q.add_argument("--action", required=True)
    q.add_argument("--asset", default=None)
    q.add_argument("--requester", required=True, help="registered actor id")
    q.add_argument("--plan-step", type=_plan_step, default=None,
                   help="bind the request to a response-plan step (STEP-... or DEC-...)")
    q.set_defaults(fn=_cmd_request)

    a = sub.add_parser("approve", help="record a human approval (or denial)")
    a.add_argument("--incident", required=True)
    a.add_argument("--action", required=True)
    a.add_argument("--asset", default=None)
    a.add_argument("--approver", required=True, help="registered HUMAN actor id")
    a.add_argument("--reason", required=True)
    a.add_argument("--deny", action="store_true")
    a.add_argument("--override-hold", action="store_true")
    a.add_argument("--override-veto", action="store_true")
    a.add_argument("--ttl", type=int, default=None, help="minutes (default from policy config)")
    a.set_defaults(fn=_cmd_approve)

    e = sub.add_parser("ingest-evidence", help="ingest evidence envelopes (JSONL, "
                       "all-or-nothing)")
    e.add_argument("file")
    e.add_argument("--incident", required=True)
    e.add_argument("--collector", required=True,
                   help="registered SYSTEM collector or human operator actor id")
    e.set_defaults(fn=_cmd_ingest_evidence)

    ev = sub.add_parser("evidence", help="list an incident's evidence")
    ev.add_argument("--incident", required=True)
    ev.add_argument("--kind", default=None)
    ev.add_argument("--host", default=None)
    ev.set_defaults(fn=_cmd_evidence)

    v = sub.add_parser("verify", help="verify audit hash chains and evidence integrity")
    v.add_argument("--incident", default=None)
    v.add_argument("--anchor", default=None,
                   help="also verify the database against this signed anchor file (Phase 7)")
    v.add_argument("--key-file", default=None,
                   help=f"anchor key file (default: ${KEY_FILE_ENV})")
    v.set_defaults(fn=_cmd_verify)

    k = sub.add_parser("anchor-keygen", help="create a new external anchor key file")
    k.add_argument("--out", required=True, help="new key file, outside the repository")
    k.set_defaults(fn=_cmd_anchor_keygen, standalone=True)

    an = sub.add_parser("anchor", help="write a signed checkpoint of every audit chain head")
    an.add_argument("--out", required=True, help="new anchor file (never overwritten)")
    an.add_argument("--key-file", default=None,
                    help=f"anchor key file (default: ${KEY_FILE_ENV})")
    an.set_defaults(fn=_cmd_anchor, standalone=True)

    s = sub.add_parser("show", help="summarise an incident")
    s.add_argument("--incident", required=True)
    s.set_defaults(fn=_cmd_show)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "standalone", False):       # Phase 7 key/anchor commands: no Core writes
        try:
            return args.fn(args)
        except (CoreError, ValueError, OSError) as e:
            print(f"[core] error: {e}", file=sys.stderr)
            return 2
    svc = CoreService.open(args.db)
    try:
        return args.fn(svc, args)
    except (CoreError, ApprovalError, PermissionError, ValueError, KeyError,
            FileNotFoundError) as e:
        print(f"[core] error: {e}", file=sys.stderr)
        return 2
    finally:
        svc.conn.close()
