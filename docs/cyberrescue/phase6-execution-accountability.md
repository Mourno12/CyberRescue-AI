# CyberRescue — Phase 6: Execution Accountability and Core Request Binding

Phase 6 lets the Core **record** that an authorization was used by a **simulated** execution.
It completes the audit vocabulary Phase 1 reserved: `ACTION_EXECUTED ─executes─►
ACTION_AUTHORIZED` and `ACTION_VERIFIED ─verifies─► ACTION_EXECUTED`. It also lets the Core CLI
bind a request to a plan step.

**Everything remains simulation-only. Nothing touches real infrastructure, and nothing can
record a real execution.**

## Decisions

| | Decision |
|---|---|
| Q1 | Execution accountability plus `core request --plan-step`. Policy-level IP/account targets (G5) are a separate, later phase |
| Q2 | Schema v3: an append-only `execution_records` table plus the two audit events |
| Q3 | `action_requests.status` stays `authorized`; `execution_records` is the source of truth |
| Q4 | Maximum authorization age = the approval lifetime (60 min, `CYBERRESCUE_APPROVAL_TTL_MINUTES`) |
| Q5 | `core request --plan-step` |
| Q6 | Phase 3 cases and Phase 4 plans contain no execution data, and recording leaves `case_sha256` and `plan_sha256` unchanged (see "Phase 3/4 documents: the identity boundary") |

## Schema v3

```sql
execution_records (
  id, incident_id, action_request_id UNIQUE, mode CHECK (mode = 'simulated'),
  action, asset_id, plan_id, plan_sha256, step_id, step_sha256, report_sha256,
  evidence_fingerprint, environment_sha256, outcome CHECK (outcome IN ('succeeded','failed')),
  criteria, audit_head_hash, recorded_by, authorized_event_uid, executed_event_uid,
  verified_event_uid, created_at)
```

**Enforced by the database itself, whatever the application does:**

| Constraint | Effect |
|---|---|
| `UNIQUE(action_request_id)` | One record per authorization, ever: replay is impossible |
| `CHECK (mode = 'simulated')` | A real execution cannot be recorded, and a mode cannot be changed |
| `execution_records_no_update`, `_no_delete` triggers | Append-only |
| `execution_records_bound_to_request` trigger | The record must match an **authorized tier-1/2** request of the **same incident, action and asset** |

**Migration.**
* v2 → v3 is purely additive (`CREATE … IF NOT EXISTS`), recorded as `migration.v2_to_v3`, and
  idempotent.
* v1 databases go v1 → v2 → v3. Every existing row and audit hash is unchanged, and all chains
  verify.
* Newer versions are refused ("newer than this code").
* The read-only tools (Phases 3–5) open only the current version; run
  `python -m cyberrescue.core init` once on an older database.
* **Rollback:** v2 code refuses a v3 file, so restore a pre-migration copy.

## Recording: `CoreService.record_simulated_execution`

This is the **only** way to record an execution. It re-checks everything itself, inside one
`BEGIN IMMEDIATE` transaction:

| Check | Refusal |
|---|---|
| The recorder is a registered **SYSTEM actor with role `executor`** | Agents, humans, the system actor, collectors and detectors are refused |
| IDs and hashes are well-formed; outcome is `succeeded`/`failed`; criteria are `{check, satisfied}`; a success has every criterion satisfied | Malformed input |
| The incident exists and is open | Closed incident |
| The request belongs to **this incident** | Wrong incident binding |
| The step's `action` and `asset_id` equal the request's | Target substitution |
| The request is `authorized`, a tier-1/2 non-destructive catalogue action, with an ALLOW decision and the linked `ACTION_AUTHORIZED` event, requested by a P1-allowed actor | Forged status or requester, tier 3 (even if authorized) |
| `params.plan_step`, if present, equals the step id; without it, only asset-bound actions (`isolate_host`, `preserve_disk_image`, `notify_stakeholders`) | Wrong plan step; parameterised action not bound to a step |
| The authorization is **not older than the approval lifetime** (Core clock) | Expired authorization |
| `evidence_fingerprint` equals the incident's evidence **now** | Evidence substitution, or evidence changed since the plan |
| The policy engine does not DENY the request **now** (e.g. a later human denial, P9) | Current denial |
| No record exists for the request | Replay; the database's `UNIQUE` backs this up |

**What it writes:**
* `ACTION_EXECUTED` (`executes` → `ACTION_AUTHORIZED`). Payload: `mode: "simulated"`, record and
  request ids, action/asset, plan id/hash, step id/hash, report hash, evidence fingerprint,
  environment hash, and the audit head before recording.
* `ACTION_VERIFIED` (`verifies` → `ACTION_EXECUTED`). Payload: outcome and criteria.
* The `execution_records` row.

It never changes the request's status, the incident's state, approvals, sign-offs, actors,
policy decisions, vetoes, holds or evidence.

## Authorization-age rule

* **Limit:** an authorization may be recorded only within `PolicyConfig.approval_ttl_minutes`
  (default 60; `CYBERRESCUE_APPROVAL_TTL_MINUTES` changes both approvals and this limit) of its
  `ACTION_AUTHORIZED` event.
* **Enforcement:** the Core enforces it with its own clock when recording.
* **Dry runs:** they stay clock-free and report an authorization older than the limit *at the
  plan's `as_of`* as `BLOCKED (expired)`.

## Replay protection

| Layer | Mechanism |
|---|---|
| Database | `UNIQUE(action_request_id)` and append-only triggers |
| Core | Explicit "already executed" check in the same `BEGIN IMMEDIATE` transaction; a concurrent second connection loses |
| Executor | A dry run reports a spent authorization as `BLOCKED (already_executed)`, naming the record. A prerequisite with a succeeded record for the same plan satisfies its dependants. A second `--record` run records nothing |

## The executor side

**Single writer.** `cyberrescue/execution/recorder.py` is the only module in the package that
opens a writable Core, and it calls only `record_simulated_execution`.
* It first simulates on a read-only connection.
* It then records each step that run SIMULATED, SUCCEEDED or FAILED, one transaction each.
* Blocked, unsupported and decision-point items are never recorded.

**Recorded fields.** The recorded `step_sha256` hashes the step's policy-independent content
(everything except the preview), so it still binds after policy state changes.

**Verification.** `cyberrescue/execution/records.py` verifies a recorded run by
cross-checking:
* the report's and plan's self-hashes;
* each record that cites the report, against the report's simulated step;
* every simulated step having a record;
* each record against its two events (payload, links, recorder);
* the incident's audit chain.

A record row edited or deleted behind dropped triggers, or an edited event, is detected.

## CLI

```powershell
python -m cyberrescue.core request --incident INC-C --action block_ip --requester <actor> --plan-step STEP-0123456789ab
python -m cyberrescue.core show --incident INC-C                        # lists simulated execution records
python -m cyberrescue.core register-actor --kind system --role executor --name "simulated executor"
python -m cyberrescue.execution simulate --plan PLAN.json --record --recorder <executor actor id>
python -m cyberrescue.execution verify --report REPORT.json --plan PLAN.json   # recorded runs: cross-check
python -m cyberrescue.evaluation run --accountability
```

**`--plan-step`:**
* Accepts only `STEP-<12 hex>` or `DEC-<12 hex>`. Anything else exits 2 before anything is
  written.
* The value is stored as `params.plan_step` in the request and its audited `ACTION_PROPOSED`
  event on the incident's chain.
* It changes nothing about the policy decision, and a request without it behaves exactly as
  before.

**`simulate`:**
* Without `--record` it is the same read-only dry run as Phase 5.
* `--record` exits 1 if the Core refuses any record.
* There is still **no** execute, approve, authorize or request command in the execution CLI.

## Security invariants (tests)

| Invariant | Where |
|---|---|
| One record per request: application check, database `UNIQUE` with the check bypassed, a second connection | `test_core_execution_refusals.py`, `test_core_execution_schema.py` |
| Expired authorizations rejected (60 min, and the configured TTL) | `test_core_execution_refusals.py`, `test_execution_recorder.py` |
| Wrong incident, wrong plan step, target substitution, evidence substitution rejected | `test_core_execution_refusals.py`, `test_core_cli_plan_step.py` |
| Record tampering and deletion prevented by triggers and detected by verify; audit tampering breaks the chain | `test_core_execution_schema.py`, `test_execution_records_verify.py` |
| `ACTION_EXECUTED`/`ACTION_VERIFIED` cannot be forged by agent or human messages; only the store emits them; only the executor can cause them | `test_execution_accountability_security.py` |
| Recording creates no approvals, sign-offs, actors, requests or policy decisions; the gate decides as before; legal holds still block wipe and restore | `test_execution_accountability_security.py` |
| Tier-3 actions are never recorded, even when authorized; `mode` cannot be anything but `simulated` | schema, refusals, security |
| Hostile evidence never reaches a record or its events | `test_execution_accountability_security.py` |
| Replaying a recorded simulation is idempotent (A, B, C) | `test_execution_accountability_security.py`, `test_execution_recorder.py` |
| Phase 5 dry-run behaviour unchanged when there are no records; all Phase 5 tests unchanged except one AST allow-list entry for `recorder.py` | `test_execution_spent.py`, Phase 5 suite |

## Phase 3/4 documents: the identity boundary

A case/plan's identity covers its **semantic content** and the audit state it was built from.
It does not cover accountability events appended after it:

```text
Case/Plan identity  =  semantic content  +  audit ANCHOR (hash commits to the whole prefix)
                       +  audit_chain_ok over the ENTIRE chain (tail included)
Execution accountability  =  ACTION_EXECUTED / ACTION_VERIFIED after the anchor
                             +  execution_records  (verify_accountability, verify_recorded)
```

**The anchor.** The Phase 3 builder (`case_anchor`) anchors a case at the incident chain's last
event that is not a *trailing* `ACTION_EXECUTED`/`ACTION_VERIFIED`. From the anchor it takes:
* `as_of`;
* `integrity.audit_head_hash`;
* `integrity.audit_events` (the anchor's sequence number).

The plan derives its id, `as_of` and previews from the case.

**Consequences:**
* **Recording leaves both documents byte-identical.** `case_sha256` and `plan_sha256` are
  unchanged, and `verify-case`/`verify-plan` still pass.
* **Normal events still move the anchor.** Any other audited event (an approval, a request,
  evidence) moves it as before, and a later event makes earlier accountability events part of
  the anchored prefix.
* **Older cases are unaffected.** For chains with no trailing accountability events every value
  is identical to the pre-Phase-6 definition, so earlier exports still verify.

**Tamper detection, by location:**

| What is tampered with | Detected by |
|---|---|
| Case or plan content | Self-hash and rebuild (`verify-case` / `verify-plan`) |
| Evidence | The rebuild (fingerprint, evidence integrity) |
| Any audit event, before or after the anchor | `audit_chain_ok`, which verifies the whole chain and so changes the case and fails `verify-case`/`verify-plan` |
| An execution record row | `verify_accountability`, `verify_recorded` (record against its events) |
| An extra, correctly chained accountability event | `verify_accountability`: it has no record |

Tests: `tests/test_case_plan_hash_boundary.py`.

## Scenario results (`--accountability`)

| Scenario | Recorded | Refused | On replay | Notes |
|---|---|---|---|---|
| A / INC-C | 8 | 0 | 0 | All proposed steps after CISO approvals. Isolation recorded for `srv-db-01` only. Wipe, restore and regulator notification never recorded |
| B / INC-B | 0 | 0 | 0 | False positive: nothing recorded |
| C / INC-A | 5 | 0 | 0 | Isolation recorded for `ws-eng-014` only |

Every recorded run verifies, and every recorded step is `already_executed` in the next dry run.

## Phase 5 limitations resolved

| Phase 5 limitation | Phase 6 status |
|---|---|
| No execution record in the Core | Resolved for simulated runs |
| `ACTION_EXECUTED`/`ACTION_VERIFIED` unused | Now emitted, only for simulated runs |
| Authorizations not consumed | Resolved, one record per authorization |
| `params.plan_step` API-only | Resolved via `core request --plan-step` |

The WarRoom Commander's tools are unchanged; they only use asset-bound actions.

## Known limitations

* **A forged trailing accountability event does not move the case.** This is deliberate: one
  appended with valid hashes by someone with raw write access to the database file is caught by
  `verify_accountability` (it has no record), not by `verify-case`. Truncating the chain's tail
  is detected by a Phase 7 external anchor taken before the truncation (`core verify --anchor`).
* **IP and account targets** are still invisible to policy (G5): `block_ip`/`disable_account`
  requests carry no asset id, and binding them relies on `params.plan_step`.
* **The audit chain itself is unkeyed.** Phase 7 adds keyed *external* anchors
  ([phase7-audit-anchoring.md](phase7-audit-anchoring.md)), which make rewriting or truncating
  any anchored prefix detectable. Records still also store the head hash at recording time.
* **The executor actor is registered by an operator** with local Core access, like collectors.
  The Core cannot tell a well-behaved executor process from another process holding that actor
  id.
* **One CLI run can mix outcomes.** If the Core refuses some steps (e.g. expired), the others are
  still recorded; the run exits 1 and `verify` reports the unrecorded steps.
* **Tier-3 actions are never simulated or recorded,** and real execution remains out of scope.
