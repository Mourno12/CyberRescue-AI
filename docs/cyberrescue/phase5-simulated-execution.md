# CyberRescue — Phase 5: Simulated Executor

Phase 5 adds `cyberrescue/execution/`, a deterministic, read-only, **simulation-only** executor
for Phase 4 response plans. It works in four steps:
1. It takes a plan.
2. It simulates each **step the CyberRescue Core has already authorized** against an
   in-memory environment built from the incident's evidence.
3. It checks the plan's own success criteria.
4. It returns a hashed, verifiable **execution report**.

It runs no command and contacts no system. It does not:
* create approvals, sign-offs or actors;
* request, approve or authorize an action;
* bypass the Commander gate;
* write to the Core;
* read ground truth;
* use an LLM.

## Authorization: the plan is never authority

A step is simulated only after every check below passes, in this order. The first failure ends
it as **BLOCKED** (with a category) or **UNSUPPORTED**.

| # | Check | Failure |
|---|---|---|
| 1 | **Plan integrity**: strict schema (a forged `"approved": true` or `"authorizes": true` is rejected); `plan_sha256` matches; same protected-accounts list; evidence fingerprint and rule/playbook/ATT&CK versions unchanged; audit chain and evidence verify | `integrity` |
| 2 | The database still produces **this exact step** (action, target, parameters, citations, criteria): a rehashed, edited plan is caught here | `integrity` |
| 3 | The catalogue agrees it is a tier-1/2, non-destructive action | `integrity` |
| 4 | The target is re-validated now (inventory, address checks, protected accounts) | `target` |
| 5 | Every prerequisite step (`after`) SUCCEEDED in this run | `dependency` |
| 6 | A simulated handler exists | UNSUPPORTED |
| 7 | **The Core already authorized it** (see below) | `authorization` |
| 8 | Current policy (pure `PolicyEngine.evaluate` via the Phase 4 previewer) has no hard DENY and no veto that the authorizing decision did not consider | `policy` / `veto` |

**A Core authorization** is an `action_requests` row with status `authorized`, plus:
* its latest `policy_decisions` row with outcome `ALLOW`;
* an `ACTION_AUTHORIZED` audit event for it, linked (`authorizes`) to that decision;
* a requester that rule P1 allows (the Commander agent, or a human operator/approver).

These records come only from the existing path: `request_action`, i.e. the Commander gate in
enforce mode or `python -m cyberrescue.core request`, after `approve` where policy demands it. A
status changed in the database without the audit record does not count. Each authorization is
used once per run.

**Binding an authorization to a step:**

| Action | Accepted authorization |
|---|---|
| `isolate_host`, `preserve_disk_image`, `notify_stakeholders` | same action and asset id (how the WarRoom gate authorizes), or `params.plan_step` = the step id |
| `kill_process`, `quarantine_file`, `block_ip`, `disable_account` | **only** `params.plan_step` = the step id |

The Core's authorization scope is (incident, action, asset id). It cannot say *which* process,
file, address or account is meant, so it cannot bind those actions to a step by itself.

**Decision points** (tier-3 actions and protected targets) are never simulated:
* **BLOCKED `legal_hold`** when an active hold (P8) is among the unmet rules now;
* **BLOCKED `human_decision`** otherwise;
* **UNSUPPORTED** if the Core has in fact authorized such an action. Tier-3 simulation is out of
  scope, so even an authorized wipe never becomes a success.

## State model

```text
PENDING -> CHECKING -> BLOCKED | UNSUPPORTED                 (terminal)
                    -> SIMULATED -> SUCCEEDED | FAILED       (terminal)
```

Every result carries its full path, and the model refuses any other transition:
* `SUCCEEDED` requires an applied effect **and** every success criterion of the plan;
* a simulated step must reference its Core authorization;
* blocked steps carry a category and never an effect.

## Simulation

**The environment.** `SimEnvironment` is built from the incident's **structured** evidence (no
raw lines) and the inventory. It contains:
* hosts;
* processes seen starting;
* files seen as executables, written files or service/autostart targets;
* external destination addresses;
* account names.

Each fact cites its evidence ids. Changes are copy-on-write, and the module has no I/O.

**Handlers.** There is one pure handler per supported action. A handler applies its effect only
to something the evidence shows. A process never seen running, a file never seen, or an account
never seen gives `applied=False`, never an invented success.

| Action (supported) | Simulated effect | Plan criterion checked afterwards |
|---|---|---|
| `notify_stakeholders` | notification recorded | `notification_recorded` |
| `preserve_disk_image` | image recorded for the host | `image_recorded` |
| `isolate_host` | host marked isolated | `no_network_activity_from_host` |
| `block_ip` | egress to the address blocked | `no_connection_to_indicator` |
| `disable_account` | account disabled (if seen) | `no_successful_logon_by_account` |
| `kill_process` | process terminated (if seen running) | `no_process_activity` (existed **and** terminated) |
| `quarantine_file` | file quarantined (if seen) | `file_absent` (existed **and** quarantined) |

**Unsupported actions.** `wipe_host`, `delete_file`, `restore_from_backup` and
`notify_regulator` have no handler; a plan cannot contain them as steps anyway.

**Determinism.**
* No wall clock is used: `as_of` is the incident's last audit event.
* Nothing is written, so the same database and plan always give a byte-identical report, and
  repeated runs are idempotent by construction.
* `report_sha256` covers the content.
* `verify` re-hashes a report and reproduces it from the database and plan.

## CLI (all read-only)

```powershell
python -m cyberrescue.execution [--db PATH] [--protected-accounts FILE] simulate --plan PLAN.json [--format json|md|html] [--out FILE]
python -m cyberrescue.execution [--db PATH] [--protected-accounts FILE] show --plan PLAN.json --id STEP-…|DEC-… [--json]
python -m cyberrescue.execution [--db PATH] [--protected-accounts FILE] verify --report REPORT.json --plan PLAN.json   # exit 1 on mismatch
python -m cyberrescue.evaluation run [--scenario A] --execution
```

* Every run prints `SIMULATION ONLY - nothing was executed against any real system.`
* No command executes, requests, approves or authorizes; a test pins the command and flag set.
* Only `simulate --out` writes, and only that file.
* Errors exit with 2, and the database is never created.
* Reports exist as JSON (canonical), Markdown and static HTML. They use the Phase 3/4 escaping,
  are ASCII-only, have no scripts, and contain no command lines.

## Results on the Phase 2B scenarios

These runs are in a throw-away Core. The Commander requests every plan step through
`request_action` with `params.plan_step`.

| | Commander only (no human approval) | After a CISO approves the steps that need it |
|---|---|---|
| **INC-C** (A, ransomware) | notify, block `185.220.101.47`, disable `svc_sqlbackup`, image `srv-app-01`: **SUCCEEDED**. Isolate `srv-db-01`: **BLOCKED (authorization)**, policy now `REQUIRE_APPROVAL [P5]`. Image, kill and quarantine on `srv-db-01`: **BLOCKED (dependency)**. Wipe and restore `srv-db-01`: **BLOCKED (legal_hold)**, `[P6, P8]`. Notify regulator: **BLOCKED (human_decision)** | all 8 steps **SUCCEEDED**; wipe/restore still **legal_hold**, regulator still **human_decision** |
| **INC-B** (B, false positive) | nothing to simulate | nothing to simulate |
| **INC-A** (C, commodity malware) | notify, isolate, image, kill, quarantine on `ws-eng-014`: **SUCCEEDED**. Wipe `ws-eng-014`: **BLOCKED (human_decision)** `[P6]` | same |

If a human also approves the wipe with `overrides_hold` and the Commander requests it, the Core
authorizes it, but the executor reports **UNSUPPORTED**, never a success.

**Evaluation** (`--execution`) shows no mismatches on A, B or C, and outcomes are counted per
category (blocked is never failure):
* the false positive simulates nothing;
* no decision point is ever simulated;
* eradication of patient zero is held exactly when a PII host is affected (A, not C);
* 12/12 (A) and 10/10 (C) simulated steps meet their criteria;
* 0/3 approval-gated steps run before an approval (A);
* with approvals, isolation is simulated exactly for the compromised hosts and C2 blocking
  exactly for the contacted C2 IPs.

## Security tests (`tests/test_execution_security.py`)

The test database holds the scenarios, persisted detections, Band imports, hostile telemetry
with forged `"approved"` fields, and Commander requests for every step.

| Area | What the tests show |
|---|---|
| No writes | Every command and export leaves every table, trigger and index unchanged: approvals, sign-offs, actors, requests, decisions, vetoes, holds, incidents, audit events |
| Gate and policy | The Commander gate's verdicts and the policy snapshot are identical. No execution module names the gate, `PolicyEngine`, or a Core write method |
| Forged approvals | Forged `approved` / `approval_id` / `overrides_hold` request params, and forged plan fields, authorize nothing. A missing approval gives `BLOCKED (authorization)` |
| Legal hold | A hold blocks wipe even with a non-overriding approval |
| Tier and targets | A plan cannot put a tier-3 action in a step, bump a tier, or slip a rehashed changed step past the database check. Invalid or protected targets are refused, including by the executor's own target re-check |
| Hostile text | Hostile evidence appears in a report only as `Untrusted` data |
| Unsupported | With no handlers, nothing is reported as a success |
| Real-world isolation | AST: no subprocess/socket/os/http/file-write names; handlers import only simulation types. At runtime, traps on `Popen`, `os.system`, sockets and file writes are never hit while simulations succeed |
| Ground truth | The package never loads ground truth, evaluation, the gate, `agents/`, LLM or HTTP clients, and never opens a dataset file |
| Determinism | Repeated runs are byte-identical |

## Compatibility

* Schema v2, no migration.
* **No changes** to:
  * `cyberrescue/core`, the Commander gate, the policy engine;
  * telemetry, detection, the investigation layer, the response planner;
  * datasets, ground truth, WarRoom code (`agents/`, `shared/`), Docker or the README.
* Evaluation changes: the new `execution.py`, and `cli.py` gains `--execution`.
* The original 77 WarRoom tests are unchanged.

## Known limitations

* **Nothing is recorded in the Core.** `ACTION_EXECUTED` / `ACTION_VERIFIED` and the
  `executed`/`verified` statuses stay reserved: the Core has no API that emits them, and adding
  one would change the Core. The report is a separate, verifiable document instead.
* **Binding parameterised actions needs `params.plan_step`.** That is available through
  `request_action` (the service API). The Core CLI `request` command and the WarRoom Commander
  tools cannot set it. IP and account targets also cannot be stored as asset ids (Phase 4
  finding).
* **The simulated world is the evidence.** A target the evidence never shows cannot be acted
  on, and simulated effects say nothing about real-world reliability.
* **Tier-3 actions are never simulated,** even when authorized.
* **Authorizations are not consumed.** Because nothing is written, every run may reuse the same
  Core authorizations (deterministically); real single-use execution would need a Core record.
* **The evaluation's "with approvals" regime** approves exactly what the plan's previews ask
  for. It shows the gating works, not that approving was right.
