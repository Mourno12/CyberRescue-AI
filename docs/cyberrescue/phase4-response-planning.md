# CyberRescue — Phase 4: Response Planning Layer

Phase 4 adds a deterministic, read-only, **proposal-only** response planner,
`cyberrescue/response/`. For one incident it turns the Phase 3 investigation case into an
advisory **Response Plan** containing:

* **proposed steps**: catalogue actions of tier 1 or 2, ordered, each citing detections,
  persisted findings and evidence;
* **human decision points**: every tier-3 action, and tier-2 actions on protected targets;
* **investigative tasks**: one per Phase 3 gap (these are not actions);
* **notes**: stated limitations.

Every step and decision carries a **policy preview** (what the policy engine would answer),
ATT&CK labels and, for steps, success criteria that a later verification phase can check.

The layer adds **no new authority**:
* It never requests, approves, authorizes or executes anything.
* It never writes to the Core.
* It contains no LLM, no clock and no randomness.
* Evidence text is data, and ground truth is never read.

## Decisions

| | Decision |
|---|---|
| Q1 | Direction C: a deterministic response planner. The executor and verification (reserved as "Phase 4" in Core code comments) become **Phase 5**; the Core comments are left unchanged |
| Q2 | Tier-3 actions are **never** plan steps, only human decision points with their policy requirements |
| Q3 | The ATT&CK mapping is used by the planner only; the Phase 3 case and its `case_sha256` are unchanged |
| Q4 | No plan submission: no `--submit`, no call to `request_action`, `grant_approval`, `authorize`, `audit.append` or the Commander gate |
| Q5 | A protected-accounts list guards `disable_account`; a protected account becomes a human decision point |
| Q6 | The executor reference is renamed to Phase 5 in this document only |

## Architecture

```text
SQLite ─(mode=ro)─► ReadOnlyCore ─► build_case (Phase 3, unchanged) ─► Case: scope, gaps, as_of,
                         │                                                  persisted-finding map
                         ├─► detect() dry run (Phase 2C, unchanged) ─► detection entities
                         └─► allow-listed reads ─► IncidentSnapshot(now = as_of)
                                                          │
 playbook-v1 + attack-map-v1 + targets.py ─► planner ─► PolicyEngine.evaluate (pure) per item
                                                          │      = PolicyPreview(authorizes=False)
                                                          ▼
                       ResponsePlan (frozen, canonical JSON, plan_sha256, bound to case_sha256)
                                                          │
                          render: json | md | html  ──►  stdout, or the --out file only
                          verify-plan: re-hash the document + rebuild from the database
                                                          ┊
   (a human reads it; any action still goes: core `request` / Commander ─► gate ─► policy ─► approval)

Separately, evaluation only:  cyberrescue/evaluation/response.py  (plan + ground truth)
```

| Module | Responsibility |
|---|---|
| `model.py` | Frozen plan model: `PlanStep`, `DecisionPoint`, `Task`, `PlanNote`, `PolicyPreview`, `ResponsePlan` |
| `targets.py` | Target validation and the protected-accounts list |
| `protected_accounts.json` | The protected accounts (operator-editable, fingerprinted) |
| `playbooks.py` | `playbook-v1`: triggers, templates, phase order |
| `attack.py` | `attack-map-v1`: static rule → ATT&CK table |
| `preview.py` | Read-only snapshot and pure policy previews |
| `planner.py` | `build_plan` and `verify_plan` |
| `export.py` | JSON, Markdown and HTML renderers |
| `cli.py` | CLI |

## Proposal-only by construction

1. **The model refuses authority.**
   * A `PlanStep` accepts only tier-1/2, non-destructive catalogue actions, must cite evidence,
     and must agree with the catalogue on tier and reversibility.
   * `PolicyPreview.authorizes` is the literal `False`, and its `kind` and `note` are fixed.
   * The plan's disclaimer is fixed.
2. **There is no write path.**
   * The database is opened through Phase 3's `open_readonly` (`mode=ro`, `PRAGMA query_only`).
   * The policy snapshot is rebuilt from the same allow-listed reads `CoreStore.snapshot` uses.
   * Only `preview.py` touches the policy engine, and only its pure `evaluate()`.
   * The requester is a hypothetical Commander that exists only in memory and is never
     registered.
3. **Only detections trigger proposals.** Agent findings (Band imports), human findings,
   observations and vendor alerts never produce a step. An agent can add a G6 *task*, never an
   action.
4. **The CLI has no acting command.** It has `plan`, `verify-plan` and `step`, and a test pins
   that set.

## Playbook v1

| Trigger (detections only) | Plan content |
|---|---|
| Compromised host (execution / persistence / recovery inhibition / impact / multi-stage) | `isolate_host`, then `preserve_disk_image`; `wipe_host` as a **decision**, plus `restore_from_backup` as a **decision** when impact (RANSOM-001) is seen |
| Malicious executable (IOC-001 / PROC-001 executable, PERSIST-001 target) | `quarantine_file` after imaging; the path is an `Untrusted` parameter |
| Malicious process (IOC-001 / PROC-001 / RANSOM-001) | `kill_process` (irreversible) after imaging, so memory evidence is kept |
| Established C2 to an IP (IOC-002) | `block_ip` on a validated target |
| Successful lateral authentication (AUTH-001 / LAT-001) | `disable_account` on a validated target; a protected account becomes a **decision** |
| Accessed host (successful logon, no compromise detection) | `preserve_disk_image` only; no isolation without evidence of compromise |
| Any proposal | `notify_stakeholders`: CISO, plus DPO and Legal when a notification regulation applies or a host is under hold |
| Notification regulation applies (deadline > 0 for the data classes at risk) | `notify_regulator` as a **decision** |
| Every Phase 3 gap G1–G6 | An investigative **task** |

* **Ordering:**
  * Steps run by phase: notify, contain, preserve, eradicate. Within a phase they are ordered
    host, ip, account.
  * Per host, the dependencies are explicit: isolate → preserve → kill and quarantine.
  * Wipe and restore decisions list the isolation and imaging steps as prerequisites.
* **Text:** every human-readable string is a fixed template, and only safe tokens are
  interpolated. A hostile process name therefore appears as `<unprintable>` in the rationale,
  and verbatim only as an `Untrusted` parameter.
* **Cautions:** irreversibility, evidence-derived targets, and the criticality of
  high- and critical-criticality assets.

**Notes** record what the plan deliberately does not do:
* no catalogue action exists for domains;
* the indicator was already blocked;
* autostart entries have no removal action;
* a refused target, with a fixed-template reason;
* no detection supports a response.

## Target validation (`targets.py`)

| Kind | Accepted only if |
|---|---|
| host | It is a plain identifier **and** an asset in the inventory |
| ip | It is valid, external, globally routable (not multicast, reserved or unspecified), not mapped to one of our hosts by the evidence, and not allowlisted by threat intel |
| account | It is a plain account name (no domain prefix, no `$` machine account) **and** not on `protected_accounts.json` |

* A protected account is not dropped: it becomes a `protected_target` decision point.
* The list is fingerprinted by its normalised content, so line endings and order do not
  matter, and its hash is recorded in `plan.inputs`.
* `--protected-accounts FILE` overrides the list for the CLI.

## Policy previews

* Each step and decision shows `preview: <ALLOW|REQUIRE_APPROVAL|DENY> [unmet rules]`.
* The answer is evaluated as of the plan's `as_of` for a hypothetical Commander.
* Rule reasons are `Untrusted`, because they can quote veto or approval text.
* Tests compare every preview with a live `request_action` on a copy of the database.
* **A preview is not a decision.** Approvals valid at `as_of` may have expired by the time
  someone reads the plan, and the real decision is made by the Core at request time.

**Core limitation found in this phase.** `action_requests.asset_id` and `approvals.asset_id`
reference the asset inventory, so the Core can record IP and account actions only **without**
an asset id. Previews evaluate those targets the same way (`evaluated_asset_id: null`). A test
pins the limitation, and the Core is unchanged. Giving non-host targets a proper home belongs
with the Phase 5 executor.

## Determinism and verification

* No wall clock is used. `as_of` is the case's, and ids are content-derived.
* **The same database state always produces a byte-identical plan.**
* `plan_sha256` covers the canonical content. The plan is bound to `case_sha256`, the ruleset,
  playbook, ATT&CK-map and policy versions, the evidence fingerprint, and the threat-intel,
  regulatory-rules and protected-accounts hashes.
* `verify-plan` re-hashes the document, which detects an edited file, compares the
  protected-accounts list, and rebuilds the plan from the database, which detects changed
  evidence, findings, policy state, rules or playbook.
* Building a plan leaves every Phase 3 `case_sha256` unchanged.

## CLI (all read-only)

```powershell
python -m cyberrescue.response [--db PATH] [--protected-accounts FILE] plan --incident INC-C [--format json|md|html] [--out FILE]
python -m cyberrescue.response [--db PATH] [--protected-accounts FILE] verify-plan FILE        # exit 1 on mismatch
python -m cyberrescue.response [--db PATH] [--protected-accounts FILE] step --incident INC-C --id STEP-…|DEC-… [--json]
python -m cyberrescue.evaluation run [--scenario A] --response
```

* Errors (missing database, unknown incident or id) exit with 2, and the database is never
  created.
* Only `plan --out` writes, and only that file.
* No format emits command lines, so nothing can be copy-pasted into a shell.

## Results on the Phase 2B scenarios

| | Steps | Decision points | Tasks / notes |
|---|---|---|---|
| A / INC-C | notify (CISO, DPO, Legal); isolate `srv-db-01` (preview REQUIRE_APPROVAL [P5]); block `185.220.101.47`; disable `svc_sqlbackup`; image `srv-app-01`; image `srv-db-01`; kill `bhz.exe`; quarantine `C:\ProgramData\upd\bhz.exe` | wipe and restore `srv-db-01` (REQUIRE_APPROVAL [P6, P8], legal hold); notify regulator under GDPR-ART-33 and SEC-8K-1.05 ([P6]) | G1 `srv-app-01`, G4 `srv-dc-01`, G5 `srv-db-01` (+ G6 with Band imports); note: persistence |
| B / INC-B | none | none | G3 corroborate the IDS alert; note: no response |
| C / INC-A | notify (CISO); isolate, image, kill and quarantine on `ws-eng-014` | wipe `ws-eng-014` ([P6]) | notes: C2 already blocked, persistence |

In A, `srv-backup-01` (benign backup traffic) and `srv-dc-01` (targeted, never accessed) get
no containment step.

**Evaluation** (`--response`) shows no mismatches on A, B or C:
* isolation, C2 blocking and account disabling match the ground-truth facts;
* the malware path is quarantined (A);
* a regulator decision appears exactly when a PII host is affected;
* eradication follows imaging;
* no step touches a benign-only host;
* 7/7 (A) and 4/4 (C) acting steps cite malicious evidence;
* there are no tier-3 steps, and the false positive is quiet.

Checks the ground truth cannot answer (e.g. C's malware path) are `not_evaluated`. The usual
caveat applies: the playbook was written against these three datasets.

## Security tests (`tests/test_response_security.py`)

The test database holds all scenarios, persisted detections, Band-imported agent findings, an
evaluated `wipe_host` request, and the Phase 2B/2C hostile telemetry.

* Every command (`plan` in all formats, `verify-plan`, `step` on every item) leaves the hash
  of every table, trigger and index unchanged. No request, approval or audit event appears.
* The policy snapshot and the Commander gate's verdicts are identical after building and
  rendering plans, and so are the Phase 3 case hashes.
* Every preview has `authorizes = false`, and no step is tier 3.
* Hostile text appears outside `Untrusted` only in `tasks.host`, an identifier copied from the
  Phase 3 gap host. A test pins that field.
* A hostile process name with the real malware hash yields kill and quarantine steps. The name
  appears only as `Untrusted` parameters, never as a target or in prose.
* AST checks over every module find:
  * no authority, gate, audit or nondeterminism names;
  * no upper-case write SQL;
  * `PolicyEngine` only in `preview.py`, which calls only `evaluate`.
* The package never loads ground truth, the scenario generators, evaluation code, the
  Commander gate, `agents/` or LLM clients, and never opens a dataset file.
  * `cyberrescue.core.service` is *loaded* by the `cyberrescue.core` package `__init__`, and
    `detection.publisher` by Phase 3 (constants only). The AST checks show neither is called.

## Compatibility

* Schema v2, no migration.
* **No changes** to `cyberrescue/core`, telemetry, detection, the investigation layer,
  datasets, ground truth, WarRoom code (`agents/`, `shared/`), Docker or the README.
* Evaluation changes:
  * `cli.py` gains `--response`;
  * the new `response.py`.
  * The default JSON output without flags is unchanged.
* Shadow and enforce modes, `--persist`, the Commander gate and the policy engine are untouched.
* The original 77 WarRoom tests are unchanged.

## Known limitations

* **The playbook is tuned to three synthetic scenarios.** This shows consistency, not
  generalisation.
* **Missing catalogue actions:** there is nothing for domains, credential resets or autostart
  removal. These are reported as notes, not worked around.
* **Non-host targets:** the Core cannot record IP or account targets as asset ids (see above).
* **Previews are point-in-time.** Approvals expire and holds change; the Core decides at
  request time.
* **Evidence-derived targets** are validated, not proven. Account and IP steps carry cautions
  for a human to confirm, and business impact is noted, not computed.
* **ATT&CK labels** are rule-level, not event-level inferences.
* **Packaging:** `protected_accounts.json` is read from the source tree (as `shared/mock_env`
  is). Docker copies `cyberrescue/` whole.
* **Next (Phase 5):** a simulated executor and verification against the success criteria,
  using the reserved `ACTION_EXECUTED` / `ACTION_VERIFIED` vocabulary.
