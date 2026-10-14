# CyberRescue — Phase 3: Investigation (Forensics) Layer

Phase 3 adds a deterministic, read-only investigation layer, `cyberrescue/investigation/`.
For one incident it builds a reproducible **Case** from the Core containing:
* an annotated, condensed timeline;
* an entity graph with path and pivot queries;
* the scope;
* forensic gaps;
* evidence provenance with integrity status;
* reconciliation of agent statements against evidence;
* a read-only view of policy and approval state.

Cases export as JSON, Markdown or static HTML and carry a verifiable fingerprint.

The layer adds **no new authority**. It cannot write to the Core, and it contains no LLM, no
clock and no randomness. Evidence text is data, and ground truth is never read.

## Decisions

| | Decision |
|---|---|
| Q1 | Direction A: the deterministic Investigation Layer |
| Q2 | Raw evidence lines are excluded by default; `--include-raw` adds them, escaped and labelled untrusted |
| Q3 | Static HTML export ("D-lite"): no server, no scripts |
| Q4 | No WarRoom integration; the `INC-[ABC]` regex work is deferred to its own phase |
| Q5 | Band-imported agent findings are reconciled for citation coverage only |
| Q6 | The fact `lateral_code_execution_observed` is closed through gap G1, and one Phase 2C assertion moves from `not_evaluated` to `match` |

## Architecture

```text
SQLite file ── open(mode=ro, PRAGMA query_only) ──► ReadOnlyCore (allow-listed reads only)
                                                        │
      EvidenceView (Phase 2C: Ev records, no raw) ◄─────┤
      detect() dry run (Phase 2C, unchanged)            │ persisted findings, claims,
                                                        │ citations, holds, vetoes,
                                                        │ requests, decisions, approvals
                          CaseBuilder ◄─────────────────┘
   timeline · graph · pivot · scope · gaps · claims · provenance · policy view · integrity
                               │
            Case (frozen, canonical JSON, case_sha256)
                               │
     render: json | md | html  ──►  stdout, or the --out file only
     verify-case: re-hash the document + rebuild from the database

Separately, evaluation only:  cyberrescue/evaluation/investigation.py  (Case + ground truth)
```

| Module | Responsibility |
|---|---|
| `readonly.py` | `open_readonly` and `ReadOnlyCore` |
| `model.py` | Frozen case model and the `Untrusted` wrapper |
| `findings.py` | Persisted findings with author, origin, rule and citations |
| `timeline.py` | Annotated and condensed timeline |
| `graph.py` | Entity graph and `find_path` |
| `pivot.py` | `related_evidence` and `entity_activity` |
| `scope.py` | Scope derivation |
| `gaps.py` | Gaps G1–G6 |
| `claims.py` | Agent-claim reconciliation |
| `provenance.py` | Evidence provenance with integrity status |
| `policy_view.py` | Read-only policy and approval state |
| `builder.py` | `build_case` and `verify_case` |
| `export.py` | JSON, Markdown and HTML renderers |
| `cli.py` | CLI |

## Read-only by construction

1. **SQLite enforces it.** The database is opened with `mode=ro` and `PRAGMA query_only`, so
   every write raises inside SQLite. This works on the Core's WAL databases, including after the
   `-wal`/`-shm` files have been cleaned up, and a concurrent writer's changes stay visible.
2. **The facade has no write methods.** `ReadOnlyCore` exposes the store, evidence store and
   audit log only through allow-listed reads; `add_finding`, `register_actor`, `authorize`,
   `audit.append` and the rest do not exist on it. `select()` accepts only `SELECT`.
3. **Nothing is created or migrated.** A missing database, a non-Core file, or any schema other
   than v2 is refused.
4. **Detection runs unchanged.** `detect()` (Phase 2C) runs on a `ReadOnlyCore` and is always a
   dry run. Detections already persisted (with `--persist`) are matched by `detection_id`.

## Components

**Timeline.** Evidence is ordered by `(observed_at, id)`. Each entry records:
* the persisted findings that cite it, with the relation and the finding's origin
  (detection / agent / human);
* the dry-run detections that cite it;
* the observations that reference it.

*Condensation:* events sharing (host, event type, process-or-destination, and identical
annotations) chain while consecutive members are ≤ 60 s apart. A chain of ≥ 3 becomes one
*burst* that keeps every evidence id. Because annotations are part of the key, cited activity
never merges with uncited noise. Filters: host, `since`/`until`, `cited-only`.

On Scenario A, `--cited-only` tells the attack in 15 entries covering 59 of 225 records:
1. service install;
2. `bhz.exe` start and shadow-copy deletion;
3. C2 connection;
4. failed DC logons, then SMB attempts ending in a successful app-server logon;
5. the 34-file rename burst;
6. 6 ransom notes;
7. the EDR alert.

**Entity graph.** Nodes are host, account, process (per host and image), file, directory, ip,
domain, hash, alert and e-mail sender. The edge types are:

| Edge | Meaning |
|---|---|
| `started`, `runs`, `child_of` | Process creation and parentage |
| `has_hash`, `executed_as` | Binary identity |
| `wrote_in`, `created` | File activity (per directory) and created executables |
| `connected_to` | Network connections, with port |
| `resolved`, `resolves_to` | DNS lookups and answers |
| `requested` | Proxy requests, with outcome |
| `http_request_to` | Inbound web requests, with status |
| `logged_on_to`, `remote_auth` | Logons and remote authentication, with outcome |
| `autostarts` | Services and Run keys |
| `about` | Alerts and what they refer to |
| `delivered_to` | E-mail delivery |

* Every edge cites all of its evidence ids.
* Labels are `Untrusted`.
* An address the evidence-derived address book resolves to exactly one host is represented by
  that host.
* Size is capped (2,000 nodes and 5,000 edges); truncation is reported.
* `find_path` is a bounded, deterministic breadth-first search over undirected edges. **A path
  shows a connection, not causation;** use the timeline for sequence.

**Pivots.** `related_evidence` returns records that share entity keys with a given record
within a window. Results are ranked by (number of shared entities, time distance, id), and
each result lists the shared keys.

**Scope.** A description, never a recommendation. It lists:
* *compromised* hosts: execution, persistence, recovery-inhibition, impact or chain detections;
* *accessed* hosts: successful lateral authentication;
* *targeted* hosts: authentication attempts that never succeeded;
* accounts;
* infrastructure, with outcome;
* data classes at risk;
* in-scope hosts under legal hold;
* the rule basis for each host.

**Gaps.** Each gap reports the *absence of observed evidence*, never the absence of activity.

| Code | Meaning |
|---|---|
| G1 | Authenticated access with no observed activity by that account on the target afterwards; one gap per logon |
| G2 | Indicator contact with no observed outcome |
| G3 | Uncorroborated vendor alert |
| G4 | In-scope host with no endpoint telemetry |
| G5 | Partial chain |
| G6 | Agent statement not backed by evidence |

Descriptions are templates that interpolate safe identifiers only.

**Agent-claim reconciliation (Q5).** Non-detector findings, such as WarRoom agents imported with
`import-band` or human findings, are classified by **citation coverage only**:
* `evidence-backed`: at least one valid supporting citation and no rejected citations;
* `partially backed`: valid citations, but the author also has `CLAIM_REJECTED` citation events;
* `unsupported`: no valid supporting citation.

This does not judge whether a statement is true.

**Provenance.** For each record: source, sensor, vendor and adapter (as `Untrusted`), the
ingester's kind and role, both hashes, the audit event, the Phase 2A integrity result, and the
findings that cite it.

**Policy view.** Read-only: holds, vetoes, sign-off status, action requests with their latest
decision and unmet rules, and approvals. Agent proposals imported from Band show as `proposed`
with no decision. A request evaluated by the Core shows its outcome, e.g.
`REQUIRE_APPROVAL [P6, P8]`.

## Determinism and verification

* No wall clock is used. `as_of` is the timestamp of the case's **audit anchor**, and ids are
  content-derived. The anchor is the incident chain's last event, except that trailing Phase 6
  accountability events (`ACTION_EXECUTED`, `ACTION_VERIFIED`) are skipped. Their records are
  verified on the execution side (`phase6-execution-accountability.md`).
  * `integrity.audit_head_hash` and `integrity.audit_events` are the anchor's hash and sequence
    number.
  * `integrity.audit_chain_ok` still verifies the whole chain.
* **The same database state always produces a byte-identical case.**
* `case_sha256` is the sha256 of the canonical content.
* `verify-case` re-hashes the document, which detects an edited export, and rebuilds the case
  from the database, which detects changed evidence, findings, policy state or rules.
* Across *independently ingested* Cores, the evidence-derived analysis is identical: graph,
  scope, gaps, observations and detection ids. Core-assigned values are not: finding and hold
  ids (uuid4), ingestion times, and audit hashes.

## Trust labelling and exports

* Every free-text value derived from evidence or agents is wrapped as
  `{"untrusted": "..."}`. Examples: command lines, paths, process names, user-agents, mail
  subjects, alert names, agent summaries and claims, raw lines.
* **Identifier fields are also evidence-derived:** `host`, `primary_host`, graph `key`/`src`/`dst`.
  They are not wrapped, but every renderer escapes them, and a security test pins exactly this
  set of fields. Consumers (e.g. a future LLM layer) must treat them as data too.
* **Markdown:** dynamic strings appear only inside code spans whose backtick fence is longer
  than any backtick run in the text.
* **HTML:** one self-contained page. Everything is escaped, and a Content-Security-Policy
  (`default-src 'none'`) blocks scripts and external resources. The page contains no scripts,
  links, images or forms.
* **All output is ASCII.** Control characters, including ANSI and OSC escapes, become `?` and
  non-ASCII is backslash-escaped. Attacker text therefore cannot inject markup or drive the
  operator's terminal.

## CLI (all read-only)

```powershell
python -m cyberrescue.investigation [--db PATH] case --incident INC-C [--format json|md|html] [--out FILE] [--include-raw]
python -m cyberrescue.investigation [--db PATH] timeline --incident INC-C [--host H] [--since T] [--until T] [--cited-only] [--no-condense] [--json]
python -m cyberrescue.investigation [--db PATH] pivot --incident INC-C --evidence EV-… [--by host,account] [--window 15m]
python -m cyberrescue.investigation [--db PATH] entity --incident INC-C (--host H | --account A | --ip I | --domain D | --key TYPE:VALUE)
python -m cyberrescue.investigation [--db PATH] path --incident INC-C --from host:srv-db-01 --to host:srv-app-01 [--max-hops 4]
python -m cyberrescue.investigation [--db PATH] scope --incident INC-C [--json]
python -m cyberrescue.investigation [--db PATH] gaps --incident INC-C [--json]
python -m cyberrescue.investigation [--db PATH] provenance --evidence EV-… [--json]
python -m cyberrescue.investigation [--db PATH] verify-case FILE          # exit 1 on mismatch
python -m cyberrescue.evaluation run [--scenario A] --investigation
```

* `path` exits with 1 when no path exists.
* Errors (missing database, unknown incident or evidence) exit with 2.
* Only `case --out` writes, and only to that file.

## Results on the Phase 2B scenarios

| | Scope (compromised / accessed / targeted) | Infrastructure | Gaps |
|---|---|---|---|
| A / INC-C | srv-db-01 / srv-app-01 / srv-dc-01; PII at risk; db under legal hold | 185.220.101.47 established | G1 (app), G4 (dc), G5 (DATA-001 partial) |
| B / INC-B | — / — / — | — | G3 (IDS alert) |
| C / INC-A | ws-eng-014 / — / — | cdn-pidgin-loader.net blocked | none |

**Evaluation** (`--investigation`) shows no case-check mismatches on A, B or C:
* scope matches the ground-truth facts;
* 58/58 and 6/6 malicious events appear in the detection-annotated timeline;
* the ground-truth stage order is preserved;
* no benign-explained event is ever detected;
* lateral code execution is correctly not observed;
* the false positive stays quiet.

With Q6, the Phase 2C fact check for A is **16/16 match**. The usual caveat applies: the rules
and checks were developed against these three datasets, so this shows consistency, not
generalisation.

## Security tests (`tests/test_investigation_security.py`)

The test database holds all scenarios, persisted detections, Band-imported agent findings, an
evaluated `wipe_host` request, and the Phase 2B/2C hostile telemetry.

* Every CLI command leaves the hash of every table, trigger and index unchanged.
* The policy snapshot and the Commander gate's verdicts are identical after building and
  rendering cases.
* Hostile text appears outside `Untrusted` only in the pinned identifier fields.
* Scope and gap text never contains action or approval language.
* AST checks find no authority, execution or nondeterminism names, and no write SQL, in any
  module. Raw evidence is read only by the builder, and only under `include_raw`.
* The package never loads ground truth, the scenario generators, evaluation code or LLM clients,
  and a file-read spy shows no dataset file is opened.

## Compatibility

* Schema v2, no migration.
* **No changes** to `cyberrescue/core`, telemetry, detection, datasets, ground truth, WarRoom
  code, Docker or the README.
* Evaluation changes:
  * `harness.py` also derives scope and gaps;
  * `expectations.py` adds `CASE_FACT_EXTRACTORS`;
  * `metrics.py` consults it;
  * `cli.py` gains `--investigation`;
  * one Phase 2C test assertion changed (Q6).
* Shadow and enforce modes, `--persist`, the Commander gate and the policy engine are untouched.

## Known limitations

* **Citation coverage is not truth.** Claim reconciliation does not judge whether a statement
  is true. Rejected citations are attributed per author, because `CLAIM_REJECTED` events do not
  record which finding they belong to.
* **Gaps are about evidence.** G1–G6 report missing observations, not missing activity.
* **Paths are not causation.** `find_path` shows connection only, and shortest paths can run
  through benign entities.
* **Condensation hides detail in summary views.** Every burst keeps all of its evidence ids.
* **Address resolution is fragile.** IP→host mapping is learned from evidence, with the same
  NAT, DHCP and WorkstationName caveats as Phase 2C.
* **Identifier fields are evidence-derived but not wrapped** as `Untrusted` (see above).
* **Read-only on WAL databases** needs the directory to be writable (for `-shm`) or the `-shm`
  file to exist.
* **Test cost:** many tests build scenario Cores, so the suite takes roughly 1–1.5 minutes on
  the development machine.
