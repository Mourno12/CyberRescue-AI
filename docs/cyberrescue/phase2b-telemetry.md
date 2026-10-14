# CyberRescue — Phase 2B: Synthetic Telemetry → Evidence

Phase 2B adds deterministic synthetic telemetry for the three existing WarRoom
incidents. It feeds that telemetry into the Phase 2A Evidence Core through an
adapter, with no change to any trust boundary.

```text
Synthetic telemetry (TelemetryEvent, JSONL)       datasets/cyberrescue/synthetic/telemetry/
        ↓  cyberrescue.telemetry.adapter.to_envelope      (pure field mapping)
EvidenceEnvelope (Phase 2A, unchanged)
        ↓  CoreService.ingest_evidence_batch              (Phase 2A, unchanged)
Evidence store (sealed, immutable, audited)
```

Out of scope, and not implemented: detection rules (Phase 2C), correlation, the
Forensics agent, LLM calls, MITRE ATT&CK mapping, dashboard, automated response,
risk scoring.

## Package `cyberrescue/telemetry/`

| Module | Role | Operational path? |
|---|---|---|
| `schema.py` | `TelemetryEvent`, the telemetry record | yes |
| `adapter.py` | `TelemetryEvent → EvidenceEnvelope`; JSONL loader | yes |
| `catalog.py` | Label-free scenario registry (scenario → incident) and dataset layout | yes |
| `importer.py` | Adapter + `ingest_evidence_batch` | yes |
| `cli.py` | `python -m cyberrescue.telemetry` | yes (`generate`/`check` load generators lazily) |
| `scenarios.py` | Deterministic generators for A/B/C | **no**: offline tooling |
| `ground_truth.py` | Evaluation-only labels model and consistency check | **no**: evaluation only |
| `datasets.py` | Render, write and byte-check the committed datasets | **no**: offline tooling |

## Scenarios

The scenarios use the existing incidents; no incident was created or replaced.

| Scenario | Dataset | Incident | Window (UTC, 2026-06-13) | Events | Verdict |
|---|---|---|---|---|---|
| A | `scenario-a` | **INC-C** `INC-C-2026-0042` | 13:30–14:10 | 225 | true positive: ransomware |
| B | `scenario-b` | **INC-B** `INC-B-2026-0041` | 11:00–11:50 | 153 | false positive |
| C | `scenario-c` | **INC-A** `INC-A-2026-0039` | 08:55–09:25 | 110 | true positive: commodity malware, contained |

**A: BlackHaze ransomware on `srv-db-01` (customer PII).** The timeline:
* UpdSvc service install, then `C:\ProgramData\upd\bhz.exe` runs as `svc_sqlbackup` (14:01).
* `vssadmin delete shadows`.
* TLS to `185.220.101.47` (EDR and NetFlow both record it).
* NTLM/SMB authentication to `srv-dc-01`, which fails three times, and to `srv-app-01`,
  which fails twice and then succeeds.
* 34 `.blackhaze` renames and 6 `RECOVER_YOUR_FILES.txt` drops.
* The ransom note's content, which carries prompt injection and a fenced `SIGNOFF` block.
* The CrowdFalcon alert at the mock alert's `detected_utc` (14:07:22).

The background noise includes DB connection pools, PostgreSQL logs, Kerberos and DNS. It also
contains two **confounders**: a legitimate `pg_dump` backup run by the *same* service account,
and one mistyped password.

**B: "possible beaconing" from `srv-web-01`.** The resolver is misconfigured to `8.8.8.8`
and polled every 5 minutes, and Windows Update checks in every 10 minutes. Both destinations
are allowlisted. The rest is public web traffic, log rotation, and the SuriWatch alert at
11:42:55. One internet scanner request has a hostile User-Agent and is rejected with HTTP 400.
There are no auth or file events.

**C: GreyLoader on `ws-eng-014`.** A phishing e-mail arrives whose subject carries prompt
injection, with `invoice_0613.zip` attached. The user extracts and runs `InvoiceViewer.exe`.
The dropper sets an HKCU Run key, looks up `cdn-pidgin-loader.net`, and its proxy CONNECT is
**blocked** (403). The CrowdFalcon alert fires at 09:18:04. The noise is developer activity
(git, VS Code, node, pytest), allowed proxy traffic and routine mail. There are no SMB, RPC,
RDP or WinRM connections from the host.

Every indicator in each mock alert appears in its telemetry. All attacker activity precedes
the alert's `detected_utc`, and every host is in the mock asset inventory.

### EDR/IDS vendor alerts

Vendor alerts are **ordinary telemetry**: `category = "alert"`, stored as `kind = alert`
evidence. They never become findings, approvals, decisions or authorization. Ground truth
deliberately does not count a vendor alert as attacker activity. It is a sensor's opinion,
and evaluating it is Phase 2C's job.

## Telemetry schema (`cyberrescue.telemetry/v1`)

| Field | Notes | → Evidence |
|---|---|---|
| `event_id` | `^[a-z0-9][a-z0-9-]{0,63}$`, unique per file | `source_ref` |
| `dataset` | Slug, e.g. `scenario-a` | `source = <provenance>.<dataset>.<sensor>` |
| `sensor` | Slug: `edr`, `winevt-security`, `netflow`, `dns`, `proxy`, `ids`, `web-access`, `mail-gateway`, `syslog` | `source`, `metadata.sensor` |
| `vendor` | Product name, data only | `metadata.vendor` |
| `timestamp` | ISO-8601 with timezone → UTC | `observed_at` |
| `category` | `process, file, network, auth, log, alert, ioc, other` | `kind` |
| `action` | Sensor event type (`process_start`, `4625`, `flow`, `edr_detection`) | `event_type` |
| `host`, `user` | Data only, never actors or bindings | `host`, `user` (`asset_id` only on an exact inventory match) |
| `message` | The raw sensor line, required | `raw` (verbatim) |
| `fields` | ECS-style normalised fields | `data` (verbatim) |
| `provenance` | `synthetic` (default), `replayed`, `live` | `provenance` |

The model is frozen and has `extra="forbid"`, so an event cannot carry an incident id,
evidence id, hashes or ingestion metadata. Evaluation-label keys (`label(s)`, `ground_truth`,
`gt`, `is_malicious`, `attack_stage`, `evaluation_only`) are refused anywhere in `fields`, at
any depth. Any object carrying `evaluation_only` is refused outright.

The adapter adds this `metadata`:
* `adapter` (`cyberrescue.telemetry.adapter/v1`);
* `telemetry_schema`, `dataset`, `sensor` and `vendor`;
* for synthetic data, `provenance_note`.

The Core alone assigns the incident, ids and hashes.

## Determinism and committed datasets

```text
datasets/cyberrescue/synthetic/
  manifest.json                 generator version, seeds, sha256, per-file counts (no labels)
  telemetry/scenario-{a,b,c}.jsonl
  ground_truth/scenario-{a,b,c}.json      EVALUATION ONLY
```

* Attacker timelines are fixed in code. Background noise comes from `random.Random(seed)`,
  with seeds 20260042, 20260041 and 20260039.
* Event ids are assigned **after** time-sorting (`scenario-a-000001`, …), so no id, sensor,
  `source` or file name hints at a label.
* Rendering is deterministic: sorted keys, ASCII-only JSON, `\n` line endings.
  `.gitattributes` pins `eol=lf` for `datasets/cyberrescue/**` because `core.autocrlf` would
  otherwise rewrite the bytes on Windows checkouts.
* `python -m cyberrescue.telemetry check` re-renders everything in memory and compares bytes.
  The test suite does the same, and also checks that output does not depend on
  `PYTHONHASHSEED`.

## Ground-truth isolation

Ground truth records the verdict, category, attacker event ids, attack chain stages, vendor
alert ids, hostile-content ids, benign explanations for confounders, and expected facts (e.g.
`lateral_auth_succeeded: ["srv-app-01"]`, `c2_contact: false` for C). The stage names are
plain descriptive labels, not an ATT&CK mapping.

It cannot become operational evidence, because:

1. It is a separate model in a separate tree, marked `"evaluation_only": true`.
2. The telemetry schema forbids its fields and label keys. The adapter refuses any object with
   `evaluation_only`, and the remaining fields still fail validation even without that marker.
3. The operational modules (`schema`, `adapter`, `catalog`, `importer`, `cli`) never import
   `ground_truth`, `scenarios` or `datasets`. A subprocess test checks `sys.modules`.
4. Import never opens a `ground_truth/` path. A `pathlib.Path` spy test checks this.
5. No stored evidence contains a label marker.
6. No CLI command prints ground truth.

## Security boundary

Phase 2B reuses Phase 2A unchanged. Only registered SYSTEM collectors and human operators may
submit evidence, and agents are rejected. Unknown and closed incidents are rejected, and closed
incidents are not reopened. Batches are all-or-nothing. Every record is sealed and audited.

`tests/test_telemetry_security.py` imports all three scenarios together with purpose-built
hostile telemetry: forged approval alerts, fenced SIGNOFF/VETO/RESOLUTION/APPROVAL blocks,
identity, incident and policy claims, an incident id in `host`, SQL injection and shell
payloads. The tests prove that:

* approvals, sign-offs, vetoes, holds, actors, incidents, aliases, action requests,
  decisions, risk snapshots, findings, claims and citations are **identical** before and after;
* the only new audit events are `EVIDENCE_INGESTED`;
* the policy `IncidentSnapshot`, its hash and the verdicts are identical;
* the Commander gate still DENIES `wipe_host` (P6, P8) in shadow mode and blocks it in enforce
  mode, even after a finding cites the alerts and the forged approval;
* a "Critical" vendor alert changes neither incident status nor severity;
* nothing reaches `extract_blocks`, and agents cannot smuggle telemetry through messages;
* AST checks find no authority-bearing call in any telemetry module or in the CLI ingest path.
  `open-incident` uses only `open_incident`.

## CLI

```powershell
python -m cyberrescue.telemetry list
python -m cyberrescue.telemetry show --scenario A           # counts only, no ground truth
python -m cyberrescue.telemetry generate                    # regenerate committed datasets
python -m cyberrescue.telemetry check                       # exit 1 if any byte differs

python -m cyberrescue.core register-actor --kind system --role collector --name "synthetic"
python -m cyberrescue.telemetry open-incident --scenario A  # operator step: opens INC-C from its mock alert
python -m cyberrescue.telemetry ingest --scenario A --collector <collector-id>
python -m cyberrescue.telemetry ingest --file events.jsonl --incident INC-C --collector <id>
python -m cyberrescue.core evidence --incident INC-C --kind alert
python -m cyberrescue.core verify
```

`--db PATH` works on both CLIs; the default is `$CYBERRESCUE_DB_PATH` or `<repo>/cyberrescue.db`.
A scenario always binds to the incident the catalogue maps it to, so `--scenario` with
`--incident` is rejected. `--file` requires an explicit `--incident`. In both cases the binding
comes from the operator, never from content. Re-ingesting is idempotent.

`open-incident` exists because the Core has no other "open incident" command. It is an
explicit, separate operator action and is idempotent. Ingestion never opens or changes an
incident.

## Tests

| File | Covers |
|---|---|
| `tests/test_telemetry_adapter.py` | Schema validation, forbidden fields and labels, field mapping, all-or-nothing loading |
| `tests/test_telemetry_scenarios.py` | Incident mapping, determinism (in process and across hash seeds), ordering and neutral ids, inventory hosts, alert alignment, indicators, no label leakage, per-scenario facts |
| `tests/test_telemetry_datasets.py` | Committed files byte-identical to a fresh render, LF, manifest hashes and counts, round-trip, tamper detection |
| `tests/test_telemetry_importer.py` | Import via the existing evidence path: binding, verbatim sealing, audit source, idempotency, collectors only, missing and closed incidents, all-or-nothing |
| `tests/test_telemetry_cli.py` | Every CLI command and its error exits |
| `tests/test_telemetry_security.py` | Hostile telemetry is inert; ground-truth isolation |

## Next: Phase 2C

**Implemented.** See [phase2c-detection.md](phase2c-detection.md). Deterministic detection
rules run over `list_evidence`. `cyberrescue/evaluation/`, which runs outside the Core,
measures them against `ground_truth/`.
