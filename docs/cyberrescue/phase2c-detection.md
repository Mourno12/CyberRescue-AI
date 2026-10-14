# CyberRescue — Phase 2C: Detection & Correlation Engine

Phase 2C adds a deterministic, offline, explainable detection engine on top of the Phase 2A
evidence store. It turns evidence into *evidence-backed findings*. It never authorizes
anything.

```text
Synthetic telemetry → adapter → Evidence (Phase 2A/2B)
        ↓  CoreService.list_evidence(incident)        read-only
EvidenceView      one incident; Ev records without `raw`; AddressBook, DnsMap,
                  AssetContext, ThreatIntel (mock IOC DB)
        ↓  DetectionEngine.run                        pure: no I/O, no clock, no randomness
Layer 1 rules → Detection | Observation
Layer 2 correlators (CORR-001, ALERT-001)
        ↓
DetectionReport   byte-identical for identical evidence
        ↓  explicit operator step: run --persist --detector <SYSTEM detector actor>
FindingPublisher → CoreService.record_finding + link_evidence   (existing Phase 2A APIs)
```

Separately, and evaluation only: `cyberrescue/evaluation` takes the detection report and
joins it with `ground_truth/`.

The engine contains no LLM, no ML, no ATT&CK mapping, no risk score and no automated response.

## Detection vs Observation

| Output | Meaning | Persisted? |
|---|---|---|
| **Detection** | All *required* conditions matched, the rule's minimum corroboration was met, and there is ≥1 supporting evidence id (enforced by the model) | Only with `--persist` |
| **Observation** | Not a finding. One of four kinds: an indicator seen without malicious context (`indicator_observed`), an allowlisted candidate (`suppressed`), a vendor alert no detection cites (`uncorroborated_alert`), or required conditions without enough corroboration (`partial_match`) | Never |

This is the distinction between *indicator observed* and *correlated finding*.

## Rule model

Each rule is a Python class with a frozen `RuleSpec`:

| Field | Meaning |
|---|---|
| `rule_id` | Must match `^[A-Z]+-\d{3}$` |
| `version` | Bumped on any logic change |
| `name`, `description` | Human-readable text |
| `finding_type` | Plain labels, not ATT&CK: `execution`, `persistence`, `recovery_inhibition`, `credential_access`, `lateral_movement`, `command_and_control`, `privilege_escalation`, `exfiltration`, `impact`, `beaconing`, `multi_stage`, `vendor_alert` |
| `severity` | `low`, `medium`, `high` or `critical`: the incident `severity_hint` vocabulary |
| `window` | Named window in seconds, 1 s to 24 h |
| `conditions` | Each condition is `required` or `corroborating` |
| `base_confidence` | Starting confidence level |
| `min_corroboration` | Corroborating conditions needed for a Detection |

`Rule.result()` is the single place where condition results become a Detection or an
Observation. It lists **every** declared condition, matched or not, with its evidence ids and
structured detail.

**Confidence** uses the same `low` / `medium` / `high` vocabulary as `ioc_db.json`. It is a
fixed step function: the base level, raised one step for each corroborating condition matched,
capped at `high`. The calculation is recorded in `confidence_basis`, e.g.
`base low + 3/3 corroborating (…) -> high`. IOC rules inherit the indicator's own confidence.

**Identifiers** are content-derived:
* `detection_id = DET- + sha256(rule ␟ version ␟ incident ␟ supporting ids)[:24]`
* `detection_key = DK- + sha256(rule ␟ incident ␟ correlation key)[:24]`

**Registry:** `default_registry()` is frozen and rejects duplicate ids.
`ruleset_version = cyberrescue.detection/1+<sha256 of all specs>`.

## Rule catalogue

The windows were sized from the Phase 2B datasets.

| Rule | Detects | Required → corroborating | Window |
|---|---|---|---|
| AUTH-001 | Failed logons, then success | ≥2 × 4625 then 4624, same (target, account, source) → network logon, first-seen source | 5 min |
| AUTH-002 | Repeated failures without success | ≥3 × 4625, no success in the window → same corroborations | 5 min |
| LAT-001 | Remote auth to several hosts | Network logons by one account from one source to ≥2 hosts → SMB/RPC/RDP/WinRM flows, NTLM, the account ran a user-writable-path process on the source | 15 min |
| PROC-001 | Execution from a user-writable path | Image in ProgramData, a user's Downloads/AppData/Desktop/Documents, Users\Public or Temp → active IOC hash, file dropped on host, vendor alert (context); **min 1** | 30 min |
| PROC-002 | Suspicious script interpreter | Interpreter → suspicious arguments (encoded command, download cradle, URL, hidden window, bypass) or an Office/browser/dropper parent; **min 1** | 30 min |
| RECOV-001 | Recovery inhibition | vssadmin/wmic/bcdedit/wbadmin destruction → user-writable parent | 30 min |
| PERSIST-001 | Autostart to a user-writable path | 7045 service or Run/RunOnce value → the target ran, the target's hash is an IOC; **min 1** | 1 h |
| PRIV-001 | New privileged account | 4720 plus 4728/4732/4756 into a privileged group → privileged logon. Existing-account changes are Observations | 1 h |
| IOC-001 | Known-malicious hash executed | `process.hash.sha256` is an active IOC → vendor alert (context) | 30 min |
| IOC-002 | Contact with malicious infrastructure | Outbound flow, connect, DNS or proxy request to an active IP/domain → connection established. Blocked or attempted contact is medium severity. Inbound-only sightings are Observations | 30 min |
| NET-001 | Beaconing | ≥4 regular flows to one external destination (jitter ≤ max(5 s, 5 %)). Suppressed when the destination, or a DNS name it was resolved from, is allowlisted | 6 h horizon |
| DATA-001 | Exfiltration from a sensitive asset | PII/financial/credentials asset with ≥50 MB to one external destination → database dump in the hour before. A dump followed by a small external transfer is an Observation | 15 min |
| RANSOM-001 | Encryption activity | ≥20 renames by one process, ≥90 % to one new extension → ransom note in ≥3 directories, recovery inhibition, vendor alert (context); **min 1**. No extension list | 5 min |
| CORR-001 | Multi-stage host chain | ≥3 distinct finding types on one host (lateral movement counts on its *source* host) → an archive e-mail delivered to a chain user (context) | 60 min |
| ALERT-001 | Uncorroborated vendor alert | Observation only | — |

**Where the windows come from:**

| Window | Evidence in the datasets |
|---|---|
| Auth, 5 min | Attacker bursts last 9–20 s; the nearest benign failure → success pair is 28 min apart |
| Lateral, 15 min | The sweep spans 67 s |
| Mass rename, 5 min | 34 renames in 131 s |
| Corroboration, 30 min | Shadow deletion is 3.5 min before the renames; the alert is 10 s after them |
| Chain, 60 min | The stages span about 6.5 min in both A and C |
| Beacon | B's flows repeat at 300 ± 2 s and 600 s |

**Not data-derived (decision D1 = a):** PRIV-001, DATA-001 (including the 50 MB threshold) and
the positive cases of PROC-002 have no scenario data. They are covered by unit fixtures only.

**Threat intel** matching is exact, on normalised structured fields only. As a result,
`198.51.100.234` does not match the indicator `198.51.100.23`. `status: benign` entries in
`ioc_db.json` are the allowlist.

## Results on the Phase 2B scenarios

| Scenario | Findings | Observations |
|---|---|---|
| A / INC-C | 10: AUTH-001, AUTH-002, LAT-001, PROC-001, PERSIST-001, RECOV-001, IOC-001, IOC-002 (established), RANSOM-001 (critical/high), CORR-001 (6 stages on srv-db-01) | DATA-001 partial: `pg_dump`, then only 48 KB external |
| B / INC-B | **0** | NET-001 suppressed ×2 (8.8.8.8; 13.107.4.50 via its DNS name windowsupdate.microsoft.com); IOC-002 inbound HollowRAT IP (HTTP 400); ALERT-001 for the IDS alert |
| C / INC-A | 5: PROC-001, PERSIST-001, IOC-001, IOC-002 (**blocked**, medium), CORR-001 (phishing mail as context) | — |

The benign decoys never appear as supporting evidence: the legitimate `pg_dump` backup, the
rsync flows to the backup vault, `mchen`'s mistyped password, and the health checks.

## Findings and persistence (decisions D2, D4)

* **Dry run is the default.** `run --persist --detector <id>` writes findings. Ingestion never
  triggers detection.
* **Writes go only through Phase 2A APIs:**
  * `record_finding` creates the finding with severity and template summary. It adds the
    supporting citations under the strict same-incident check, and **one claim of
    kind `detection`** holding the canonical JSON of the Detection.
  * `link_evidence` adds the context citations.
  * The publisher writes one report in a single transaction, so any failure stores nothing.
* **D2:** `record_finding(…, claim_kind="protocol_claim")`. The new parameter is optional and
  the default is unchanged.
* **Who may publish:** only a registered SYSTEM actor with role `detector`. Collectors, agents
  and humans are refused.
* **Idempotency:** publishing is idempotent by `detection_id`. If the evidence behind a
  `detection_key` changes, a new finding records which one it `supersedes`; findings are
  append-only.
* **Closed incidents** refuse new citations, through the existing Phase 2A freeze.

## Security boundaries (`tests/test_detection_security.py`)

* **No authority side effects.** Persisting findings for all three scenarios plus hostile
  telemetry leaves approvals, sign-offs, vetoes, holds, actors, incidents, aliases, requests,
  decisions, risk and evidence unchanged. The only new audit events are `FINDING_RECORDED`,
  `CLAIM_RECORDED` and `FINDING_EVIDENCE_LINKED`.
* **Policy and gate unchanged.** The policy snapshot, its hash and the verdicts are identical,
  and the Commander gate still denies `wipe_host` (P6, P8) in shadow mode and blocks it in
  enforce mode. Findings are not part of `IncidentSnapshot`.
* **Rules never read `raw`.** They only see `Ev` records, which have no `raw` field; an AST
  check enforces this. IOC and ransomware text that appears only in the raw line is never
  detected.
* **Forged fields are ignored.** Evidence fields named `allowlisted`, `suppress`, `approved`,
  `incident` or `rule_id` have no effect.
* **Summaries interpolate only plain identifiers** (`[A-Za-z0-9._-]{1,64}`); anything else is
  printed as `<unprintable>`. Attacker text stays as structured data, for the future LLM layer
  to treat as data.
* **Nothing is executed.** Nothing reaches the protocol parser. Incident ids found inside
  evidence are ignored.
* **AST checks** cover every detection module: no authority calls, no execution, no
  clock/random/uuid. The publisher calls only `record_finding` and `link_evidence`.
* **Ground truth stays out.** A subprocess check shows the detection package never loads ground
  truth, the scenario generators, evaluation code or LLM clients. A file-read spy shows no
  dataset file is opened.

## Evaluation (`cyberrescue/evaluation`, evaluation only)

`python -m cyberrescue.evaluation run [--scenario A] [--json]` runs each scenario in a
temporary Core and joins the detection report with the ground truth on `source_ref`. It
deliberately reports no single accuracy number. Instead it gives:

* stage coverage (by supporting-evidence overlap) and type agreement;
* expected and unexpected findings;
* evidence coverage and precision, as exact ratios;
* observations;
* the per-rule matrix;
* fact checks. A fact with no extractor is reported as `not_evaluated`, never as a pass.

| | Stages | Malicious evidence supported | Unexpected findings | Facts |
|---|---|---|---|---|
| A | 5/5 | 58/58 | 0 | 15 match, 1 not evaluated (`lateral_code_execution_observed`); Phase 3 closes this through gap G1, giving 16/16 |
| B | — | 0/0 | 0 | 7/7 match |
| C | 4/4 | 5/6 (6/6 including context) | 0 | 10/10 match |

**Caveat:** the rules were designed with knowledge of these three datasets, so these numbers
show consistency, not generalisation.

## CLI

```powershell
python -m cyberrescue.detection rules [-v]
python -m cyberrescue.detection run --incident INC-C [--json] [--explain]
python -m cyberrescue.core register-actor --kind system --role detector --name engine
python -m cyberrescue.detection run --incident INC-C --persist --detector <actor-id>
python -m cyberrescue.detection findings --incident INC-C
python -m cyberrescue.evaluation run [--scenario A] [--json]
```

## Compatibility

* The schema is still v2: no migration.
* Evidence, datasets, ground truth, the policy engine and the Commander gate are unchanged.
* Shadow and enforce modes behave identically to before.
* The only Core change is the optional `claim_kind` parameter.
* No WarRoom file and none of the original 77 tests were modified.

## Known limitations

* The rules are tuned to the Phase 2B field names (EDR, Windows Security events, NetFlow, DNS,
  proxy). Other sources need adapter mappings.
* IP→host resolution is learned from evidence. NAT or DHCP churn leaves addresses unresolved,
  and WorkstationName can be spoofed.
* Detections overlap by design: AUTH, LAT, PROC and IOC rules can describe the same events, and
  CORR-001 summarises them.
* Evidence is trusted as collected. A forged structured field would be believed; collector
  signing is future work.
* A persisted finding's id and creation time come from the Core (uuid4 and clock). The
  determinism guarantee covers the `DetectionReport` and its `detection_id`.

## Next: Phase 3

**Implemented.** See [phase3-investigation.md](phase3-investigation.md). The read-only
Investigation Layer consumes these detections and findings: it builds timelines, entity graphs,
scope, forensic gaps and verifiable case exports.
