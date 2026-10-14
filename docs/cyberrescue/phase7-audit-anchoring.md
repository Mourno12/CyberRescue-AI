# CyberRescue — Phase 7: External Keyed Audit Anchors

## Objective

The Core's audit log is one SHA-256 hash chain per incident, plus `__system__`. Triggers block
update and delete, and `AuditLog.verify` recomputes each chain. That makes the log
**tamper-evident**, but not proof against someone who can write the database file. Such a
person can:
* drop the triggers;
* rewrite history and recompute every hash;
* or simply delete the tail of a chain.

`core verify` would still pass.

Phase 7 makes those attacks **detectable**, without changing the chain. An **anchor** is a
checkpoint of every chain head (sequence number and hash). It is signed with **HMAC-SHA256**
under a key kept **outside the database and the repository**, and stored by the operator
elsewhere. `core verify --anchor` proves that the database still contains exactly those heads at
those positions, while still allowing the chain to grow.

## Decisions

| | Decision |
|---|---|
| Q1 | Keyed external audit anchors |
| Q2 | Chain heads only; no database identity field, no `schema_meta` change, schema stays **v3** |
| Q3 | Nothing recorded in the Core; anchoring appends no event and changes no chain |
| Q4 | Core CLI only; `verify-case`, `verify-plan` and `execution verify` are unchanged |
| Q5 | Key **file** only (`--key-file` / `CYBERRESCUE_ANCHOR_KEY_FILE`); no raw key in the environment; key files inside the repository are refused |

**Unchanged:**
* the audit hash formula, `AuditLog.append`/`verify`, triggers, schema and migrations;
* policy (`policy-v2`), the Commander gate, the WarRoom agents;
* `CoreService` authority methods;
* Phase 3 case identity and `verify-case`, Phase 4 plan identity and `verify-plan`;
* Phase 5 and Phase 6 behaviour;
* detection, datasets and ground truth.

## Threat and trust model

**Attacker:** can read and write the SQLite file (drop triggers, edit, insert or delete rows,
recompute hashes) but **does not hold the anchor key**.

**Trust:**
* *Trusted:* the key file, and anchor files the operator keeps outside the attacker's reach
  (another host, write-once storage, a ticket, an e-mail to oneself).
* *Untrusted:* the database file.

| Attack | Result with an anchor |
|---|---|
| Rewrite an event at or before the anchored sequence, recompute every hash, drop the triggers | **Detected:** `rewritten` (the hash at the anchored sequence differs) |
| Delete the tail of a chain, below the anchored sequence | **Detected:** `truncated` |
| Delete recorded `ACTION_EXECUTED`/`ACTION_VERIFIED` events that were anchored | **Detected:** `truncated` |
| Delete a whole anchored chain | **Detected:** `missing` |
| Tamper with an event *after* the anchor without recomputing hashes | **Detected:** `broken` (the existing `AuditLog.verify` still runs) |
| Edit the anchor file (sequence, hash, chains, time, tag) | **Detected:** HMAC failure |
| Use a different key | **Detected:** HMAC failure |
| Append new, correctly chained events after the anchor | Accepted as growth (by design) |
| A forged trailing `ACTION_EXECUTED`/`ACTION_VERIFIED` after the anchor | Growth for the anchor. Caught by `verify_accountability` (no execution record), as in Phase 6 |
| Holder of the key | Out of scope: can forge anchors |
| Roll back both the database and the operator's anchors | Undetectable: keep anchors where the attacker cannot reach |

## Key handling (`core/anchor.py`)

* **Generate:** `core anchor-keygen --out FILE` writes 32 bytes from `secrets.token_bytes`.
  * The file is created exclusively (`open(..., "xb")`), so it **never overwrites** anything.
  * Paths **inside the repository** are refused, including relative ones.
  * Permissions are set to 0600 where the OS supports it.
* **Format (ASCII):**
  ```text
  cyberrescue-anchor-key/1
  <lowercase hex, at least 32 bytes>
  ```
* **Load:** from `--key-file`, or `CYBERRESCUE_ANCHOR_KEY_FILE` (a *path*). Refused keys:
  * missing, not a regular file, or unreadable;
  * malformed: wrong header, bad hex, extra lines, non-ASCII, oversized;
  * weak: fewer than 32 bytes, or fewer than 16 distinct byte values;
  * inside the repository.
* **Non-disclosure:**
  * The key lives only in an `AnchorKey`. It is redacted in `repr`/`str`, immutable, and
    cannot be pickled, copied or converted to JSON.
  * Its only use is `AnchorKey.mac()`.
  * Errors are fixed messages raised `from None`, so no key material is echoed or chained.
  * The key never reaches the database, audit events, logs, stdout, reports, case or plan
    exports, or anchor files (tested).
* **Operator guidance:**
  * Keep the key off the database host if possible, or at least outside the project and the
    database directory, readable only by the operator.
  * Back it up. Without it, anchors cannot be checked.
  * Rotate it by generating a new key and taking a new anchor. Keep old keys to check old
    anchors.

## Checkpoint format and HMAC

```json
{"checkpoint":{"chains":{"<chain>":{"hash":"<sha256 hex>","seq":<n>}, ...},
               "created_at":"<ISO-8601>","schema":"cyberrescue.audit-anchor/1",
               "schema_version":3},
 "hmac_sha256":"<hex>"}
```

* **Serialization:** strict canonical JSON, one line plus a newline. Keys are sorted, there is
  no whitespace, all output is ASCII (`\uXXXX` escapes), and NaN/Infinity and unknown types are
  rejected.
* **Signature input:** `HMAC-SHA256(key, b"cyberrescue.audit-anchor/1\n" + canonical(checkpoint))`.
  * The domain label separates anchors from any other use of the key.
  * The input is unambiguous and independent of how the file is formatted.
* **What a checkpoint holds:** the head of **every** chain (`SELECT` of the highest `seq` and its
  `hash`), the schema version, and `created_at` (the Core clock). Everything except `created_at`
  is deterministic for a given database state. There is no key material and no database
  identity field.
* **Parsing is strict:**
  * no duplicate keys;
  * exact field sets;
  * types (integer `seq ≥ 1`, booleans rejected);
  * lowercase 64-hex hashes and tag;
  * the exact schema label;
  * then a constant-time HMAC comparison (`hmac.compare_digest`).

## Verification semantics (`verify_checkpoint`)

**Three outcomes, never conflated:**

| Outcome | Raised / returned | CLI exit |
|---|---|---|
| Malformed anchor | `AnchorFormatError` | 2 |
| HMAC does not match (altered anchor *or* different key) | `AnchorSignatureError` | 2 |
| Valid anchor; the database differs | `AnchorVerifyResult.ok == False` | 1 |
| Valid anchor; the database matches or has grown | `AnchorVerifyResult.ok == True` | 0 |

**Per chain:**
* The event at the anchored sequence must exist, with the anchored hash.
* The whole chain must still pass the unchanged `AuditLog.verify`.
* The schema version must equal the anchored one.

**Statuses:**

| Status | Meaning | Valid? |
|---|---|---|
| `ok` | The anchored head is still the head | yes |
| `grown` | The anchored event is intact; the chain has grown since | yes |
| `unanchored` | A chain created after the anchor (reported) | yes |
| `rewritten` | Different hash at the anchored sequence | no |
| `truncated` | The anchored sequence no longer exists | no |
| `missing` | An anchored chain is absent | no |
| `broken` | The chain fails `AuditLog.verify` | no |

**Growth after an anchor is valid:** new events, new incidents and new chains are normal
operation. The anchor protects the **prefix it covers**. Anything appended later is protected
only by the *next* anchor, so take anchors regularly (e.g. after each significant decision, at
shift change, before and after exports).

**Stale anchors** stay valid for the prefix they cover. A fresh anchor only extends coverage, and
nothing ever invalidates an old one except tampering or a schema change.

**Schema.** `core anchor` refuses a database that is not at the current schema version (run
`core init` first). Every other Core command migrates on open, which would otherwise change the
schema version the anchor recorded. After a future migration, old anchors report a schema
mismatch, which is reported as a mismatch rather than ignored.

**Rollback.** Anchoring changes no stored data, so "rolling back" Phase 7 means simply not using
`--anchor`. A database restored from backup verifies against anchors taken before the backup,
and fails (`truncated`/`rewritten`) against later anchors, as it should.

## Relationship to Phases 3, 4 and 6

* **Phase 3 case identity / Phase 4 plan identity.** Anchoring appends no event and changes no
  chain, so `case_sha256` and `plan_sha256` are unchanged (tested for A, B and C). Cases still
  carry their own anchored head (`integrity.audit_head_hash`).
  `verify-case`/`verify-plan` are unchanged; external-anchor integration there is future work
  (Q4).
* **Phase 6 accountability.** Execution events before an anchor are protected by it: deleting
  them is `truncated`. A forged trailing accountability event after the anchor is growth for
  the anchor and is caught by `verify_accountability`.

## CLI

```powershell
python -m cyberrescue.core anchor-keygen --out D:\secure\cyberrescue-anchor.key
python -m cyberrescue.core anchor --out D:\anchors\2026-10-04T1200.json --key-file D:\secure\cyberrescue-anchor.key
$env:CYBERRESCUE_ANCHOR_KEY_FILE = "D:\secure\cyberrescue-anchor.key"
python -m cyberrescue.core verify --anchor D:\anchors\2026-10-04T1200.json
python -m cyberrescue.core verify --incident INC-C --anchor D:\anchors\2026-10-04T1200.json
```

* **`anchor`:**
  * reads through a **read-only** SQLite connection, with no `CoreService`;
  * never creates a database;
  * never overwrites an anchor file.
* **`verify --anchor`:**
  * loads the key and authenticates the anchor before printing anything;
  * then prints the unchanged `verify` report, then the anchor section with database-controlled
    chain ids escaped to ASCII.
* **Exit codes:**
  * 0: verified;
  * 1: database mismatch, or existing audit or evidence tampering;
  * 2: missing or invalid key, malformed or unreadable anchor, failed HMAC, missing database,
    incident not covered, usage errors.
* **Without `--anchor`,** `verify` behaves exactly as before.

## Security invariants (tests)

| Invariant | Tests |
|---|---|
| Rewrite plus full rehash with dropped triggers is detected; truncation (including accountability events), chain deletion and post-anchor breakage are detected | `test_anchor_verify.py`, `test_audit_anchor_security.py` (1–5, 15) |
| Any edit to an anchor, an added or removed chain, or a wrong key fails | `test_anchor_checkpoint.py`, `test_audit_anchor_security.py` (6–8) |
| The key never leaks (stdout, stderr, logs, anchors, exports, database) | `test_anchor_key.py`, `test_anchor_checkpoint.py`, `test_core_cli_anchor.py`, security (9) |
| Anchoring and verifying create no state; audit rows are byte-identical; case and plan hashes unchanged | security (10–13) |
| Growth accepted; forged trailing executions left to `verify_accountability` | security (14, 16) |
| Hostile chain ids keep canonical single-line ASCII JSON | `test_anchor_checkpoint.py`, security (17) |
| Missing, malformed or weak keys fail closed; overwrite refused; repository paths refused | `test_anchor_key.py`, security (18–19) |
| `verify` without `--anchor` unchanged | `test_core_cli_anchor.py`, security (20) |
| `anchor.py`: no write SQL, only `SELECT`, no authority operation, no `.audit` access, a single exclusive-create file write for new keys | security (static) |

## Known limitations

* **Anchor freshness.** Anchors protect only what they cover. Events after the latest anchor are
  only as safe as the unkeyed chain until the next anchor.
* **Storage of anchors and the key.** The guarantee depends on keeping both away from the
  attacker. A key holder can forge anchors, and rolling back both the database and the anchors
  is undetectable.
* **The chain itself is still unkeyed** (by decision); evidence is still not signed by
  collectors.
* **No layer integration yet:** `verify-case`, `verify-plan` and `execution verify` don't take
  `--anchor` (Q4).
* **Pre-existing terminal output:** the original `core verify` report prints chain ids
  unescaped. It is left unchanged by Phase 7's no-behaviour-change rule; the new anchor section
  escapes them.
* **Still deferred:** G5, executor-actor identity, dataset-specific rules, identity resolution,
  WarRoom `INC-[ABC]` regexes. There is still no real execution.
