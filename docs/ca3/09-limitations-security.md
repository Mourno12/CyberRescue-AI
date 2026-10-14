# 09 — Limitations and security considerations

## What is not proven

| Claim | Status |
|---|---|
| The four LLM agents collaborate end to end through Band | **UNVERIFIED in this work.** No credentials were configured and no live run was approved. Upstream WarRoom files (`TEST_RESULTS_OPTION_B.md`, `PHASE_4_PROTOCOL_TEST.md`) describe earlier live runs by the upstream author. They were not reproduced here and are not evidence for this submission |
| Live SIGNOFF/VETO reach Core authorization during a run | **NOT VERIFIED live.** `live sync` does this in offline tests with MOCKED Band clients ([02 §6](02-system-design.md#6-live-integration-gap-and-how-it-is-addressed)) |
| Detection quality on real telemetry | **Not evaluated.** All telemetry is SYNTHETIC (3 scenarios); results show internal consistency against generated ground truth, not real-world accuracy |
| Response actions work on real systems | **Not attempted by design.** All execution is SIMULATED |

## Known limitations

1. **Upstream handles are rendered, not removed.** The prompts and Facilitator
   texts still contain the upstream handles. They are replaced at load time from
   `agent_config.yaml`, and an agent refuses to start if anything stays
   unresolved. `shared/protocol.md` (documentation) still lists the upstream
   handles.
2. **Live sync is untested against real Band.** Real view latency, ordering and
   timestamp formats are unknown. The one real sample (`shared/sample_message.json`)
   uses UUID ids and `...ssssssZ` timestamps. The sync halts on out-of-order
   arrival rather than guessing, and recovery is a manual operator procedure
   (runbook §6). A message imported out of order before a halt (for example a
   SIGNOFF whose SIGNOFF_REQUEST had not yet been seen) is rejected by the
   ingestor and stays rejected. The settle window and the all-views-or-nothing
   rule reduce this but cannot rule it out. Ties in timestamp are ordered by
   message id, which is deterministic but not necessarily the true order. A
   Commander tool call made between a sign-off and the next poll is blocked, and
   the Commander must retry. The approval invariant and post-import chain check
   **detect** after commit; making them preventive is proposed but not
   implemented (02 §6).
3. **Band free tier.** No single key reads a whole room. The export takes the
   union of every agent key's view, so messages that @mention none of our agents
   (for example a CISO message tagging only a person) can be missing. The export
   records per-view success so gaps are visible.
4. **Messages without a Band id are not de-duplicated** by `ProtocolIngestor`
   (`live sync` and `export-band` reject or drop id-less records),
   because de-duplication keys on `external_id`. Real Band messages always carry
   an id, and `export-band` drops id-less records, so the documented path is not
   affected. Hand-built transcripts could double-import. Found by probing on
   2026-10-11; Core is left unchanged.
5. **Haiku Commander reliability.** Upstream notes say Haiku can loop on
   sign-offs instead of acting. Sonnet is more decisive at higher cost
   (`run_all.ps1 -CommanderModel`).
6. **Gate binding.** Without `CYBERRESCUE_INCIDENT` the gate binds to the most
   recent open incident on the target asset. The preflight warns about this in
   enforce mode.
7. **ip/account policy targets.** `block_ip` and `disable_account` requests carry
   `asset_id=None` (a Core schema limitation noted in Phase 4–6 docs), so
   per-target policy rules for them are deferred.
8. **`core verify` prints chain ids unescaped** (an open Phase 7 finding). It is
   cosmetic, and the anchor path escapes them.
9. **The anchor key is only as safe as its storage.** The offline demo keeps a
   demo key next to its output for convenience. In real use, keep it apart from
   the database.

## Threat model summary

| Threat | Control | Evidence |
|---|---|---|
| An LLM fabricates an approval ("CISO approved") | Approvals only via `grant_approval` by a registered human approver | `test_synthetic_inc_c_run_through_the_gate`, `test_action_claims_authorize_nothing` |
| An unrostered or impostor sender signs off or vetoes | Roster-based identity from transport metadata | `test_unrostered_senders_get_powerless_roles`, `test_escalation_waits_for_a_rostered_human_with_authority` |
| A message for another incident | Context-bound incident; `INCIDENT_REF_MISMATCH` | `test_block_for_another_incident_is_flagged` |
| A replayed or duplicate message | De-duplication by Band message id | `test_reimport_is_idempotent`, `test_duplicate_band_message_id_is_ingested_once` |
| A duplicate action call | Single-use approvals | `test_enforced_commander_acts_once_on_valid_signoffs_and_approval` |
| Core unavailable or misconfigured | Fail closed in enforce; typo never enforces | `test_enforce_fails_closed_*`, `test_gate_typo_never_reports_enforce` |
| Destroying evidence under a legal hold | P8 needs `overrides_hold` plus a reason; P6 tier-3 needs a human | offline demo step 6b |
| Audit log edited in the database | Per-incident hash chains plus a keyed external anchor | offline demo step 9; `test_audit_anchor_security.py` |
| Secrets leaking to Git or logs | Gitignored config; preflight checks tracking; values never printed | `test_no_secret_value_appears_in_any_output`, `test_tracked_secret_file_fails` |
| A half-started agent team | Launcher preflight plus stop-all on startup failure | `run_all.ps1` (refusal observed on 2026-10-11) |
| Sync turns a chat message into an approval | Sync calls no authorizing API; a runtime invariant halts on any approval/authorization event caused by an import | `test_import_that_would_create_an_approval_halts`, `test_sync_source_never_calls_authorizing_apis`, `test_synced_signoffs_reach_the_gate_but_human_approval_is_still_required` |
| Partial / reordered / wrong-room transcript | All views or nothing; settle window; out-of-order, invalid and correlation halts | `test_incomplete_views_*`, `test_out_of_order_arrival_halts_without_importing`, `test_invalid_messages_halt_before_import`, `test_blocks_for_another_incident_halt` |
| Lexical vs chronological timestamp order | UTC-normalised (instant, id) order; one-message-per-import; timezone-less rejected | `test_lexical_order_differs_but_import_follows_chronology` (also mutation-checked), `test_equivalent_timestamps_normalise_to_one_instant` |
| Failed sync logged as success | Fail-safe terminal record; bounded lock retry; exit code matches the last record | `test_retry_exhaustion_*`, `test_non_retryable_sqlite_error_halts_immediately`, `test_base_exception_still_writes_a_failed_terminal_record` |
| Placeholder config passes preflight | Shared placeholder detector; runbook YAML and example file must fail | `test_documented_example_configurations_fail_preflight` |
| Runtime artifacts committed by accident | Sync/roster/export refuse repo paths; gitignore backstop | `test_sync_refuses_a_database_inside_the_repo`, `test_runtime_artifact_names_are_gitignored` |
| Re-sync double-imports | Id filter + ingestor de-dup + UNIQUE index + one sync per DB (lock) | `test_repeated_polls_are_idempotent`, `test_sync_after_a_manual_import_adds_nothing`, `test_one_sync_per_database` |
| Agents start mentioning non-existent identities | Handles rendered from config; unresolved handle → agent refuses to start; preflight `[identities]` / `[prompts]` | `tests/test_live_handles.py` |
