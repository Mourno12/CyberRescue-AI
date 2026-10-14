# 04 — Agent input/output definitions

Every agent:

- receives a Band message only when it is @mentioned;
- calls its own deterministic tools;
- replies through `thenvoi_send_message`, with human-readable text followed by
  one fenced `json` block that validates against
  `shared/schemas.py::ProtocolMessage`.

Required block fields are `type`, `incident` and `summary`. Optional fields are
`severity`, `evidence`, `deadline_utc`, `decision`, `regulation`, `actions`,
`recruited` and `mentions`.

The tool outputs below were **captured on 2026-10-11** by calling the real tool
functions offline (deterministic mock environment, no LLM). The protocol blocks
are **illustrative**: they show the required shape and are not output from a
live LLM run.

## Triage (LangGraph)

| | |
|---|---|
| Input | Alert text @mentioning Triage (from `python -m injector.inject_alert INC-C --dry-run`) |
| Domain tools | `classify_alert(incident)`, `lookup_asset(asset_id)` |
| Platform tools | `thenvoi_send_message`, `thenvoi_create_chatroom` (recruitment patched into code), `thenvoi_get_participants` |
| Output | `BRIEF` to the recruited specialists, or `CLOSE` for a false positive |

Real `classify_alert("INC-C")` output (abridged):

```json
{"incident_id": "INC-C-2026-0042", "disposition": "investigate", "severity": "critical",
 "category": "ransomware", "asset_id": "srv-db-01", "data_classes": ["customer_pii", "financial"],
 "recommended_specialists": ["compliance", "threat_intel", "commander"],
 "rationale": "3 known-malicious indicator(s) → Threat Intel ...; asset holds regulated data ... → Compliance ..."}
```

Illustrative output block:

```json
{"type": "BRIEF", "incident": "INC-C-2026-0042", "summary": "Critical ransomware on srv-db-01 (customer PII).",
 "severity": "critical", "recruited": ["threat_intel", "compliance", "commander"]}
```

## Threat Intelligence (LangGraph)

| | |
|---|---|
| Input | `BRIEF` or `QUESTION` @mentioning Threat Intel |
| Domain tools | `lookup_ioc(indicator)`, `assess_spread_risk(asset_id)`, `analyze_incident(incident)` |
| Platform tools | `thenvoi_send_message` only |
| Output | `FINDING` to the Commander, a `QUESTION` to Compliance, `SIGNOFF` |

Real outputs (abridged):

```json
{"indicator": "185.220.101.47", "matched": true, "malware_family": "BlackHaze ransomware",
 "actor": "FIN-Spectre", "lateral_movement": true, "confidence": "high"}
{"asset_id": "srv-db-01", "spread_risk": "critical", "containment_sufficient": false,
 "eradication_requires_reimage": true,
 "reachable_high_value_hosts": ["srv-app-01", "srv-dc-01", "srv-mail-01", "srv-backup-01"]}
```

## Compliance (Pydantic AI, second Band account)

| | |
|---|---|
| Input | `BRIEF`, `QUESTION` or `SIGNOFF_REQUEST` @mentioning Compliance |
| Domain tools | `check_regulatory_triggers(incident)`, `evidence_preservation_requirements(asset_id)`, `start_notification_clock(regulation, incident)`, `regulatory_clock_status(incident)` |
| Platform tools | `thenvoi_send_message` only |
| Output | `FINDING` (obligations plus a T-minus clock), `QUESTION`, `SIGNOFF`, or a `VETO` with `regulation` |

Real outputs (abridged):

```json
{"triggered": [{"rule_id": "GDPR-ART-33", "deadline": {"value": 72, "unit": "hours"}},
               {"rule_id": "SEC-8K-1.05", "deadline": {"value": 4, "unit": "business_days"}}]}
{"asset_id": "srv-db-01", "preservation_required": true, "blocks_destructive_actions": ["wipe_host", "reimage"],
 "requires_human_authorization_to_destroy": true, "image_satisfies_hold": false}
```

Illustrative VETO:

```json
{"type": "VETO", "incident": "INC-C-2026-0042", "summary": "srv-db-01 is under a legal hold.",
 "decision": "BLOCK wipe_host; ALLOW isolate_host + preserve_disk_image",
 "regulation": "GDPR-ART-33; SEC-8K-1.05; FORENSIC-RETENTION"}
```

## Incident Commander (Anthropic)

| | |
|---|---|
| Input | `FINDING`, `SIGNOFF`, `VETO`, or the human ruling @mentioning the Commander |
| Action tools | `isolate_host`, `preserve_disk_image`, `wipe_host`, `notify_stakeholders`. Each one calls the Core gate first |
| Platform tools | `thenvoi_send_message`, `thenvoi_get_participants`, `thenvoi_lookup_peers` |
| Output | `SIGNOFF_REQUEST`, `ESCALATION` to the human, `ACTION` per executed tool, `RESOLUTION` |

Real action-tool result with `CYBERRESCUE_GATE_MODE=enforce`, `CYBERRESCUE_INCIDENT=INC-C`
and no approvals (captured offline):

```json
{"status": "blocked_by_policy", "action": "wipe_host", "asset_id": "srv-db-01",
 "policy_outcome": "REQUIRE_APPROVAL",
 "reason_blocked": "P6: tier-3 action always requires human approval; P8: srv-db-01 is under legal hold ['GDPR-ART-33', 'SEC-8K-1.05', 'FORENSIC-RETENTION']; approval must override the hold with a reason",
 "note": "NOT executed: the CyberRescue Core did not authorize this action. ..."}
```

## Human CISO

| | |
|---|---|
| Input | `ESCALATION` @mentioning the CISO |
| Output (Band) | A plain-text ruling. It moves the Core incident AWAITING_HUMAN → RESPONDING when imported and the sender is rostered as `ciso`/`dpo`/`general_counsel`. It **creates no approval** |
| Output (Core) | `python -m cyberrescue.core approve --incident INC-C --action wipe_host --asset srv-db-01 --approver <id> --override-hold --override-veto --reason "..."`, the only way to authorize |

## How messages become Core records (ingestion)

| Block type | Core effect | Accepted only from |
|---|---|---|
| BRIEF / ESCALATION / RESOLUTION / CLOSE | state-machine trigger | roles permitted by the state machine |
| FINDING | finding attributed to its sender, with its claims stored as claims (not evidence); `evidence_ids` citations are checked separately | any sender (recorded and attributed; it authorizes nothing) |
| SIGNOFF_REQUEST | the plan sign-offs are checked against (latest wins) | Commander agent |
| SIGNOFF | sign-off on the **latest** request | recruited specialists (not Triage) |
| VETO | veto scoped to the tier-3 actions it names | Compliance, only if recruited |
| ACTION | `AGENT_ACTION_CLAIM`, a claim and never an authorization | Commander |
| malformed / no block | `UNSTRUCTURED_MESSAGE`, with no effect | — |
