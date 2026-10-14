"""The response playbook (versioned data): which facts lead to which proposals.

Only DETERMINISTIC DETECTIONS trigger proposals. Agent findings (Band imports),
human findings, observations and vendor alerts never do - so no LLM-written or
attacker-written text has a route into a proposed action.

    compromised host (execution / persistence / recovery inhibition / impact /
      multi-stage detection)  -> isolate_host, then preserve_disk_image;
                                 wipe_host as a DECISION, and restore_from_backup
                                 as a DECISION where impact (RANSOM-001) is seen
    malicious executable (IOC-001 / PROC-001, PERSIST-001 target)
                              -> quarantine_file, after imaging
    malicious process (IOC-001 / PROC-001 / RANSOM-001)
                              -> kill_process (irreversible), after imaging
    established external C2 (IOC-002)
                              -> block_ip (validated target)
    successful lateral authentication (AUTH-001 / LAT-001)
                              -> disable_account (validated, not protected) -
                                 a protected account becomes a DECISION
    accessed host (no compromise detection)
                              -> preserve_disk_image only (no isolation without
                                 evidence of compromise)
    any proposal              -> notify_stakeholders (CISO; + DPO, Legal when a
                                 notification regulation applies or a host is
                                 under legal hold)
    notification regulation applies
                              -> notify_regulator as a DECISION
    every Phase 3 gap         -> an investigative TASK (never an action)

Every human-readable string is a fixed template; only safe tokens
(``safe_token``) are interpolated.
"""

from __future__ import annotations

from dataclasses import dataclass

from cyberrescue.detection.matchers import safe_token

PLAYBOOK_VERSION = "playbook-v1"
PHASE_ORDER = ("notify", "contain", "preserve", "eradicate")

MALWARE_RULES = ("IOC-001", "PROC-001")
PROCESS_RULES = ("IOC-001", "PROC-001", "RANSOM-001")
PERSISTENCE_RULE = "PERSIST-001"
C2_RULE = "IOC-002"
LATERAL_AUTH_RULES = ("AUTH-001", "LAT-001")
IMPACT_RULE = "RANSOM-001"
CRITICAL = ("high", "critical")
CRITICALITY_CAUTION = ("{host} is a {criticality}-criticality asset; this action interrupts "
                       "the services it provides.")
BASE_STAKEHOLDERS = ("CISO",)
DATA_STAKEHOLDERS = ("CISO", "DPO", "Legal")


class Text(str):
    """Text that is already a filled template (e.g. a target-refusal reason) and is
    passed through ``fill`` unchanged. Never wrap evidence-derived values in it."""


def _safe(value: object) -> str:
    if isinstance(value, Text):
        return str(value)
    if isinstance(value, (list, tuple)):
        return ", ".join(safe_token(x) for x in value) or "-"
    return safe_token(value)


def fill(template: str, **values: object) -> str:
    """Format ``template`` with values reduced to safe tokens (lists are joined)."""
    return template.format(**{k: _safe(v) for k, v in values.items()})


@dataclass(frozen=True)
class StepTemplate:
    action: str
    phase: str
    rationale: str
    success: tuple[tuple[str, str], ...] = ()        # (check, description template)
    cautions: tuple[str, ...] = ()


STEPS: dict[str, StepTemplate] = {
    "isolate_compromised": StepTemplate(
        "isolate_host", "contain",
        "{host} shows evidence of compromise ({rules}). Network isolation stops spread "
        "and C2 while the host stays powered on for imaging.",
        (("no_network_activity_from_host",
          "No network activity from {host} after isolation except the management channel."),)),
    "preserve_compromised": StepTemplate(
        "preserve_disk_image", "preserve",
        "Capture disk and memory of {host} before anything changes its state; "
        "eradication on this host must wait for the image.",
        (("image_recorded", "A forensic disk and memory image of {host} is recorded."),)),
    "preserve_accessed": StepTemplate(
        "preserve_disk_image", "preserve",
        "{account} authenticated successfully to {host} ({rules}). Whether code ran there is "
        "not observed; an image preserves the answer. No isolation is proposed without "
        "evidence of compromise.",
        (("image_recorded", "A forensic disk and memory image of {host} is recorded."),)),
    "kill_process": StepTemplate(
        "kill_process", "eradicate",
        "{process} on {host} matches {rules}. If it is still running, terminating it stops "
        "further damage; it comes after imaging so memory evidence is kept.",
        (("no_process_activity", "No activity by {process} on {host} after termination."),),
        ("kill_process is irreversible; the process name comes from evidence - confirm it "
         "before requesting.",)),
    "quarantine_file": StepTemplate(
        "quarantine_file", "eradicate",
        "The executable used on {host} ({rules}) is moved to quarantine after imaging so "
        "it cannot run again; the path is evidence-derived and shown as untrusted data.",
        (("file_absent", "The file is absent from its original path on {host}."),),
        ("The file path comes from evidence; confirm it before requesting.",)),
    "block_ip": StepTemplate(
        "block_ip", "contain",
        "{hosts} established a connection to known-malicious {ip} ({family}, {rules}). "
        "Blocking it at the egress firewall cuts the C2 channel.",
        (("no_connection_to_indicator", "No connection to {ip} from any host after the "
                                         "block."),)),
    "disable_account": StepTemplate(
        "disable_account", "contain",
        "{account} authenticated remotely to {hosts} ({rules}). Disabling it stops further "
        "use of the credentials.",
        (("no_successful_logon_by_account", "No successful logon by {account} after it "
                                             "is disabled."),),
        ("The account name comes from evidence; confirm it and the business impact (for "
         "example scheduled jobs that run as it) before requesting.",)),
    "notify_internal": StepTemplate(
        "notify_stakeholders", "notify",
        "Internal notification of {recipients}: the plan proposes response actions on "
        "{hosts}.",
        (("notification_recorded", "A notification to {recipients} is recorded."),)),
}


@dataclass(frozen=True)
class DecisionTemplate:
    action: str
    reason_code: str
    question: str
    rationale: str


DECISIONS: dict[str, DecisionTemplate] = {
    "wipe_host": DecisionTemplate(
        "wipe_host", "tier3", "Wipe and reimage {host}?",
        "Eradication destroys forensic state and is irreversible (tier 3). Only a human "
        "decides it, after isolation and imaging; legal holds and vetoes apply."),
    "restore_from_backup": DecisionTemplate(
        "restore_from_backup", "tier3", "Restore {host} from backup?",
        "Recovery overwrites the current state of {host} (tier 3). Only a human decides "
        "it, after imaging; the backup's integrity must be confirmed first."),
    "notify_regulator": DecisionTemplate(
        "notify_regulator", "tier3", "Notify the regulator under {regulations}?",
        "Data classes at risk ({classes}) fall under notification rules with deadlines. "
        "External notification is irreversible (tier 3) and is a human decision."),
    "protected_account": DecisionTemplate(
        "disable_account", "protected_target", "Disable protected account {account}?",
        "{account} authenticated remotely to {hosts} ({rules}) but is on the protected-"
        "accounts list, so the planner does not propose disabling it; a human decides."),
}


@dataclass(frozen=True)
class TaskTemplate:
    title: str
    description: str


TASKS: dict[str, TaskTemplate] = {
    "G1": TaskTemplate("Establish whether code ran after the logon",
                       "Collect endpoint (process and file) telemetry from {host} for the "
                       "period after the successful logon and review it."),
    "G2": TaskTemplate("Determine the outcome of the indicator contact",
                       "Check proxy, firewall and endpoint records for whether the contact "
                       "from {host} succeeded."),
    "G3": TaskTemplate("Corroborate or dismiss the vendor alert",
                       "Review the vendor alert on {host} against the host's telemetry; no "
                       "detection supports it."),
    "G4": TaskTemplate("Obtain endpoint telemetry",
                       "{host} is in scope but has no process or file telemetry; collect it "
                       "before assessing the host."),
    "G5": TaskTemplate("Check whether the partial chain completed",
                       "A detection chain on {host} matched only partially; look for the "
                       "missing stages."),
    "G6": TaskTemplate("Review an agent statement",
                       "An agent statement is not backed by evidence citations; confirm or "
                       "discard it before relying on it."),
}

NOTES: dict[str, str] = {
    "no_response": "No detection supports a response action; no steps are proposed.",
    "domain_indicator": "Indicator {indicator} is a domain ({outcome}); the catalogue has "
                        "no domain-blocking action, so no step is proposed.",
    "already_blocked": "Contact with {indicator} was blocked; no blocking step is needed.",
    "persistence": "Autostart entries found on {hosts} have no removal action in the "
                   "catalogue; their removal belongs to eradication (a human decision).",
    "target_refused": "A {kind} target from {rules} was not proposed: {reason}.",
}
