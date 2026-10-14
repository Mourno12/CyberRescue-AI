"""Simulated action handlers and success-criterion evaluators.

``HANDLERS`` maps each SUPPORTED action to a pure function
``(environment, step) -> (environment', SimEffect)`` that changes only the
in-memory ``SimEnvironment``. Exactly the seven tier-1/2 catalogue actions a
Phase 4 plan can propose are supported. Tier-3 actions have no handler: they
are never simulated, and any action without a handler is UNSUPPORTED - never
reported as a success.

A handler applies its effect only to something the simulated world contains
(a process the evidence saw start, a file the evidence saw, an account the
evidence saw). Anything else is ``applied=False`` - the simulator does not
invent targets.

``evaluate_criteria`` checks the plan's own ``SuccessCriterion`` list against
the environment AFTER the step: each Phase 4 check has exactly one evaluator,
and a criterion with no evaluator is unsatisfied.

All descriptions are fixed templates over safe tokens (``fill``).
"""

from __future__ import annotations

from collections.abc import Callable

from cyberrescue.execution.environment import SimEnvironment
from cyberrescue.execution.model import CriterionResult, SimEffect
from cyberrescue.response.model import PlanStep
from cyberrescue.response.playbooks import fill

Handler = Callable[[SimEnvironment, PlanStep], tuple[SimEnvironment, SimEffect]]


def _param(step: PlanStep, name: str) -> str:
    p = step.params.get(name)
    return p.untrusted if p is not None else ""


def _host_known(env: SimEnvironment, host: str | None) -> bool:
    return bool(host) and host in env.hosts


def isolate_host(env, step):
    host = step.target.value
    if not _host_known(env, host):
        return env, SimEffect(applied=False, description=fill(
            "{host} is not in the simulated inventory; nothing was isolated.", host=host))
    return env.with_(isolated=env.isolated | {host}), SimEffect(
        applied=True, description=fill("Simulated: {host} isolated from the network.",
                                       host=host))


def preserve_disk_image(env, step):
    host = step.target.value
    if not _host_known(env, host):
        return env, SimEffect(applied=False, description=fill(
            "{host} is not in the simulated inventory; no image was recorded.", host=host))
    return env.with_(imaged=env.imaged | {host}), SimEffect(
        applied=True, description=fill("Simulated: disk and memory image of {host} recorded.",
                                       host=host))


def kill_process(env, step):
    host, name = step.target.value, _param(step, "process")
    key = (host, name.lower())
    if not env.process_running(host, name):
        return env, SimEffect(applied=False, description=fill(
            "Process {process} is not running on {host} in the simulation (not seen in the "
            "evidence, or already terminated); nothing was terminated.",
            process=name, host=host))
    return env.with_(killed=env.killed | {key}), SimEffect(
        applied=True, description=fill("Simulated: process {process} on {host} terminated.",
                                       process=name, host=host),
        evidence_ids=env.processes[key])


def quarantine_file(env, step):
    host, path = step.target.value, _param(step, "path")
    key = (host, path.lower())
    if not env.file_present(host, path):
        return env, SimEffect(applied=False, description=fill(
            "The file is not present on {host} in the simulation (not seen in the evidence, "
            "or already quarantined); nothing was quarantined.", host=host))
    return env.with_(quarantined=env.quarantined | {key}), SimEffect(
        applied=True, description=fill("Simulated: the file on {host} moved to quarantine.",
                                       host=host),
        evidence_ids=env.files[key])


def block_ip(env, step):
    ip = step.target.value
    if not ip:
        return env, SimEffect(applied=False, description="No address to block.")
    return env.with_(blocked=env.blocked | {ip}), SimEffect(
        applied=True, description=fill("Simulated: egress to {ip} blocked.", ip=ip),
        evidence_ids=env.indicators.get(ip, ()))


def disable_account(env, step):
    account = (step.target.value or "").lower()
    if account not in env.accounts:
        return env, SimEffect(applied=False, description=fill(
            "Account {account} is not seen in the evidence; nothing was disabled.",
            account=account))
    return env.with_(disabled=env.disabled | {account}), SimEffect(
        applied=True, description=fill("Simulated: account {account} disabled.",
                                       account=account),
        evidence_ids=env.accounts[account])


def notify_stakeholders(env, step):
    recipients = tuple(step.recipients)
    if not recipients:
        return env, SimEffect(applied=False, description="No recipients to notify.")
    return env.with_(notifications=(*env.notifications, recipients)), SimEffect(
        applied=True, description=fill("Simulated: notification to {recipients} recorded.",
                                       recipients=list(recipients)))


HANDLERS: dict[str, Handler] = {
    "notify_stakeholders": notify_stakeholders,
    "preserve_disk_image": preserve_disk_image,
    "isolate_host": isolate_host,
    "block_ip": block_ip,
    "disable_account": disable_account,
    "kill_process": kill_process,
    "quarantine_file": quarantine_file,
}


# --- success criteria ----------------------------------------------------------------

def _crit(env: SimEnvironment, step: PlanStep, check: str) -> tuple[bool, str, tuple[str, ...]]:
    host, value = step.target.value, step.target.value
    if check == "no_network_activity_from_host":
        ok = host in env.isolated
        return ok, fill("{host} is {state} in the simulation.", host=host,
                        state="isolated" if ok else "not_isolated"), ()
    if check == "image_recorded":
        ok = host in env.imaged
        return ok, fill("Image of {host}: {state}.", host=host,
                        state="recorded" if ok else "absent"), ()
    if check == "no_process_activity":
        key = (host, _param(step, "process").lower())
        ok = key in env.killed                      # it existed, and it was terminated
        return ok, fill("Process on {host}: {state}.", host=host,
                        state="terminated" if ok else "not_terminated"), \
            env.processes.get(key, ())
    if check == "file_absent":
        key = (host, _param(step, "path").lower())
        ok = key in env.quarantined                 # it existed, and it was quarantined
        return ok, fill("File on {host}: {state}.", host=host,
                        state="quarantined" if ok else "still_present_or_never_seen"), \
            env.files.get(key, ())
    if check == "no_connection_to_indicator":
        ok = value in env.blocked
        return ok, fill("Egress to {ip}: {state}.", ip=value,
                        state="blocked" if ok else "open"), env.indicators.get(value or "", ())
    if check == "no_successful_logon_by_account":
        acct = (value or "").lower()
        ok = acct in env.disabled
        return ok, fill("Account {account}: {state}.", account=acct,
                        state="disabled" if ok else "enabled"), env.accounts.get(acct, ())
    if check == "notification_recorded":
        ok = tuple(step.recipients) in env.notifications and bool(step.recipients)
        return ok, fill("Notification to {recipients}: {state}.",
                        recipients=list(step.recipients),
                        state="recorded" if ok else "absent"), ()
    return False, "No simulator check exists for this criterion.", ()


def evaluate_criteria(env: SimEnvironment, step: PlanStep) -> tuple[CriterionResult, ...]:
    out = []
    for c in step.success_criteria:
        ok, observed, evidence = _crit(env, step, c.check)
        out.append(CriterionResult(check=c.check, expected=c.description, satisfied=ok,
                                   observed=observed, evidence_ids=tuple(evidence)))
    return tuple(out)
