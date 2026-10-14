"""Build and verify a response plan - read-only, deterministic, proposal-only.

``build_plan`` reads one incident through a ``ReadOnlyCore``:

1. the Phase 3 investigation case (``build_case``, unchanged) for scope, gaps,
   ``as_of`` and the persisted-finding mapping;
2. the Phase 2C detection dry run on the same evidence (entities such as the
   executable, account and indicator are not part of the case);
3. a policy snapshot as of ``as_of`` for previews.

It applies ``playbook-v1`` and returns a frozen ``ResponsePlan``. Nothing is
written: no action request, no approval, no audit event. The plan's
``plan_sha256`` covers its content; ``verify_plan`` re-hashes a document and
rebuilds it from the database.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from cyberrescue.core.audit import canonical_json
from cyberrescue.core.catalog import get_action
from cyberrescue.detection.engine import DetectionEngine, load_view
from cyberrescue.detection.model import Detection, digest
from cyberrescue.investigation.builder import build_case
from cyberrescue.investigation.model import Case
from cyberrescue.investigation.readonly import ReadOnlyCore
from cyberrescue.investigation.scope import COMPROMISE_TYPES
from cyberrescue.response.attack import ATTACK_MAP_VERSION, attack_for, merge
from cyberrescue.response.model import (
    DecisionPoint,
    PlanNote,
    PlanStep,
    ResponsePlan,
    SuccessCriterion,
    Target,
    Task,
    untrusted,
)
from cyberrescue.response.playbooks import (
    BASE_STAKEHOLDERS,
    C2_RULE,
    CRITICAL,
    CRITICALITY_CAUTION,
    DATA_STAKEHOLDERS,
    DECISIONS,
    IMPACT_RULE,
    LATERAL_AUTH_RULES,
    MALWARE_RULES,
    NOTES,
    PERSISTENCE_RULE,
    PHASE_ORDER,
    PLAYBOOK_VERSION,
    PROCESS_RULES,
    STEPS,
    TASKS,
    Text,
    fill,
)
from cyberrescue.response.preview import Previewer, readonly_snapshot
from cyberrescue.response.targets import (
    ProtectedAccounts,
    check_account,
    check_host,
    check_ip,
    load_protected_accounts,
)
from shared.mock_data import load_reg_rules


_KIND_ORDER = ("host", "ip", "account", "none")


def _sha(plan: ResponsePlan) -> str:
    return hashlib.sha256(canonical_json(plan.content()).encode()).hexdigest()


def notification_rules(rules: Iterable[dict], classes: Iterable[str]) -> tuple[str, ...]:
    """Regulations with a notification deadline triggered by these data classes."""
    have = set(classes)
    return tuple(sorted(r["rule_id"] for r in rules
                        if have & set(r.get("trigger", {}).get("data_classes", []))
                        and (r.get("deadline") or {}).get("value", 0) > 0))


@dataclass
class _Draft:
    key: str
    template: str
    target: Target
    detections: list[Detection]
    values: dict[str, object] = field(default_factory=dict)
    params: dict[str, object] = field(default_factory=dict)
    recipients: tuple[str, ...] = ()
    after_keys: tuple[str, ...] = ()
    cautions: tuple[str, ...] = ()


class _Planner:
    def __init__(self, case: Case, detections: tuple[Detection, ...], view, previewer: Previewer,
                 protected: ProtectedAccounts, reg_rules: list[dict]) -> None:
        self.case = case
        self.detections = detections
        self.view = view
        self.pv = previewer
        self.protected = protected
        self.reg_rules = reg_rules
        self.persisted = {d.detection_id: d.persisted_finding_id for d in case.detections
                          if d.persisted_finding_id}
        self.drafts: dict[str, _Draft] = {}
        self.decisions: list[tuple[str, Target, list[Detection], dict, tuple[str, ...],
                                   tuple[str, ...]]] = []
        self.notes: list[PlanNote] = []

    # --- helpers ---------------------------------------------------------------------
    def _evidence(self, dets: Iterable[Detection]) -> tuple[str, ...]:
        return self.view.ordered(i for d in dets for i in d.supporting_evidence_ids)

    @staticmethod
    def _rules(dets: Iterable[Detection]) -> tuple[str, ...]:
        return tuple(sorted({d.rule_id for d in dets}))

    def _note(self, code: str, refs: Iterable[str] = (), **values: object) -> None:
        self.notes.append(PlanNote(code=code, description=fill(NOTES[code], **values),
                                   refs=tuple(sorted(set(refs)))))

    def _refused(self, kind: str, dets: list[Detection], reason: str) -> None:
        self._note("target_refused", [d.detection_id for d in dets], kind=kind,
                   rules=list(self._rules(dets)), reason=Text(reason))

    def _add(self, draft: _Draft) -> str:
        if draft.key in self.drafts:                  # same proposal from another trigger
            prev = self.drafts[draft.key]
            prev.detections += [d for d in draft.detections if d not in prev.detections]
        else:
            self.drafts[draft.key] = draft
        return draft.key

    def _criticality(self, host: str) -> tuple[str, ...]:
        asset = self.pv.snapshot.assets.get(host)
        if asset and asset.criticality in CRITICAL:
            return (fill(CRITICALITY_CAUTION, host=host, criticality=asset.criticality),)
        return ()

    # --- playbook ----------------------------------------------------------------------
    def compromised(self) -> None:
        for host in self.case.scope.compromised_hosts:
            dets = [d for d in self.detections
                    if d.primary_host == host and d.finding_type in COMPROMISE_TYPES]
            chk = check_host(host, self.view.assets)
            if not chk.ok:
                self._refused("host", dets, chk.reason)
                continue
            t = chk.target
            iso = self._add(_Draft(f"isolate:{host}", "isolate_compromised", t, dets,
                                   {"host": host},
                                   cautions=self._criticality(host)))
            pre = self._add(_Draft(f"preserve:{host}", "preserve_compromised", t, list(dets),
                                   {"host": host}, after_keys=(iso,)))
            procs: dict[str, list[Detection]] = defaultdict(list)
            paths: dict[str, list[Detection]] = defaultdict(list)
            shown: dict[str, tuple[str, str | None]] = {}
            for d in dets:
                ent = d.entities
                if d.rule_id in PROCESS_RULES and ent.get("process"):
                    k = str(ent["process"]).lower()
                    procs[k].append(d)
                    shown.setdefault(f"p:{k}", (str(ent["process"]), ent.get("executable")))
                path = ent.get("executable") if d.rule_id in MALWARE_RULES else \
                    ent.get("target") if d.rule_id == PERSISTENCE_RULE else None
                if path:
                    paths[str(path).lower()].append(d)
                    shown.setdefault(f"f:{str(path).lower()}", (str(path), None))
            for k, pd in sorted(procs.items()):
                name, exe = shown[f"p:{k}"]
                params = {"process": name, **({"executable": exe} if exe else {})}
                self._add(_Draft(f"kill:{host}:{k}", "kill_process", t, pd,
                                 {"host": host, "process": name}, params=params,
                                 after_keys=(pre,)))
            for k, fd in sorted(paths.items()):
                self._add(_Draft(f"quarantine:{host}:{k}", "quarantine_file", t, fd,
                                 {"host": host}, params={"path": shown[f"f:{k}"][0]},
                                 after_keys=(pre,)))
            autostarts = [d for d in dets if d.rule_id == PERSISTENCE_RULE]
            if autostarts:
                self._note("persistence", [d.detection_id for d in autostarts], hosts=[host])
            self.decisions.append(("wipe_host", t, dets, {"host": host}, (iso, pre), ()))
            if any(d.rule_id == IMPACT_RULE for d in dets):
                self.decisions.append(("restore_from_backup", t, dets, {"host": host},
                                       (iso, pre), ()))

    def accessed(self) -> None:
        for host in self.case.scope.accessed_hosts:
            dets = [d for d in self.detections
                    if (d.rule_id == "LAT-001" and host in d.entities.get("succeeded_hosts", []))
                    or (d.rule_id == "AUTH-001" and d.entities.get("target_host") == host)]
            chk = check_host(host, self.view.assets)
            if not chk.ok:
                self._refused("host", dets, chk.reason)
                continue
            accounts = sorted({str(d.entities.get("user", "")).lower() for d in dets} - {""})
            self._add(_Draft(f"preserve:{host}", "preserve_accessed", chk.target, dets,
                             {"host": host, "account": accounts}))

    def accounts(self) -> None:
        groups: dict[str, list[Detection]] = defaultdict(list)
        for d in self.detections:
            succeeded = d.rule_id == "AUTH-001" or (
                d.rule_id == "LAT-001" and d.entities.get("succeeded_hosts"))
            if d.rule_id in LATERAL_AUTH_RULES and succeeded and d.entities.get("user"):
                groups[str(d.entities["user"]).lower()].append(d)
        for name, dets in sorted(groups.items()):
            hosts = sorted({h for d in dets for h in (
                d.entities.get("succeeded_hosts", []) if d.rule_id == "LAT-001"
                else [d.entities.get("target_host")]) if h})
            chk = check_account(name, self.protected)
            values = {"account": name, "hosts": hosts}
            if chk.ok:
                self._add(_Draft(f"disable:{name}", "disable_account", chk.target, dets,
                                 values))
            elif chk.protected:
                self.decisions.append(("protected_account", chk.target, dets, values, (), ()))
            else:
                self._refused("account", dets, chk.reason)

    def infrastructure(self) -> None:
        groups: dict[tuple[str, str], list[Detection]] = defaultdict(list)
        for d in self.detections:
            if d.rule_id == C2_RULE:
                groups[(d.entities["indicator"], d.entities["indicator_type"])].append(d)
        for (indicator, kind), dets in sorted(groups.items()):
            outcomes = {d.entities.get("outcome") for d in dets}
            refs = [d.detection_id for d in dets]
            if "established" not in outcomes:
                if "blocked" in outcomes:
                    self._note("already_blocked", refs, indicator=indicator)
                continue                              # attempted: a G2 task covers it
            if kind != "ip":
                self._note("domain_indicator", refs, indicator=indicator, outcome="established")
                continue
            chk = check_ip(indicator, self.view)
            if not chk.ok:
                self._refused("ip", dets, chk.reason)
                continue
            family = str(dets[0].entities.get("malware_family", "")).replace(" ", "_")
            self._add(_Draft(f"block:{chk.target.value}", "block_ip", chk.target, dets,
                             {"ip": chk.target.value, "family": family,
                              "hosts": sorted({d.primary_host for d in dets if d.primary_host})}))

    def notifications(self) -> None:
        regs = notification_rules(self.reg_rules, self.case.scope.data_classes_at_risk)
        if not self.drafts:
            return
        every = [d for dr in self.drafts.values() for d in dr.detections]
        uniq = list({d.detection_id: d for d in every}.values())
        hosts = sorted({dr.target.value for dr in self.drafts.values()
                        if dr.target.kind == "host"})
        recipients = DATA_STAKEHOLDERS if (regs or self.case.scope.hosts_under_hold) \
            else BASE_STAKEHOLDERS
        target = Target(kind="none", source="plan")
        note = self._add(_Draft("notify:internal", "notify_internal", target, uniq,
                                {"recipients": list(recipients), "hosts": hosts},
                                recipients=recipients))
        if regs:
            classes = set(self.case.scope.data_classes_at_risk)
            regulated = {c for r in self.reg_rules if r["rule_id"] in regs
                         for c in r["trigger"]["data_classes"]} & classes
            hosts_r = {h for h in (*self.case.scope.compromised_hosts,
                                   *self.case.scope.accessed_hosts)
                       if set(self.view.assets.data_classes(h)) & regulated}
            dets = [d for d in uniq if d.primary_host in hosts_r] or uniq
            self.decisions.append(("notify_regulator", target, dets,
                                   {"regulations": list(regs),
                                    "classes": sorted(regulated)}, (note,), regs))

    # --- assembly ----------------------------------------------------------------------
    def _step_id(self, draft: _Draft) -> str:
        return "STEP-" + digest(draft.key, *sorted(d.detection_id for d in draft.detections))[:12]

    def build_steps(self) -> tuple[tuple[PlanStep, ...], dict[str, str]]:
        ids = {k: self._step_id(d) for k, d in self.drafts.items()}
        drafts = sorted(self.drafts.values(), key=lambda d: (
            PHASE_ORDER.index(STEPS[d.template].phase), _KIND_ORDER.index(d.target.kind),
            d.target.value or "", STEPS[d.template].action, d.key))
        steps = []
        for n, d in enumerate(drafts, 1):
            tpl = STEPS[d.template]
            spec = get_action(tpl.action)
            rules = self._rules(d.detections)
            values = {**d.values, "rules": list(rules)}
            steps.append(PlanStep(
                step_id=ids[d.key], order=n, phase=tpl.phase, action=tpl.action,
                tier=int(spec.tier), reversible=spec.reversible, target=d.target,
                params={k: untrusted(v) for k, v in sorted(d.params.items())},
                recipients=d.recipients, after=tuple(ids[k] for k in d.after_keys),
                rationale=fill(tpl.rationale, **values), trigger_rules=rules,
                detection_ids=tuple(sorted(x.detection_id for x in d.detections)),
                finding_ids=tuple(sorted({self.persisted[x.detection_id] for x in d.detections
                                          if x.detection_id in self.persisted})),
                evidence_ids=self._evidence(d.detections),
                attack=merge(attack_for(x.rule_id, x.entities) for x in d.detections),
                success_criteria=tuple(SuccessCriterion(
                    check=c, description=fill(text, **values), subject=d.target.value)
                    for c, text in tpl.success),
                cautions=(*d.cautions, *tpl.cautions),
                preview=self.pv.preview(tpl.action, d.target.value, kind=d.target.kind)))
        return tuple(steps), ids

    def build_decisions(self, ids: dict[str, str]) -> tuple[DecisionPoint, ...]:
        out = []
        for key, target, dets, values, prereq, regs in self.decisions:
            tpl = DECISIONS[key]
            spec = get_action(tpl.action)
            rules = self._rules(dets)
            vals = {**values, "rules": list(rules)}
            out.append(DecisionPoint(
                decision_id="DEC-" + digest(key, target.value or "",
                                            *sorted(d.detection_id for d in dets))[:12],
                action=tpl.action, tier=int(spec.tier), reason_code=tpl.reason_code,
                target=target, question=fill(tpl.question, **vals),
                rationale=fill(tpl.rationale, **vals), regulations=regs,
                prerequisites=tuple(ids[k] for k in prereq if k in ids),
                trigger_rules=rules,
                detection_ids=tuple(sorted(d.detection_id for d in dets)),
                finding_ids=tuple(sorted({self.persisted[d.detection_id] for d in dets
                                          if d.detection_id in self.persisted})),
                evidence_ids=self._evidence(dets),
                attack=merge(attack_for(d.rule_id, d.entities) for d in dets),
                preview=self.pv.preview(tpl.action, target.value, kind=target.kind)))
        return tuple(sorted(out, key=lambda d: (d.tier, d.action, d.target.value or "",
                                                d.decision_id)))

    def build_tasks(self) -> tuple[Task, ...]:
        return tuple(Task(
            task_id="TASK-" + g.gap_id.removeprefix("GAP-"), gap_code=g.code, host=g.host,
            title=TASKS[g.code].title, description=fill(TASKS[g.code].description, host=g.host),
            evidence_ids=g.evidence_ids, refs=(g.gap_id, *g.refs)) for g in self.case.gaps)


def build_plan(core: ReadOnlyCore, incident_ref: str, *,
               protected: ProtectedAccounts | None = None) -> ResponsePlan:
    iid = core.resolve(incident_ref)
    case = build_case(core, iid)
    view = load_view(core, iid)
    report = DetectionEngine().run(view)
    if report.ruleset_version != case.ruleset_version:     # same process, same rules
        raise RuntimeError("detection ruleset changed while planning")
    protected = protected or load_protected_accounts()
    reg_rules = load_reg_rules()
    previewer = Previewer(readonly_snapshot(core, iid, case.as_of), as_of=case.as_of)

    p = _Planner(case, report.detections, view, previewer, protected, reg_rules)
    p.compromised()
    p.accessed()
    p.accounts()
    p.infrastructure()
    p.notifications()
    steps, ids = p.build_steps()
    decisions = p.build_decisions(ids)
    if not steps:
        p._note("no_response")
    notes = tuple(sorted(p.notes, key=lambda n: (n.code, n.description)))

    plan = ResponsePlan(
        plan_id="PLAN-" + digest(case.case_sha256, PLAYBOOK_VERSION, ATTACK_MAP_VERSION,
                                 previewer.policy_version, protected.sha256)[:16],
        incident_id=iid, aliases=case.aliases, as_of=case.as_of, case_id=case.case_id,
        case_sha256=case.case_sha256, ruleset_version=case.ruleset_version,
        playbook_version=PLAYBOOK_VERSION, attack_map_version=ATTACK_MAP_VERSION,
        policy_version=previewer.policy_version,
        inputs={"evidence_fingerprint": view.fingerprint,
                "threat_intel_sha256": report.inputs["threat_intel_sha256"],
                "protected_accounts_sha256": protected.sha256,
                "reg_rules_sha256": hashlib.sha256(
                    canonical_json(reg_rules).encode()).hexdigest()},
        steps=steps, decision_points=decisions, tasks=p.build_tasks(), notes=notes)
    return plan.model_copy(update={"plan_sha256": _sha(plan)})


@dataclass
class PlanVerifyResult:
    ok: bool
    errors: list[str] = field(default_factory=list)


def verify_plan(core: ReadOnlyCore, plan_json: str, *,
                protected: ProtectedAccounts | None = None) -> PlanVerifyResult:
    errors: list[str] = []
    try:
        plan = ResponsePlan.model_validate(json.loads(plan_json))
    except ValueError as e:
        return PlanVerifyResult(False, [f"not a valid plan document: {str(e)[:200]}"])
    if _sha(plan) != plan.plan_sha256:
        errors.append("plan_sha256 does not match the document content (edited export)")
    protected = protected or load_protected_accounts()
    if plan.inputs.get("protected_accounts_sha256") != protected.sha256:
        errors.append("the protected-accounts list differs from the one the plan used")
    fresh = build_plan(core, plan.incident_id, protected=protected)
    if fresh.plan_sha256 != plan.plan_sha256:
        errors.append("the database no longer produces this plan (evidence, findings, "
                      "policy state, rules or playbook changed since export)")
    return PlanVerifyResult(not errors, errors)
