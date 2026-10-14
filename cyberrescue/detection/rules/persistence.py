"""Persistence: autostart entries (services, Run keys) pointing at user-writable
locations."""

from __future__ import annotations

from cyberrescue.detection.context import EvidenceView
from cyberrescue.detection.matchers import basename, is_run_key, is_user_writable, safe_token
from cyberrescue.detection.model import ConditionResult, ConditionSpec, RuleSpec, Window
from cyberrescue.detection.registry import Rule
from cyberrescue.detection.rules.common import process_starts_of

WINDOW = Window(name="persistence", seconds=3600)


class AutostartToUserWritable(Rule):
    spec = RuleSpec(
        rule_id="PERSIST-001", version=1, name="Autostart entry to a user-writable location",
        description="A new service (7045) or a Run/RunOnce registry value points at an "
                    "executable in a user-writable location, and that executable ran.",
        finding_type="persistence", severity="high", window=WINDOW, min_corroboration=1,
        conditions=(
            ConditionSpec(id="autostart_to_user_writable", role="required",
                          description="service ImagePath or Run-key data in a user-writable "
                                      "location"),
            ConditionSpec(id="target_executed", role="corroborating",
                          description="the target executable started on the same host within "
                                      "an hour"),
            ConditionSpec(id="target_known_malicious", role="corroborating",
                          description="the executed target's hash is an active IOC")))

    def _candidates(self, view: EvidenceView):
        for e in view.of_type("7045"):
            target = e.s("service.executable")
            if is_user_writable(target):
                yield e, target, "service", e.s("service.name")
        for e in view.of_type("registry_set"):
            if not is_run_key(e.s("registry.path")):
                continue
            for target in e.strings("registry.data.strings"):
                if is_user_writable(target):
                    yield e, target, "run_key", basename(e.s("registry.path") or "")
                    break

    def evaluate(self, view: EvidenceView) -> list:
        out = []
        for e, target, mechanism, name in self._candidates(view):
            runs = process_starts_of(view, e.host, target, e.at, WINDOW.seconds)
            bad = [p for p in runs
                   if view.intel.active(view.intel.lookup_sha256(p.s("process.hash.sha256")))]
            out.append(self.result(
                view, key=[e.host, mechanism, target.lower(), e.id],
                matched={
                    "autostart_to_user_writable": ConditionResult(
                        id="autostart_to_user_writable", matched=True, evidence_ids=(e.id,),
                        detail={"mechanism": mechanism, "name": name, "target": target}),
                    "target_executed": ConditionResult(
                        id="target_executed", matched=bool(runs),
                        evidence_ids=tuple(p.id for p in runs)),
                    "target_known_malicious": ConditionResult(
                        id="target_known_malicious", matched=bool(bad),
                        evidence_ids=tuple(p.id for p in bad))},
                supporting=[e.id, *(p.id for p in runs)], primary_host=e.host,
                entities={"host": e.host, "mechanism": mechanism, "name": name,
                          "target": target, "user": e.user},
                summary=f"Autostart {mechanism} {safe_token(name)} on {safe_token(e.host)} "
                        f"points to {safe_token(basename(target))} in a user-writable "
                        "location."))
        return out
