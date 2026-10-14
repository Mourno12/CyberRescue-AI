"""Process-execution rules: user-writable images, suspicious interpreters,
recovery inhibition. Only structured EDR fields are read (``process.*``)."""

from __future__ import annotations

from cyberrescue.detection.context import Ev, EvidenceView
from cyberrescue.detection.matchers import (
    INTERPRETERS,
    OFFICE_AND_BROWSERS,
    basename,
    is_user_writable,
    recovery_inhibition,
    safe_token,
    suspicious_arguments,
)
from cyberrescue.detection.model import ConditionResult, ConditionSpec, RuleSpec, Window
from cyberrescue.detection.registry import Rule
from cyberrescue.detection.rules.common import (
    CORROBORATION_SECONDS,
    parent_starts,
    vendor_alerts,
)

CORROBORATION = Window(name="corroboration", seconds=CORROBORATION_SECONDS)


def _name(p: Ev) -> str:
    return basename(p.s("process.executable") or p.s("process.name") or "")


class UserWritableExecution(Rule):
    spec = RuleSpec(
        rule_id="PROC-001", version=1, name="Execution from a user-writable location",
        description="A process image runs from ProgramData, a user profile's Downloads/"
                    "AppData/Desktop/Documents, Users\\Public or a Temp folder, corroborated "
                    "by threat intel, the file being dropped on the host, or a vendor alert.",
        finding_type="execution", severity="high", window=CORROBORATION, min_corroboration=1,
        conditions=(
            ConditionSpec(id="user_writable_image", role="required",
                          description="process.executable is in a user-writable location"),
            ConditionSpec(id="known_malicious_hash", role="corroborating",
                          description="process.hash.sha256 is an active IOC"),
            ConditionSpec(id="dropped_on_host", role="corroborating",
                          description="the same file was created on the host before it ran"),
            ConditionSpec(id="vendor_alert", role="corroborating",
                          description="an EDR alert on the host names the same process or "
                                      "hash within 30 minutes")))

    def evaluate(self, view: EvidenceView) -> list:
        out = []
        for p in view.of_type("process_start"):
            exe = p.s("process.executable")
            if not is_user_writable(exe):
                continue
            sha = p.s("process.hash.sha256")
            ioc = view.intel.active(view.intel.lookup_sha256(sha))
            dropped = [f for f in view.of_kind("file")
                       if f.host == p.host and f.at <= p.at
                       and (f.s("file.path") or "").lower() == exe.lower()]
            alerts = vendor_alerts(view, p.host, p.at, process_name=_name(p), sha256=sha)
            out.append(self.result(
                view, key=[p.host, exe.lower(), p.id],
                matched={
                    "user_writable_image": ConditionResult(
                        id="user_writable_image", matched=True, evidence_ids=(p.id,),
                        detail={"executable": exe}),
                    "known_malicious_hash": ConditionResult(
                        id="known_malicious_hash", matched=bool(ioc), evidence_ids=(p.id,),
                        detail={"malware_family": ioc.malware_family,
                                "ioc_confidence": ioc.confidence} if ioc else {}),
                    "dropped_on_host": ConditionResult(
                        id="dropped_on_host", matched=bool(dropped),
                        evidence_ids=tuple(f.id for f in dropped)),
                    "vendor_alert": ConditionResult(
                        id="vendor_alert", matched=bool(alerts),
                        evidence_ids=tuple(a.id for a in alerts))},
                supporting=[p.id, *(f.id for f in dropped)], context=[a.id for a in alerts],
                primary_host=p.host,
                entities={"host": p.host, "user": p.user, "executable": exe,
                          "process": _name(p), "sha256": sha,
                          "parent": p.s("process.parent.name"),
                          "malware_family": ioc.malware_family if ioc else None},
                summary=f"{safe_token(_name(p))} ran from a user-writable location on "
                        f"{safe_token(p.host)} as {safe_token(p.user)}."))
        return out


class SuspiciousInterpreter(Rule):
    spec = RuleSpec(
        rule_id="PROC-002", version=1, name="Script interpreter with suspicious arguments "
                                            "or parent",
        description="A script interpreter starts with obfuscation/download arguments or from "
                    "an Office application, a browser, or a process running from a "
                    "user-writable location.",
        finding_type="execution", severity="medium", window=CORROBORATION,
        min_corroboration=1,
        conditions=(
            ConditionSpec(id="script_interpreter", role="required",
                          description="the image is a script interpreter"),
            ConditionSpec(id="suspicious_arguments", role="corroborating",
                          description="encoded command, download cradle, remote URL, hidden "
                                      "window or policy bypass in the command line"),
            ConditionSpec(id="unexpected_parent", role="corroborating",
                          description="parent is an Office app or browser, or itself ran "
                                      "from a user-writable location")))

    def evaluate(self, view: EvidenceView) -> list:
        out = []
        for p in view.of_type("process_start"):
            name = _name(p).lower()
            if name not in INTERPRETERS:
                continue
            args = suspicious_arguments(p.s("process.command_line"))
            parent = basename(p.s("process.parent.name") or "").lower()
            writable_parents = [q for q in parent_starts(view, p)
                                if is_user_writable(q.s("process.executable"))]
            odd_parent = parent in OFFICE_AND_BROWSERS or bool(writable_parents)
            if not args and not odd_parent:
                continue                       # an ordinary interpreter run: not even noise
            out.append(self.result(
                view, key=[p.host, p.id],
                matched={
                    "script_interpreter": ConditionResult(
                        id="script_interpreter", matched=True, evidence_ids=(p.id,),
                        detail={"interpreter": name}),
                    "suspicious_arguments": ConditionResult(
                        id="suspicious_arguments", matched=bool(args), evidence_ids=(p.id,),
                        detail={"patterns": args}),
                    "unexpected_parent": ConditionResult(
                        id="unexpected_parent", matched=odd_parent,
                        evidence_ids=tuple(q.id for q in writable_parents),
                        detail={"parent": parent})},
                supporting=[p.id, *(q.id for q in writable_parents)], primary_host=p.host,
                entities={"host": p.host, "user": p.user, "interpreter": name,
                          "parent": parent, "patterns": args},
                summary=f"{safe_token(name)} on {safe_token(p.host)} started with "
                        f"suspicious arguments or parent ({', '.join(args) or 'parent'})."))
        return out


class RecoveryInhibition(Rule):
    spec = RuleSpec(
        rule_id="RECOV-001", version=1, name="Backup or shadow-copy destruction",
        description="A command deletes shadow copies or backup catalogues, or disables "
                    "recovery.",
        finding_type="recovery_inhibition", severity="high", window=CORROBORATION,
        base_confidence="medium",
        conditions=(
            ConditionSpec(id="recovery_inhibition_command", role="required",
                          description="vssadmin/wmic/bcdedit/wbadmin recovery-destroying "
                                      "command line"),
            ConditionSpec(id="parent_user_writable", role="corroborating",
                          description="the parent process ran from a user-writable "
                                      "location")))

    def evaluate(self, view: EvidenceView) -> list:
        out = []
        for p in view.of_type("process_start"):
            technique = recovery_inhibition(p.s("process.command_line"))
            if not technique:
                continue
            parents = [q for q in parent_starts(view, p)
                       if is_user_writable(q.s("process.executable"))]
            out.append(self.result(
                view, key=[p.host, p.id],
                matched={
                    "recovery_inhibition_command": ConditionResult(
                        id="recovery_inhibition_command", matched=True, evidence_ids=(p.id,),
                        detail={"technique": technique}),
                    "parent_user_writable": ConditionResult(
                        id="parent_user_writable", matched=bool(parents),
                        evidence_ids=tuple(q.id for q in parents),
                        detail={"parent": p.s("process.parent.name")})},
                supporting=[p.id, *(q.id for q in parents)], primary_host=p.host,
                entities={"host": p.host, "user": p.user, "technique": technique,
                          "parent": p.s("process.parent.name")},
                summary=f"Recovery inhibition ({technique}) on {safe_token(p.host)} by "
                        f"{safe_token(p.user)}."))
        return out
