"""CyberRescue Phase 2C — process (PROC-001/002), recovery (RECOV-001), persistence
(PERSIST-001)."""

from cyberrescue.detection.model import Detection, Observation
from cyberrescue.detection.rules.persistence import AutostartToUserWritable
from cyberrescue.detection.rules.process import (
    RecoveryInhibition,
    SuspiciousInterpreter,
    UserWritableExecution,
)
from tests._detection_factory import Evidence, at

BHZ = "C:\\ProgramData\\upd\\bhz.exe"
BHZ_SHA = "9f2c4e7a1b8d3056c4a9e1f7b2d6803a5e9c1742f8b3a6d40e2c7f9a1b3d5e6c"
RUN = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\PidginUpdate"


def results(rule, ev):
    return rule.evaluate(ev.view())


def dets(rule, ev):
    return [r for r in results(rule, ev) if isinstance(r, Detection)]


def cond(det, cid):
    return next(c for c in det.conditions if c.id == cid)


# --- PROC-001 ------------------------------------------------------------------

def test_user_writable_execution_with_ioc_and_alert():
    ev = Evidence()
    p = ev.proc(at("14:01:12"), "srv-db-01", BHZ, parent="services.exe", sha=BHZ_SHA)
    alert = ev.alert(at("14:07:22"), "srv-db-01", "Ransomware.BlackHaze", process="bhz.exe")
    [d] = dets(UserWritableExecution(), ev)
    assert d.supporting_evidence_ids == (p,) and d.context_evidence_ids == (alert,)
    assert cond(d, "known_malicious_hash").detail["malware_family"] == "BlackHaze ransomware"
    assert d.confidence == "high" and d.entities["process"] == "bhz.exe"


def test_dropped_file_is_supporting_evidence():
    ev = Evidence()
    exe = "C:\\Users\\arivera\\Downloads\\inv\\InvoiceViewer.exe"
    f = ev.file(at("09:15:40"), "ws-eng-014", "file_create", exe, process="explorer.exe")
    p = ev.proc(at("09:17:02"), "ws-eng-014", exe)
    [d] = dets(UserWritableExecution(), ev)
    assert d.supporting_evidence_ids == (f, p) and d.confidence == "medium"


def test_uncorroborated_user_writable_execution_is_only_an_observation():
    ev = Evidence()
    ev.proc(at("10:00:00"), "srv-app-01", "C:\\ProgramData\\chocolatey\\choco.exe")
    [r] = results(UserWritableExecution(), ev)
    assert isinstance(r, Observation) and r.kind == "partial_match"


def test_program_files_and_system_binaries_never_fire():
    ev = Evidence()
    ev.proc(at("09:00:00"), "ws-eng-014", "C:\\Program Files\\Git\\cmd\\git.exe", sha=BHZ_SHA)
    ev.proc(at("09:00:01"), "srv-db-01", "C:\\Windows\\System32\\vssadmin.exe")
    assert results(UserWritableExecution(), ev) == []


# --- PROC-002 ------------------------------------------------------------------

def test_encoded_powershell_fires():
    ev = Evidence()
    ev.proc(at("10:00:00"), "ws-eng-014", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
            "powershell.exe", cmd="powershell -nop -w hidden -enc SQBFAFgA")
    [d] = dets(SuspiciousInterpreter(), ev)
    assert cond(d, "suspicious_arguments").detail["patterns"] == [
        "encoded_command", "hidden_window", "policy_bypass"]
    assert d.confidence == "medium"


def test_interpreter_spawned_by_office_or_dropper_fires():
    ev = Evidence()
    ev.proc(at("10:00:00"), "ws-fin-007", "C:\\Windows\\System32\\cmd.exe",
            parent="WINWORD.EXE", cmd="cmd /c whoami")
    drop = ev.proc(at("10:01:00"), "ws-fin-007", "C:\\Users\\m\\AppData\\Local\\t\\x.exe")
    child = ev.proc(at("10:01:05"), "ws-fin-007", "C:\\Windows\\System32\\cmd.exe",
                    parent="x.exe", cmd="cmd /c dir")
    office, dropper = dets(SuspiciousInterpreter(), ev)
    assert cond(office, "unexpected_parent").detail["parent"] == "winword.exe"
    assert dropper.supporting_evidence_ids == (drop, child)


def test_benign_developer_interpreters_do_not_fire():
    ev = Evidence()                      # Scenario C's developer activity
    ev.proc(at("09:00:00"), "ws-eng-014", "C:\\Python312\\python.exe", cmd="python -m pytest -q")
    ev.proc(at("09:01:00"), "ws-eng-014", "C:\\Program Files\\nodejs\\node.exe",
            cmd="node node_modules\\.bin\\jest --watch")
    assert results(SuspiciousInterpreter(), ev) == []


# --- RECOV-001 -----------------------------------------------------------------

def test_shadow_copy_deletion_with_dropper_parent():
    ev = Evidence()
    parent = ev.proc(at("14:01:12"), "srv-db-01", BHZ)
    child = ev.proc(at("14:01:35"), "srv-db-01", "C:\\Windows\\System32\\vssadmin.exe",
                    parent="bhz.exe", cmd="vssadmin.exe delete shadows /all /quiet")
    [d] = dets(RecoveryInhibition(), ev)
    assert d.supporting_evidence_ids == (parent, child) and d.confidence == "high"
    assert cond(d, "recovery_inhibition_command").detail["technique"] == \
        "vssadmin_delete_shadows"


def test_recovery_variants_and_benign_admin_commands():
    ev = Evidence()
    ev.proc(at("10:00:00"), "srv-app-01", "C:\\Windows\\System32\\wbadmin.exe",
            parent="services.exe", cmd="wbadmin delete catalog -quiet")
    ev.proc(at("10:00:01"), "srv-app-01", "C:\\Windows\\System32\\vssadmin.exe",
            cmd="vssadmin list shadows")
    [d] = dets(RecoveryInhibition(), ev)
    assert d.confidence == "medium" and d.entities["technique"] == "wbadmin_delete"


# --- PERSIST-001 ---------------------------------------------------------------

def test_service_install_pointing_at_dropper():
    ev = Evidence()
    s = ev.service(at("14:01:10"), "srv-db-01", "UpdSvc", BHZ)
    p = ev.proc(at("14:01:12"), "srv-db-01", BHZ, sha=BHZ_SHA)
    [d] = dets(AutostartToUserWritable(), ev)
    assert d.supporting_evidence_ids == (s, p) and d.confidence == "high"
    assert d.entities["mechanism"] == "service"


def test_run_key_to_downloads():
    ev = Evidence()
    exe = "C:\\Users\\arivera\\Downloads\\invoice_0613\\InvoiceViewer.exe"
    p = ev.proc(at("09:17:02"), "ws-eng-014", exe)
    r = ev.runkey(at("09:17:10"), "ws-eng-014", RUN, exe)
    [d] = dets(AutostartToUserWritable(), ev)
    assert d.supporting_evidence_ids == (p, r) and d.confidence == "medium"


def test_benign_services_and_unexecuted_targets():
    ev = Evidence()
    ev.service(at("10:00:00"), "srv-app-01", "Healthcheck", "C:\\opt\\acme\\healthcheck.exe")
    ev.runkey(at("10:00:01"), "ws-eng-014", RUN, "C:\\Program Files\\Slack\\slack.exe")
    assert results(AutostartToUserWritable(), ev) == []
    ev.service(at("10:00:02"), "srv-app-01", "Odd", "C:\\ProgramData\\x\\never_ran.exe")
    [r] = results(AutostartToUserWritable(), ev)
    assert isinstance(r, Observation) and r.kind == "partial_match"
