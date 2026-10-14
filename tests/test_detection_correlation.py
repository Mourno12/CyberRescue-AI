"""CyberRescue Phase 2C — Layer-2 correlation (CORR-001, ALERT-001) and the engine."""

from cyberrescue.detection.engine import DetectionEngine
from tests._detection_factory import Evidence, at

BHZ = "C:\\ProgramData\\upd\\bhz.exe"
BHZ_SHA = "9f2c4e7a1b8d3056c4a9e1f7b2d6803a5e9c1742f8b3a6d40e2c7f9a1b3d5e6c"
DROP = "C:\\Users\\arivera\\Downloads\\inv\\InvoiceViewer.exe"
RUN = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\X"


def run(ev):
    return DetectionEngine().run(ev.view())


def by_rule(report, rule_id):
    return [d for d in report.detections if d.rule_id == rule_id]


def three_stage_host(ev, host="ws-eng-014", user="arivera", offset=0):
    """execution (PROC-001) + persistence (PERSIST-001) + recovery inhibition."""
    p = ev.proc(at("09:17:02", offset), host, DROP, user=user)
    ev.file(at("09:15:40", offset), host, "file_create", DROP, user=user)
    ev.runkey(at("09:17:10", offset), host, RUN, DROP, user=user)
    ev.proc(at("09:17:20", offset), host, "C:\\Windows\\System32\\vssadmin.exe", user=user,
            parent="InvoiceViewer.exe", cmd="vssadmin delete shadows /all")
    return p


def test_three_stage_types_on_one_host_form_a_chain():
    ev = Evidence()
    three_stage_host(ev)
    rep = run(ev)
    [chain] = by_rule(rep, "CORR-001")
    assert chain.primary_host == "ws-eng-014" and chain.confidence == "medium"
    assert chain.entities["stages"] == ["execution", "persistence", "recovery_inhibition"]
    members = {m["detection_id"] for m in chain.entities["members"]}
    assert members == {d.detection_id for d in rep.detections if d.rule_id != "CORR-001"}
    union = {i for d in rep.detections if d.rule_id != "CORR-001"
             for i in d.supporting_evidence_ids}
    assert set(chain.supporting_evidence_ids) == union


def test_two_stage_types_are_not_a_chain():
    ev = Evidence()
    ev.proc(at("09:17:02"), "ws-eng-014", DROP)
    ev.file(at("09:15:40"), "ws-eng-014", "file_create", DROP)
    ev.runkey(at("09:17:10"), "ws-eng-014", RUN, DROP)
    assert by_rule(run(ev), "CORR-001") == []


def test_stages_on_different_hosts_are_not_merged():
    ev = Evidence()
    ev.proc(at("09:17:02"), "ws-eng-014", DROP)
    ev.file(at("09:15:40"), "ws-eng-014", "file_create", DROP)
    ev.runkey(at("09:17:10"), "ws-eng-014", RUN, DROP)
    ev.proc(at("09:17:20"), "ws-fin-007", "C:\\Windows\\System32\\vssadmin.exe",
            cmd="vssadmin delete shadows /all")
    assert by_rule(run(ev), "CORR-001") == []


def test_chain_window_boundary():
    ev = Evidence()                                  # third stage 61 minutes after the first
    ev.proc(at("09:17:02"), "ws-eng-014", DROP)
    ev.file(at("09:15:40"), "ws-eng-014", "file_create", DROP)
    ev.runkey(at("09:17:10"), "ws-eng-014", RUN, DROP)
    ev.proc(at("10:16:41"), "ws-eng-014", "C:\\Windows\\System32\\vssadmin.exe",
            cmd="vssadmin delete shadows /all")
    assert by_rule(run(ev), "CORR-001") == []


def test_lateral_movement_is_attributed_to_its_source_host():
    ev = Evidence()
    ev.proc(at("14:01:12"), "srv-db-01", BHZ, user="svc_sqlbackup", sha=BHZ_SHA)
    ev.auth(at("14:03:05"), "srv-dc-01", 4625, "svc_sqlbackup", "srv-db-01")
    ev.auth(at("14:03:51"), "srv-app-01", 4624, "svc_sqlbackup", "srv-db-01")
    assert by_rule(run(ev), "CORR-001") == []       # execution (x2 rules) + lateral = 2 types
    ev.proc(at("14:01:35"), "srv-db-01", "C:\\Windows\\System32\\vssadmin.exe",
            parent="bhz.exe", cmd="vssadmin.exe delete shadows /all /quiet")
    [chain] = by_rule(run(ev), "CORR-001")
    assert chain.primary_host == "srv-db-01"        # lateral counted on its SOURCE host
    assert chain.entities["stages"] == ["execution", "lateral_movement",
                                        "recovery_inhibition"]


def test_archive_delivery_to_chain_user_is_context():
    ev = Evidence()
    mail = ev.mail(at("09:11:30"), "arivera", "invoice_0613.zip")
    ev.mail(at("09:12:00"), "arivera", None)                     # no attachment
    ev.mail(at("09:12:30"), "mchen", "other.zip")                # another user
    three_stage_host(ev)
    [chain] = by_rule(run(ev), "CORR-001")
    assert mail in chain.context_evidence_ids
    assert next(c for c in chain.conditions if c.id == "delivery_context").evidence_ids == \
        (mail,)


def test_uncited_vendor_alert_is_an_uncorroborated_observation():
    ev = Evidence()
    a = ev.alert(at("11:42:55"), "srv-web-01", "Heuristic.PossibleBeacon", kind="ids_alert")
    rep = run(ev)
    assert rep.detections == ()
    [o] = rep.observations
    assert (o.rule_id, o.kind, o.evidence_ids) == ("ALERT-001", "uncorroborated_alert", (a,))


def test_cited_vendor_alert_is_not_reported_again():
    ev = Evidence()
    ev.proc(at("14:01:12"), "srv-db-01", BHZ, sha=BHZ_SHA)
    ev.alert(at("14:07:22"), "srv-db-01", "Ransomware.BlackHaze", process="bhz.exe")
    rep = run(ev)
    assert [o.rule_id for o in rep.observations] == []


def test_engine_is_deterministic_and_order_independent():
    ev = Evidence()
    three_stage_host(ev)
    ev.alert(at("09:30:00"), "srv-web-01", "X", kind="ids_alert")
    first = run(ev).to_json()
    assert run(ev).to_json() == first
    ev.records.reverse()
    assert run(ev).to_json() == first


def test_report_carries_versions_and_input_fingerprints():
    ev = Evidence()
    three_stage_host(ev)
    rep = run(ev)
    assert rep.ruleset_version.startswith("cyberrescue.detection/1+")
    assert {d.ruleset_version for d in rep.detections} == {rep.ruleset_version}
    assert set(rep.inputs) == {"evidence_count", "evidence_fingerprint",
                               "threat_intel_sha256", "unresolved_addresses"}
    assert rep.inputs["evidence_count"] == 4


def test_empty_evidence_gives_an_empty_report():
    rep = run(Evidence())
    assert rep.detections == () and rep.observations == ()
