"""CyberRescue Phase 2C — authentication (AUTH-001/002) and lateral movement (LAT-001)."""

from cyberrescue.detection.model import Detection
from cyberrescue.detection.rules.auth import FailedThenSuccess, RepeatedFailures
from cyberrescue.detection.rules.lateral import RemoteAuthToMultipleHosts
from tests._detection_factory import Evidence, at


def dets(rule, ev):
    return [r for r in rule.evaluate(ev.view()) if isinstance(r, Detection)]


def cond(det, cid):
    return next(c for c in det.conditions if c.id == cid)


# --- AUTH-001 ------------------------------------------------------------------

def burst(ev, *, failures=2, success_after=20, src="srv-db-01", target="srv-app-01"):
    ids = [ev.auth(at("14:03:52", 6 * n), target, 4625, "svc_sqlbackup", src)
           for n in range(failures)]
    if success_after is not None:
        ids.append(ev.auth(at("14:03:52", success_after), target, 4624, "svc_sqlbackup", src))
    return ids


def test_failures_then_success_fires_with_full_explanation():
    ev = Evidence()
    ids = burst(ev)
    [d] = dets(FailedThenSuccess(), ev)
    assert d.rule_id == "AUTH-001" and d.supporting_evidence_ids == tuple(ids)
    assert d.primary_host == "srv-app-01" and d.entities["source_host"] is None
    assert d.entities["success_after_seconds"] == 20
    assert cond(d, "network_logon").matched and cond(d, "first_seen_source").matched
    assert d.confidence == "high" and d.window.seconds == 300


def test_single_failure_then_success_does_not_fire():
    ev = Evidence()
    burst(ev, failures=1)
    assert dets(FailedThenSuccess(), ev) == []


def test_success_outside_window_does_not_fire_and_boundary_is_inclusive():
    ev = Evidence()
    burst(ev, success_after=301)
    assert dets(FailedThenSuccess(), ev) == []
    ev = Evidence()
    burst(ev, success_after=300)
    assert len(dets(FailedThenSuccess(), ev)) == 1


def test_mistyped_password_like_scenario_a_is_benign():
    ev = Evidence()                              # mchen: one interactive failure, success later
    ev.auth(at("13:40:13"), "srv-dc-01", 4625, "mchen", "ws-fin-007", logon="2")
    ev.auth(at("14:08:14"), "srv-dc-01", 4624, "mchen", "ws-fin-007", package="Kerberos")
    assert dets(FailedThenSuccess(), ev) == [] and dets(RepeatedFailures(), ev) == []


def test_failures_from_a_different_source_are_not_combined():
    ev = Evidence()
    ev.auth(at("14:00:00"), "srv-app-01", 4625, "bob", src_ip="10.1.1.1")
    ev.auth(at("14:00:05"), "srv-app-01", 4625, "bob", src_ip="10.1.1.2")
    ev.auth(at("14:00:10"), "srv-app-01", 4624, "bob", src_ip="10.1.1.1")
    assert dets(FailedThenSuccess(), ev) == []


def test_known_source_lowers_confidence():
    ev = Evidence()
    ev.auth(at("13:00:00"), "srv-app-01", 4624, "svc_sqlbackup", "srv-db-01")
    burst(ev)
    [d] = dets(FailedThenSuccess(), ev)
    assert not cond(d, "first_seen_source").matched and d.confidence == "medium"


def test_benign_kerberos_background_does_not_fire():
    ev = Evidence()
    for n in range(10):
        ev.auth(at("13:30:00", 60 * n), "srv-dc-01", 4624, "svc_app", "srv-app-01",
                package="Kerberos")
    assert dets(FailedThenSuccess(), ev) == dets(RepeatedFailures(), ev) == []


# --- AUTH-002 ------------------------------------------------------------------

def test_repeated_failures_needs_three_and_no_success():
    ev = Evidence()
    burst(ev, failures=2, success_after=None, target="srv-dc-01")
    assert dets(RepeatedFailures(), ev) == []
    ev = Evidence()
    ids = burst(ev, failures=3, success_after=None, target="srv-dc-01")
    [d] = dets(RepeatedFailures(), ev)
    assert d.supporting_evidence_ids == tuple(ids) and d.entities["failures"] == 3
    ev = Evidence()
    burst(ev, failures=3, success_after=30)                # ends in success -> AUTH-001 only
    assert dets(RepeatedFailures(), ev) == [] and len(dets(FailedThenSuccess(), ev)) == 1


# --- LAT-001 -------------------------------------------------------------------

def lateral(ev, *, second_after=46, user2="svc_sqlbackup"):
    a = ev.auth(at("14:03:05"), "srv-dc-01", 4625, "svc_sqlbackup", "srv-db-01")
    b = ev.auth(at("14:03:05", second_after), "srv-app-01", 4624, user2, "srv-db-01")
    return a, b


def test_same_account_to_two_hosts_fires():
    ev = Evidence()
    a, b = lateral(ev)
    [d] = dets(RemoteAuthToMultipleHosts(), ev)
    assert d.primary_host == "srv-db-01" and d.supporting_evidence_ids == (a, b)
    assert d.entities["destinations"] == ["srv-app-01", "srv-dc-01"]
    assert d.entities["succeeded_hosts"] == ["srv-app-01"]
    assert d.entities["failed_only_hosts"] == ["srv-dc-01"]


def test_single_destination_repeated_does_not_fire():
    ev = Evidence()
    for n in range(5):
        ev.auth(at("14:00:00", 10 * n), "srv-dc-01", 4624, "svc_app", "srv-app-01")
    assert dets(RemoteAuthToMultipleHosts(), ev) == []


def test_second_host_outside_window_does_not_fire():
    ev = Evidence()
    lateral(ev, second_after=901)
    assert dets(RemoteAuthToMultipleHosts(), ev) == []
    ev = Evidence()
    lateral(ev, second_after=900)
    assert len(dets(RemoteAuthToMultipleHosts(), ev)) == 1


def test_different_accounts_are_not_combined():
    ev = Evidence()
    lateral(ev, user2="other")
    assert dets(RemoteAuthToMultipleHosts(), ev) == []


def test_interactive_and_self_logons_are_ignored():
    ev = Evidence()
    ev.auth(at("14:00:00"), "srv-dc-01", 4624, "u", "ws-eng-014", logon="2")
    ev.auth(at("14:00:10"), "srv-app-01", 4624, "u", "ws-eng-014", logon="2")
    ev.auth(at("14:00:20"), "srv-db-01", 4624, "u", "srv-db-01")
    ev.auth(at("14:00:30"), "srv-dc-01", 4624, "u", "srv-db-01")
    assert dets(RemoteAuthToMultipleHosts(), ev) == []


def test_corroboration_raises_confidence_and_adds_evidence():
    ev = Evidence()
    lateral(ev)
    [plain] = dets(RemoteAuthToMultipleHosts(), ev)
    proc = ev.proc(at("14:01:12"), "srv-db-01", "C:\\ProgramData\\upd\\bhz.exe",
                   user="svc_sqlbackup")
    smb = ev.flow(at("14:03:05"), "srv-db-01", "10.10.0.5", 445)
    [full] = dets(RemoteAuthToMultipleHosts(), ev)
    assert plain.confidence == "medium"                            # NTLM only
    assert full.confidence == "high"
    assert {proc, smb} <= set(full.supporting_evidence_ids)
    assert cond(full, "admin_protocol_flows").detail["ports"] == [445]
