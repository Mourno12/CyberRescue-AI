"""CyberRescue Phase 2C — the engine on the committed Phase 2B scenarios.

Expectations here are about detection BEHAVIOUR on the evidence (which rules
fire, what they cite). They do not read ground truth; the evaluation layer
(tests/test_evaluation.py) compares against the labels.
"""

import pytest

from cyberrescue.detection.engine import detect
from tests._detection_factory import scenario_core

A, B, C = "INC-C", "INC-B", "INC-A"


@pytest.fixture(scope="module")
def core(tmp_path_factory):
    svc, _ = scenario_core(tmp_path_factory.mktemp("scen") / "core.db")
    reports = {ref: detect(svc, ref) for ref in (A, B, C)}
    yield svc, reports
    svc.conn.close()


def rules(rep):
    return sorted(d.rule_id for d in rep.detections)


def one(rep, rule_id):
    [d] = [d for d in rep.detections if d.rule_id == rule_id]
    return d


def ev_where(svc, ref, **match):
    return {e.id for e in svc.list_evidence(ref)
            if all(e.data.get(k) == v if k != "event_type" else e.event_type == v
                   for k, v in match.items())}


# --- Scenario A / INC-C ----------------------------------------------------------

def test_a_detects_the_full_ransomware_chain(core):
    _, reps = core
    assert rules(reps[A]) == ["AUTH-001", "AUTH-002", "CORR-001", "IOC-001", "IOC-002",
                              "LAT-001", "PERSIST-001", "PROC-001", "RANSOM-001", "RECOV-001"]
    assert [(o.rule_id, o.kind) for o in reps[A].observations] == [("DATA-001",
                                                                     "partial_match")]


def test_a_key_attributes(core):
    _, reps = core
    rep = reps[A]
    lat = one(rep, "LAT-001")
    assert (lat.entities["source_host"], lat.entities["succeeded_hosts"],
            lat.entities["failed_only_hosts"]) == ("srv-db-01", ["srv-app-01"], ["srv-dc-01"])
    assert one(rep, "IOC-002").entities["outcome"] == "established"
    ransom = one(rep, "RANSOM-001")
    assert (ransom.entities["extension"], ransom.entities["renamed_files"],
            ransom.severity, ransom.confidence) == ("blackhaze", 34, "critical", "high")
    chain = one(rep, "CORR-001")
    assert chain.primary_host == "srv-db-01" and len(chain.entities["stages"]) == 6
    assert chain.severity == "critical"


def test_a_vendor_alert_is_context_not_support(core):
    svc, reps = core
    [alert] = [e.id for e in svc.list_evidence(A, kind="alert")]
    assert all(alert not in d.supporting_evidence_ids for d in reps[A].detections)
    assert alert in one(reps[A], "RANSOM-001").context_evidence_ids


def test_a_benign_confounders_are_never_supporting_evidence(core):
    svc, reps = core
    benign = (ev_where(svc, A, **{"process.name": "pg_dump.exe"})
              | ev_where(svc, A, **{"destination.ip": "10.20.4.30"})
              | ev_where(svc, A, event_type="4625", **{"user.name": "mchen"})
              | ev_where(svc, A, **{"process.name": "healthcheck.exe"}))
    assert len(benign) >= 6
    cited = {i for d in reps[A].detections for i in d.supporting_evidence_ids}
    assert not benign & cited


# --- Scenario B / INC-B ----------------------------------------------------------

def test_b_false_positive_produces_no_findings(core):
    _, reps = core
    rep = reps[B]
    assert rep.detections == ()
    assert sorted((o.rule_id, o.kind) for o in rep.observations) == [
        ("ALERT-001", "uncorroborated_alert"), ("IOC-002", "indicator_observed"),
        ("NET-001", "suppressed"), ("NET-001", "suppressed")]


def test_b_observations_explain_why(core):
    _, reps = core
    obs = {(o.rule_id, o.entities.get("destination_ip") or o.entities.get("indicator")
            or o.entities.get("alert")): o for o in reps[B].observations}
    assert "8.8.8.8 is allowlisted" in obs[("NET-001", "8.8.8.8")].reason
    assert "windowsupdate.microsoft.com" in obs[("NET-001", "13.107.4.50")].reason
    inbound = obs[("IOC-002", "203.0.113.66")]
    assert inbound.entities["direction"] == "inbound" and "HTTP 400" in inbound.reason
    assert obs[("ALERT-001", "Heuristic.PossibleBeacon")].kind == "uncorroborated_alert"


# --- Scenario C / INC-A ----------------------------------------------------------

def test_c_detects_contained_commodity_malware(core):
    _, reps = core
    assert rules(reps[C]) == ["CORR-001", "IOC-001", "IOC-002", "PERSIST-001", "PROC-001"]
    assert reps[C].observations == ()


def test_c_c2_blocked_and_no_lateral_or_impact(core):
    _, reps = core
    c2 = one(reps[C], "IOC-002")
    assert (c2.entities["outcome"], c2.severity) == ("blocked", "medium")
    types = {d.finding_type for d in reps[C].detections}
    assert not types & {"lateral_movement", "impact", "exfiltration", "credential_access"}


def test_c_phishing_mail_is_chain_context(core):
    svc, reps = core
    [mail] = [e.id for e in svc.list_evidence(C)
              if e.event_type == "message_delivered"
              and e.data.get("email.attachments.file.name") == ["invoice_0613.zip"]]
    chain = one(reps[C], "CORR-001")
    assert mail in chain.context_evidence_ids and chain.confidence == "medium"


# --- invariants ---------------------------------------------------------------

@pytest.mark.parametrize("ref", [A, B, C])
def test_every_detection_is_evidence_backed_within_its_incident(core, ref):
    svc, reps = core
    ids = {e.id for e in svc.list_evidence(ref)}
    for d in reps[ref].detections:
        assert d.supporting_evidence_ids and set(d.supporting_evidence_ids) <= ids
        assert set(d.context_evidence_ids) <= ids
        assert all(c.matched for c in d.conditions if c.id in _required(d.rule_id))
    for o in reps[ref].observations:
        assert set(o.evidence_ids) <= ids


def _required(rule_id):
    from cyberrescue.detection.registry import default_registry
    return set(default_registry().get(rule_id).spec.required)


def test_reports_are_identical_on_an_independent_core(core, tmp_path):
    _, reps = core
    svc, _ = scenario_core(tmp_path / "other.db", keys=("C",))   # other ingest time/actors
    try:
        assert detect(svc, C).to_json() == reps[C].to_json()
    finally:
        svc.conn.close()
