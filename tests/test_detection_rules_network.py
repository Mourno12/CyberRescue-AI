"""CyberRescue Phase 2C — threat intel (IOC-001/002) and beaconing (NET-001)."""

from cyberrescue.detection.context import ThreatIntel
from cyberrescue.detection.model import Detection, Observation
from cyberrescue.detection.rules.network import (
    KnownMaliciousHash,
    MaliciousInfrastructureContact,
    PeriodicOutbound,
)
from tests._detection_factory import Evidence, at

C2 = "185.220.101.47"
GREY_SHA = "7c1f9b44a2e6d8035f1c0a7e9d2b46813c5a0e9f4b7d2a16c8e3f0b5d9a2c4e1"


def results(rule, ev, intel=None):
    return rule.evaluate(ev.view(intel))


def dets(rule, ev, intel=None):
    return [r for r in results(rule, ev, intel) if isinstance(r, Detection)]


# --- IOC-001 -------------------------------------------------------------------

def test_known_malicious_hash_inherits_intel_confidence():
    ev = Evidence()
    p = ev.proc(at("09:17:02"), "ws-eng-014", "C:\\Users\\a\\Downloads\\x.exe", sha=GREY_SHA)
    a = ev.alert(at("09:18:04"), "ws-eng-014", "Trojan.GreyLoader", sha=GREY_SHA)
    [d] = dets(KnownMaliciousHash(), ev)
    assert d.supporting_evidence_ids == (p,) and d.context_evidence_ids == (a,)
    assert d.confidence == "high" and d.entities["malware_family"] == "GreyLoader"
    assert "threat-intel confidence 'high'" in d.confidence_basis


def test_unknown_and_benign_hashes_do_not_fire():
    ev = Evidence()
    ev.proc(at("09:00:00"), "ws-eng-014", "C:\\Python312\\python.exe")
    intel = ThreatIntel([{"indicator": GREY_SHA, "type": "sha256", "status": "benign"}])
    ev.proc(at("09:00:01"), "ws-eng-014", "C:\\x.exe", sha=GREY_SHA)
    assert results(KnownMaliciousHash(), ev, intel) == []


# --- IOC-002 -------------------------------------------------------------------

def test_established_c2_connection_is_high_severity():
    ev = Evidence()
    c = ev.connect(at("14:02:40"), "srv-db-01", C2, 443, process="bhz.exe")
    f = ev.flow(at("14:02:40"), "srv-db-01", C2, 443, out=48213, inb=3120)
    [d] = dets(MaliciousInfrastructureContact(), ev)
    assert set(d.supporting_evidence_ids) == {c, f}
    assert (d.severity, d.entities["outcome"], d.confidence) == ("high", "established", "high")


def test_blocked_domain_contact_is_reported_as_blocked():
    ev = Evidence()
    q = ev.dns(at("09:17:31"), "ws-eng-014", "cdn-pidgin-loader.net", "203.0.113.77")
    r = ev.proxy(at("09:17:32"), "ws-eng-014", "cdn-pidgin-loader.net:443", verdict="blocked",
                 status=403)
    [d] = dets(MaliciousInfrastructureContact(), ev)
    assert d.supporting_evidence_ids == (q, r)
    assert (d.severity, d.entities["outcome"]) == ("medium", "blocked")
    assert not next(c for c in d.conditions if c.id == "connection_established").matched


def test_flow_without_return_traffic_is_only_attempted():
    ev = Evidence()
    ev.flow(at("10:00:00"), "srv-db-01", C2, 443, inb=0)
    [d] = dets(MaliciousInfrastructureContact(), ev)
    assert (d.severity, d.entities["outcome"]) == ("medium", "attempted")


def test_inbound_indicator_is_an_observation_not_a_finding():
    ev = Evidence()
    h = ev.http_in(at("11:21:07"), "srv-web-01", "203.0.113.66", status=400)
    [o] = results(MaliciousInfrastructureContact(), ev)
    assert isinstance(o, Observation) and o.kind == "indicator_observed"
    assert o.evidence_ids == (h,) and o.entities["direction"] == "inbound"
    assert "not a finding" in o.reason


def test_benign_and_lookalike_indicators_never_match():
    ev = Evidence()
    ev.flow(at("11:00:00"), "srv-web-01", "8.8.8.8", 53)                   # benign IOC
    ev.dns(at("11:00:01"), "srv-web-01", "windowsupdate.microsoft.com", "13.107.4.50")
    ev.http_in(at("11:00:02"), "srv-web-01", "198.51.100.234")              # not .23
    ev.proxy(at("11:00:03"), "ws-eng-014", "https://cdn-pidgin-loader.net.example.org/")
    assert results(MaliciousInfrastructureContact(), ev) == []


# --- NET-001 -------------------------------------------------------------------

def periodic(ev, dst, port, gaps=(300, 302, 298, 301, 299)):
    """Flows separated by exactly ``gaps`` seconds."""
    times, t = [0], 0
    for g in gaps:
        t += g
        times.append(t)
    return [ev.flow(at("11:00:00", s), "srv-web-01", dst, port, proto="udp") for s in times]


def test_periodic_outbound_to_unknown_external_fires():
    ev = Evidence()
    ids = periodic(ev, "93.184.216.34", 443)
    [d] = dets(PeriodicOutbound(), ev)
    assert d.supporting_evidence_ids == tuple(ids)
    assert (d.entities["period_seconds"], d.entities["connections"]) == (300, 6)
    assert d.confidence == "low"


def test_periodic_outbound_to_active_ioc_raises_confidence():
    ev = Evidence()
    periodic(ev, C2, 443)
    [d] = dets(PeriodicOutbound(), ev)
    assert d.confidence == "medium"


def test_allowlisted_resolver_is_suppressed():
    ev = Evidence()
    periodic(ev, "8.8.8.8", 53)
    [o] = results(PeriodicOutbound(), ev)
    assert isinstance(o, Observation) and o.kind == "suppressed"
    assert "8.8.8.8 is allowlisted" in o.reason


def test_allowlisted_via_dns_answer_cites_the_dns_evidence():
    ev = Evidence()
    q = ev.dns(at("10:59:59"), "srv-web-01", "windowsupdate.microsoft.com", "13.107.4.50")
    periodic(ev, "13.107.4.50", 443, gaps=(600, 600, 600, 600))
    [o] = results(PeriodicOutbound(), ev)
    assert o.kind == "suppressed" and q in o.evidence_ids
    assert "windowsupdate.microsoft.com" in o.reason


def test_irregular_internal_and_short_series_do_not_fire():
    ev = Evidence()
    periodic(ev, "93.184.216.34", 443, gaps=(300, 340, 270, 355, 240))     # irregular
    periodic(ev, "10.20.1.15", 5432)                                       # internal
    periodic(ev, "93.184.216.35", 443, gaps=(300, 300))                    # too few
    assert results(PeriodicOutbound(), ev) == []


def test_jitter_boundary():
    ev = Evidence()                       # median 300 s; 5 % = 15 s tolerance
    periodic(ev, "93.184.216.34", 443, gaps=(300, 300, 300, 315, 285))
    assert len(dets(PeriodicOutbound(), ev)) == 1
    ev = Evidence()
    periodic(ev, "93.184.216.34", 443, gaps=(300, 300, 300, 316, 284))
    assert results(PeriodicOutbound(), ev) == []
