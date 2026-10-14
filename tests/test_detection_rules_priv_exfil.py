"""CyberRescue Phase 2C — privilege escalation (PRIV-001) and exfiltration (DATA-001).

Neither pattern exists in the Phase 2B scenarios (decision D1 = a): these rules
are exercised with unit fixtures only.
"""

from cyberrescue.detection.model import Detection, Observation
from cyberrescue.detection.rules.privilege import NewPrivilegedAccount
from tests._detection_factory import Evidence, at


def results(rule, ev):
    return rule.evaluate(ev.view())


# --- PRIV-001 ------------------------------------------------------------------

def test_new_account_added_to_domain_admins():
    ev = Evidence()
    c = ev.account(at("10:00:00"), "srv-dc-01", 4720, "backup_adm")
    g = ev.account(at("10:02:00"), "srv-dc-01", 4728, "backup_adm", group="Domain Admins")
    lg = ev.auth(at("10:05:00"), "srv-db-01", 4624, "backup_adm", "srv-dc-01")
    [d] = results(NewPrivilegedAccount(), ev)
    assert isinstance(d, Detection) and d.supporting_evidence_ids == (c, g, lg)
    assert d.entities["group"] == "domain admins" and d.confidence == "high"


def test_new_account_in_ordinary_group_is_benign():
    ev = Evidence()
    ev.account(at("10:00:00"), "srv-dc-01", 4720, "newhire")
    ev.account(at("10:01:00"), "srv-dc-01", 4732, "newhire", group="Remote Desktop Users")
    assert results(NewPrivilegedAccount(), ev) == []


def test_account_creation_alone_and_late_group_change():
    ev = Evidence()
    ev.account(at("10:00:00"), "srv-dc-01", 4720, "temp1")
    assert results(NewPrivilegedAccount(), ev) == []
    ev.account(at("11:00:01"), "srv-dc-01", 4728, "temp1", group="Domain Admins")
    [r] = results(NewPrivilegedAccount(), ev)          # outside the hour: review only
    assert isinstance(r, Observation) and r.kind == "indicator_observed"


def test_existing_admin_change_is_an_observation_not_a_finding():
    ev = Evidence()
    ev.account(at("10:00:00"), "srv-dc-01", 4732, "jdoe", group="Administrators")
    [r] = results(NewPrivilegedAccount(), ev)
    assert isinstance(r, Observation) and "review, not a finding" in r.reason


# --- DATA-001 ------------------------------------------------------------------

from cyberrescue.detection.rules.exfil import SensitiveAssetExfiltration  # noqa: E402

MB = 1024 * 1024
PG_DUMP = r"C:\Program Files\PostgreSQL\15\bin\pg_dump.exe"


def test_large_external_transfer_after_dump_from_pii_host():
    ev = Evidence()
    dump = ev.proc(at("13:45:02"), "srv-db-01", PG_DUMP, cmd="pg_dump -Fc crm")
    f1 = ev.flow(at("14:00:00"), "srv-db-01", "93.184.216.34", 443, out=30 * MB)
    f2 = ev.flow(at("14:10:00"), "srv-db-01", "93.184.216.34", 443, out=25 * MB)
    [d] = results(SensitiveAssetExfiltration(), ev)
    assert isinstance(d, Detection) and d.supporting_evidence_ids == (dump, f1, f2)
    assert d.entities["bytes"] == 55 * MB and d.confidence == "high"
    assert "customer_pii" in d.entities["data_classes"]


def test_large_internal_backup_is_benign():
    ev = Evidence()                                    # Scenario A's backup to the vault
    ev.proc(at("13:45:02"), "srv-db-01", PG_DUMP)
    ev.flow(at("13:48:00"), "srv-db-01", "10.20.4.30", 873, out=115 * MB)
    assert results(SensitiveAssetExfiltration(), ev) == []


def test_small_external_transfer_after_dump_is_an_incomplete_chain():
    ev = Evidence()                                    # Scenario A: pg_dump then 48 KB C2
    ev.proc(at("13:45:02"), "srv-db-01", PG_DUMP)
    ev.flow(at("14:02:40"), "srv-db-01", "185.220.101.47", 443, out=48213)
    [o] = results(SensitiveAssetExfiltration(), ev)
    assert isinstance(o, Observation) and o.kind == "partial_match"
    assert "incomplete exfiltration chain" in o.reason


def test_non_sensitive_host_and_window_boundary():
    ev = Evidence()
    ev.flow(at("14:00:00"), "srv-web-01", "93.184.216.34", 443, out=80 * MB)  # public data
    ev.flow(at("14:00:00"), "srv-db-01", "93.184.216.34", 443, out=30 * MB)
    ev.flow(at("14:15:01"), "srv-db-01", "93.184.216.34", 443, out=30 * MB)   # 901 s later
    assert results(SensitiveAssetExfiltration(), ev) == []
