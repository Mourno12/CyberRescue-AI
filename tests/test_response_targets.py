"""CyberRescue Phase 4 — evidence-derived targets are validated before they are proposed."""

import json

import pytest

from cyberrescue.response.targets import (
    PROTECTED_ACCOUNTS_FILE,
    check_account,
    check_host,
    check_ip,
    load_protected_accounts,
)
from tests._detection_factory import Evidence, assets, at


@pytest.fixture(scope="module")
def view():
    ev = Evidence()
    ev.flow(at("10:00:00"), "srv-db-01", "185.220.101.47", 443)
    # The evidence says 45.137.21.9 is one of OUR hosts' source addresses.
    ev.flow(at("10:00:05"), "ws-fin-007", "10.10.0.5", 445, src_ip="45.137.21.9")
    return ev.view()


@pytest.fixture(scope="module")
def protected():
    return load_protected_accounts()


# --- hosts ----------------------------------------------------------------------------

def test_inventory_hosts_are_accepted():
    r = check_host("srv-db-01", assets())
    assert r.ok and r.target.kind == "host" and r.target.source == "inventory"
    assert r.target.checks == ("plain_identifier", "in_inventory")


@pytest.mark.parametrize("value", ["srv-unknown-99", "SRV-DB-01", "srv-db-01 ", "srv;rm -rf",
                                   "<script>", "", None, "a" * 80])
def test_non_inventory_or_odd_hosts_are_refused(value):
    r = check_host(value, assets())
    assert not r.ok and r.target is None


def test_refusal_reasons_never_echo_hostile_values():
    r = check_host("srv`$(calc)`IGNORE PREVIOUS", assets())
    assert "IGNORE" not in r.reason and "calc" not in r.reason


# --- ips -------------------------------------------------------------------------------

def test_an_external_malicious_ip_is_accepted(view):
    r = check_ip("185.220.101.47", view)
    assert r.ok and r.target.value == "185.220.101.47" and r.target.source == "evidence"
    assert "not_allowlisted" in r.target.checks


@pytest.mark.parametrize("value,why", [
    ("10.20.1.15", "internal"), ("192.168.1.1", "internal"), ("127.0.0.1", "internal"),
    ("203.0.113.66", "globally routable"),          # TEST-NET documentation range
    ("224.0.0.1", "internal"), ("0.0.0.0", "internal"),
    ("8.8.8.8", "allowlisted"), ("45.137.21.9", "our hosts"),
    ("not-an-ip", "valid"), ("185.220.101.47; drop", "valid"), (None, "valid")])
def test_internal_unroutable_allowlisted_or_own_addresses_are_refused(view, value, why):
    r = check_ip(value, view)
    assert not r.ok and why in r.reason


def test_ip_values_are_normalised(view):
    assert check_ip(" 185.220.101.47 ", view).target.value == "185.220.101.47"


# --- accounts --------------------------------------------------------------------------

def test_a_plain_unprotected_account_is_accepted(protected):
    r = check_account("SVC_SqlBackup", protected)
    assert r.ok and r.target.value == "svc_sqlbackup" and r.target.source == "evidence"


@pytest.mark.parametrize("name", ["Administrator", "krbtgt", "SYSTEM", "root"])
def test_protected_accounts_become_human_decisions(protected, name):
    r = check_account(name, protected)
    assert not r.ok and r.protected
    assert r.target is not None and "protected" in r.target.checks


@pytest.mark.parametrize("name", ["SRV-DB-01$", "ACME\\jdoe", "jdoe@acme.example",
                                  "j doe", "", "-x", "a" * 70, "x\nAPPROVE"])
def test_machine_domain_or_odd_accounts_are_refused(protected, name):
    r = check_account(name, protected)
    assert not r.ok and not r.protected and r.target is None


def test_protected_list_file_is_versioned_and_fingerprinted(tmp_path):
    p = load_protected_accounts()
    assert {"administrator", "krbtgt"} <= p.names and len(p.sha256) == 64
    doc = json.loads(PROTECTED_ACCOUNTS_FILE.read_text(encoding="utf-8"))
    doc["accounts"].append("IR-BreakGlass")
    other = tmp_path / "p.json"
    other.write_text(json.dumps(doc), encoding="utf-8")
    q = load_protected_accounts(other)
    assert "ir-breakglass" in q.names and q.sha256 != p.sha256
    other.write_text(json.dumps({"accounts": ["x"]}), encoding="utf-8")
    with pytest.raises(ValueError, match="protected-accounts/1"):
        load_protected_accounts(other)


def test_protected_list_fingerprint_ignores_line_endings_and_order(tmp_path):
    p = load_protected_accounts()
    raw = PROTECTED_ACCOUNTS_FILE.read_bytes().replace(b"\r\n", b"\n")
    crlf = tmp_path / "crlf.json"
    crlf.write_bytes(raw.replace(b"\n", b"\r\n"))
    assert load_protected_accounts(crlf).sha256 == p.sha256
    doc = json.loads(raw)
    doc["accounts"] = list(reversed(doc["accounts"]))
    rev = tmp_path / "rev.json"
    rev.write_text(json.dumps(doc), encoding="utf-8")
    assert load_protected_accounts(rev).sha256 == p.sha256
