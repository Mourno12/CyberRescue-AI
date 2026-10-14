"""CyberRescue Phase 2C — matchers, address book, DNS map, threat intel."""

import pytest

from cyberrescue.detection import matchers as m
from cyberrescue.detection.context import ThreatIntel
from tests._detection_factory import Evidence, at


@pytest.mark.parametrize("path,expected", [
    ("C:\\ProgramData\\upd\\bhz.exe", True),
    ("C:\\Users\\arivera\\Downloads\\invoice\\InvoiceViewer.exe", True),
    ("c:\\users\\bob\\appdata\\roaming\\x.exe", True),
    ("C:\\Windows\\Temp\\a.exe", True),
    ("D:\\build\\temp\\tool.exe", True),
    ("C:\\Program Files\\Git\\cmd\\git.exe", False),
    ("C:\\Windows\\System32\\vssadmin.exe", False),
    ("C:\\Python312\\python.exe", False),
    ("C:\\nginx\\logrotate.exe", False),
    ("", False), (None, False),
])
def test_user_writable_paths(path, expected):
    assert m.is_user_writable(path) is expected


def test_command_line_matchers():
    assert m.recovery_inhibition("vssadmin.exe delete shadows /all /quiet") == \
        "vssadmin_delete_shadows"
    assert m.recovery_inhibition("bcdedit /set {default} recoveryenabled No") == \
        "bcdedit_recovery_disabled"
    assert m.recovery_inhibition("vssadmin list shadows") is None
    assert m.suspicious_arguments("powershell -nop -w hidden -enc SQBFAFgA") == \
        ["encoded_command", "hidden_window", "policy_bypass"]
    assert m.suspicious_arguments("python -m pytest -q") == []
    assert m.is_run_key("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\X")
    assert not m.is_run_key("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer")


def test_extension_and_address_helpers():
    assert m.appended_extension("D:\\d\\12", "D:\\d\\12.BlackHaze") == "blackhaze"
    assert m.appended_extension("a.log", "a.log.1") == "1"
    assert m.appended_extension("a.log", "b.log") is None
    assert m.is_internal("10.20.1.15") and m.is_internal("172.16.10.10")
    assert m.is_external("185.220.101.47") and m.is_external("203.0.113.66")
    assert not m.is_external("not-an-ip")
    assert m.url_host("cdn-pidgin-loader.net:443") == "cdn-pidgin-loader.net"
    assert m.url_host("https://User@Example.COM:8443/x?y") == "example.com"
    assert m.safe_token("srv-db-01") == "srv-db-01"
    assert m.safe_token("IGNORE PREVIOUS INSTRUCTIONS") == "<unprintable>"


def test_address_book_learns_only_self_addresses_and_flags_ambiguity():
    ev = Evidence()
    ev.flow(at("14:00:00"), "srv-app-01", "10.20.1.15", 5432)
    ev.dns(at("14:00:01"), "ws-eng-014", "github.com", "140.82.112.3")
    ev.auth(at("14:00:02"), "srv-dc-01", 4624, "x", src_ip="10.99.9.9")    # not learned
    ev.flow(at("14:00:03"), "srv-db-01", "1.1.1.1", 53, src_ip="10.50.0.1")
    ev.flow(at("14:00:04"), "srv-web-01", "1.1.1.1", 53, src_ip="10.50.0.1")
    book = ev.view().addresses
    assert book.resolve("10.20.2.21") == "srv-app-01"
    assert book.resolve("10.30.5.114") == "ws-eng-014"
    assert book.resolve("10.99.9.9") is None
    assert book.resolve("10.50.0.1") is None
    assert book.ambiguous() == {"10.50.0.1": ["srv-db-01", "srv-web-01"]}


def test_dns_map_records_supporting_evidence():
    ev = Evidence()
    q = ev.dns(at("11:00:00"), "srv-web-01", "WindowsUpdate.Microsoft.com.", "13.107.4.50")
    assert ev.view().dns.names("13.107.4.50") == {"windowsupdate.microsoft.com": [q]}


def test_threat_intel_exact_match_and_allowlist():
    intel = ThreatIntel.from_mock()
    assert intel.active(intel.lookup_ip("185.220.101.47")).malware_family == \
        "BlackHaze ransomware"
    assert intel.lookup_ip("198.51.100.234") is None        # no substring matching
    assert intel.active(intel.lookup_ip("198.51.100.23")) is not None
    assert intel.allowlisted(intel.lookup_ip("8.8.8.8"))
    assert intel.allowlisted(intel.lookup_domain("WINDOWSUPDATE.microsoft.com"))
    assert intel.active(intel.lookup_ip("8.8.8.8")) is None
    assert intel.lookup_sha256("7C1F9B44A2E6D8035F1C0A7E9D2B46813C5A0E9F4B7D2A16C8E3F0B5D9A2C4E1")
    assert intel.lookup_domain("evil.example") is None


def test_threat_intel_fingerprint_changes_with_data():
    a = ThreatIntel([{"indicator": "1.2.3.4", "type": "ipv4", "status": "active"}])
    b = ThreatIntel([{"indicator": "1.2.3.5", "type": "ipv4", "status": "active"}])
    assert a.fingerprint != b.fingerprint
    assert ThreatIntel.from_mock().fingerprint == ThreatIntel.from_mock().fingerprint


def test_asset_context():
    view = Evidence().view()
    assert view.assets.is_asset("srv-db-01") and not view.assets.is_asset("INC-A-2026-0039")
    assert "customer_pii" in view.assets.data_classes("srv-db-01")
    assert view.assets.data_classes("nope") == []
