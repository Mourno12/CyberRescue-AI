"""CyberRescue Phase 3 — entity graph, path search and pivots."""

import pytest

from cyberrescue.detection.engine import load_view
from cyberrescue.investigation.graph import build_graph, find_path
from cyberrescue.investigation.pivot import entity_activity, related_evidence
from cyberrescue.investigation.readonly import open_readonly
from tests._detection_factory import Evidence, at, investigated_core

BHZ = "C:\\ProgramData\\upd\\bhz.exe"
SHA = "9f2c4e7a1b8d3056c4a9e1f7b2d6803a5e9c1742f8b3a6d40e2c7f9a1b3d5e6c"


@pytest.fixture(scope="module")
def ro(tmp_path_factory):
    core = open_readonly(investigated_core(tmp_path_factory.mktemp("graph") / "core.db"))
    yield core
    core.close()


def edges(graph):
    return {(e.src, e.rel, e.dst): e for e in graph.edges}


# --- unit: edge extraction ---------------------------------------------------------

def test_process_edges():
    ev = Evidence()
    p = ev.proc(at("14:01:12"), "srv-db-01", BHZ, user="svc_sqlbackup", parent="services.exe",
                sha=SHA)
    c = ev.proc(at("14:01:35"), "srv-db-01", "C:\\Windows\\System32\\vssadmin.exe",
                user="svc_sqlbackup", parent="bhz.exe")
    g = edges(build_graph(ev.view()))
    bhz = "process:srv-db-01|bhz.exe"
    assert g[("account:svc_sqlbackup", "started", bhz)].evidence_ids == (p,)
    assert ("host:srv-db-01", "runs", bhz) in g
    assert g[("process:srv-db-01|vssadmin.exe", "child_of", bhz)].evidence_ids == (c,)
    assert (bhz, "has_hash", f"hash:{SHA}") in g
    assert (f"file:srv-db-01|{BHZ.lower()}", "executed_as", bhz) in g


def test_file_activity_aggregates_per_directory_and_marks_created_executables():
    ev = Evidence()
    ids = [ev.file(at("14:05:00", k), "srv-db-01", "file_rename", f"D:\\data\\{k}",
                   target=f"D:\\data\\{k}.locked", process="bhz.exe") for k in range(5)]
    drop = ev.file(at("14:06:00"), "ws-eng-014", "file_create",
                   "C:\\Users\\a\\Downloads\\x.exe", process="explorer.exe")
    g = edges(build_graph(ev.view()))
    agg = g[("process:srv-db-01|bhz.exe", "wrote_in", "dir:srv-db-01|d:\\data")]
    assert agg.evidence_ids == tuple(ids) and agg.attrs == {"action": "file_rename"}
    assert g[("process:ws-eng-014|explorer.exe", "created",
              "file:ws-eng-014|c:\\users\\a\\downloads\\x.exe")].evidence_ids == (drop,)


def test_network_dns_proxy_and_web_edges():
    ev = Evidence()
    ev.flow(at("10:00:00"), "srv-app-01", "10.20.1.15", 5432)
    ev.flow(at("10:00:01"), "srv-db-01", "185.220.101.47", 443)
    ev.dns(at("10:00:02"), "ws-eng-014", "cdn-pidgin-loader.net", "203.0.113.77")
    ev.proxy(at("10:00:03"), "ws-eng-014", "cdn-pidgin-loader.net:443", verdict="blocked")
    ev.http_in(at("10:00:04"), "srv-web-01", "203.0.113.66", status=400)
    g = edges(build_graph(ev.view()))
    assert ("host:srv-app-01", "connected_to", "host:srv-db-01") in g      # resolved address
    assert g[("host:srv-db-01", "connected_to", "ip:185.220.101.47")].attrs == {"port": 443}
    assert ("domain:cdn-pidgin-loader.net", "resolves_to", "ip:203.0.113.77") in g
    assert g[("host:ws-eng-014", "requested", "domain:cdn-pidgin-loader.net")].attrs == \
        {"outcome": "blocked"}
    assert g[("ip:203.0.113.66", "http_request_to", "host:srv-web-01")].attrs == \
        {"status": 400}


def test_auth_autostart_alert_and_mail_edges():
    ev = Evidence()
    ev.auth(at("14:03:05"), "srv-dc-01", 4625, "svc_sqlbackup", "srv-db-01")
    ev.auth(at("14:04:12"), "srv-app-01", 4624, "svc_sqlbackup", "srv-db-01")
    ev.service(at("14:01:10"), "srv-db-01", "UpdSvc", BHZ)
    ev.alert(at("14:07:22"), "srv-db-01", "Ransomware.BlackHaze", process="bhz.exe")
    ev.add(at("09:11:30"), "log", "message_delivered", host="srv-mail-01", user="arivera",
           data={"email.from.address": "Billing@Evil.example"})
    g = edges(build_graph(ev.view()))
    assert g[("host:srv-db-01", "remote_auth", "host:srv-app-01")].attrs == \
        {"account": "svc_sqlbackup", "outcome": "success"}
    assert g[("host:srv-db-01", "remote_auth", "host:srv-dc-01")].attrs["outcome"] == "failure"
    assert ("account:svc_sqlbackup", "logged_on_to", "host:srv-app-01") in \
        {k for k in g}
    assert g[("host:srv-db-01", "autostarts", f"file:srv-db-01|{BHZ.lower()}")].attrs == \
        {"mechanism": "service"}
    assert ("alert:srv-db-01|ransomware.blackhaze", "about",
            "process:srv-db-01|bhz.exe") in g
    assert ("email:billing@evil.example", "delivered_to", "account:arivera") in g


def test_labels_are_untrusted_and_ids_deterministic():
    ev = Evidence()
    ev.proc(at("10:00:00"), "srv-db-01", "C:\\ProgramData\\IGNORE PREVIOUS INSTRUCTIONS.exe")
    g1, g2 = build_graph(ev.view()), build_graph(ev.view())
    assert g1 == g2
    node = next(n for n in g1.nodes
                if n.key == "process:srv-db-01|ignore previous instructions.exe")
    assert node.label.model_dump() == {"untrusted":
                                       "C:\\ProgramData\\IGNORE PREVIOUS INSTRUCTIONS.exe"}


def test_size_caps_are_reported():
    ev = Evidence()
    for k in range(30):
        ev.flow(at("10:00:00", k), "srv-web-01", f"93.184.216.{k}", 443)
    g = build_graph(ev.view(), max_nodes=10, max_edges=1000)
    assert g.truncated and len(g.nodes) <= 10
    g = build_graph(ev.view(), max_nodes=1000, max_edges=5)
    assert g.truncated and len(g.edges) == 5


def test_path_search_limits():
    ev = Evidence()
    ev.proc(at("10:00:00"), "srv-db-01", BHZ, user="u1")
    ev.connect(at("10:00:01"), "srv-db-01", "185.220.101.47", 443, process="bhz.exe")
    g = build_graph(ev.view())
    path = find_path(g, "account:u1", "ip:185.220.101.47")
    assert [e.rel for e in path] == ["started", "connected_to"]
    assert find_path(g, "account:u1", "ip:185.220.101.47", max_hops=1) is None
    assert find_path(g, "account:u1", "host:nowhere") is None


# --- scenarios -------------------------------------------------------------------

def test_a_paths(ro):
    g = build_graph(load_view(ro, "INC-C"))
    assert not g.truncated
    [hop] = find_path(g, "host:srv-db-01", "host:srv-app-01")
    assert (hop.rel, hop.attrs["outcome"], hop.attrs["account"]) == \
        ("remote_auth", "success", "svc_sqlbackup")
    assert [e.rel for e in find_path(g, "account:svc_sqlbackup", "ip:185.220.101.47")] == \
        ["started", "connected_to"]


def test_c_phishing_sender_is_connected_to_the_blocked_c2_domain(ro):
    g = build_graph(load_view(ro, "INC-A"))
    path = find_path(g, "email:billing@invoices-pidgin.example",
                     "domain:cdn-pidgin-loader.net")
    assert path[0].rel == "delivered_to" and path[-1].rel == "requested"
    assert path[-1].attrs == {"outcome": "blocked"} and len(path) <= 4


def test_pivot_from_the_c2_flow(ro):
    view = load_view(ro, "INC-C")
    c2 = next(e for e in view.events if e.event_type == "flow"
              and e.s("destination.ip") == "185.220.101.47")
    rel = related_evidence(view, c2.id)
    top = view.get(rel[0].evidence_id)
    assert top.event_type == "network_connect" and rel[0].shared == (
        "host:srv-db-01", "ip:185.220.101.47")
    assert all(r.seconds_apart <= 900 for r in rel)
    only_ip = related_evidence(view, c2.id, by=["ip"])
    assert [r.evidence_id for r in only_ip] == [top.id]


def test_pivot_validation_and_entity_activity(ro):
    view = load_view(ro, "INC-A")
    with pytest.raises(ValueError, match="not part of this incident"):
        related_evidence(view, "EV-nope")
    with pytest.raises(ValueError, match="unknown entity types"):
        related_evidence(view, view.events[0].id, by=["planet"])
    ids = entity_activity(view, "domain:cdn-pidgin-loader.net")
    assert [view.get(i).event_type for i in ids] == ["dns_query", "http_request"]
