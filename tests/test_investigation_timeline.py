"""CyberRescue Phase 3 — annotated, condensed incident timeline."""

import pytest

from cyberrescue.detection.engine import DetectionEngine, detect, load_view
from cyberrescue.investigation.findings import citations_by_evidence, collect_findings
from cyberrescue.investigation.model import Citation
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.investigation.timeline import build_timeline
from tests._detection_factory import Evidence, at, investigated_core


@pytest.fixture(scope="module")
def ro(tmp_path_factory):
    core = open_readonly(investigated_core(tmp_path_factory.mktemp("tl") / "core.db"))
    yield core
    core.close()


def scenario_timeline(ro, ref, **kw):
    iid = ro.resolve(ref)
    view = load_view(ro, ref)
    cites = citations_by_evidence(collect_findings(ro, iid))
    return build_timeline(view, citations=cites, report=detect(ro, ref), **kw)


def flows(ev, offsets, dst="93.184.216.34"):
    return [ev.flow(at("10:00:00", s), "srv-web-01", dst, 443) for s in offsets]


# --- unit ----------------------------------------------------------------------

def test_events_are_ordered_and_counted():
    ev = Evidence()
    b = ev.proc(at("10:05:00"), "srv-db-01", "C:\\x.exe")
    a = ev.proc(at("10:00:00"), "srv-db-01", "C:\\y.exe")
    tl = build_timeline(ev.view(), condense=False)
    assert [e.evidence_ids for e in tl.entries] == [(a,), (b,)]
    assert (tl.evidence_total, tl.evidence_shown, tl.condensed) == (2, 2, False)


def test_burst_gap_boundary_and_minimum_size():
    ev = Evidence()
    ids = flows(ev, [0, 60, 120])
    [burst] = build_timeline(ev.view()).entries
    assert (burst.entry, burst.count, burst.evidence_ids) == ("burst", 3, tuple(ids))
    assert burst.detail.untrusted.endswith("(+2 more)")
    ev = Evidence()
    flows(ev, [0, 61, 122])
    assert [e.entry for e in build_timeline(ev.view()).entries] == ["event"] * 3
    ev = Evidence()
    flows(ev, [0, 10])
    assert [e.entry for e in build_timeline(ev.view()).entries] == ["event"] * 2


def test_interleaved_events_still_chain_but_different_keys_do_not():
    ev = Evidence()
    ids = flows(ev, [0, 20, 40])
    other = flows(ev, [10, 30], dst="10.20.1.15")
    entries = build_timeline(ev.view()).entries
    assert [e.evidence_ids for e in entries if e.entry == "burst"] == [tuple(ids)]
    assert {e.evidence_ids[0] for e in entries if e.entry == "event"} == set(other)


def test_cited_and_uncited_events_never_merge():
    ev = Evidence()
    ids = flows(ev, [0, 20, 40, 60])
    cite = {ids[1]: [Citation(finding_id="F1", origin="detection", rule_id="X-001",
                              relation="supports")]}
    entries = build_timeline(ev.view(), citations=cite).entries
    cited = [e for e in entries if e.cited_by]
    assert len(cited) == 1 and cited[0].evidence_ids == (ids[1],)
    assert [e.count for e in entries if e.entry == "burst"] == [3]


def test_filters():
    ev = Evidence()
    ev.proc(at("10:00:00"), "srv-db-01", "C:\\a.exe")
    ev.proc(at("11:00:00"), "srv-app-01", "C:\\b.exe")
    ev.proc(at("12:00:00"), "srv-db-01", "C:\\c.exe")
    view = ev.view()
    assert len(build_timeline(view, host="srv-db-01").entries) == 2
    tl = build_timeline(view, since="2026-06-13T10:30:00Z", until="2026-06-13T11:30:00+00:00")
    assert [e.host for e in tl.entries] == ["srv-app-01"]
    assert tl.filters == {"since": "2026-06-13T10:30:00Z", "until": "2026-06-13T11:30:00+00:00"}
    assert build_timeline(view, cited_only=True).entries == ()


def test_detection_and_observation_annotations():
    ev = Evidence()
    a = ev.alert(at("11:42:55"), "srv-web-01", "Heuristic.X", kind="ids_alert")
    rep = DetectionEngine().run(ev.view())
    [entry] = build_timeline(ev.view(), report=rep).entries
    assert entry.evidence_ids == (a,) and entry.observation_rules == ("ALERT-001",)


# --- scenarios -------------------------------------------------------------------

def test_a_ransomware_renames_condense_into_one_cited_burst(ro):
    tl = scenario_timeline(ro, "INC-C")
    [burst] = [e for e in tl.entries if e.event_type == "file_rename"]
    assert (burst.entry, burst.count, burst.host) == ("burst", 34, "srv-db-01")
    assert {c.rule_id for c in burst.cited_by} == {"RANSOM-001", "CORR-001"}
    assert burst.process.untrusted == "bhz.exe"
    assert len(tl.entries) < tl.evidence_total / 2          # noise condensed too


def test_a_cited_only_timeline_covers_the_attack_in_order(ro):
    tl = scenario_timeline(ro, "INC-C", cited_only=True)
    starts = [e.start for e in tl.entries]
    assert starts == sorted(starts)
    assert tl.entries[0].event_type == "7045"                       # service install first
    assert all(e.cited_by or e.detection_rules for e in tl.entries)
    assert tl.evidence_shown == len({i for e in tl.entries for i in e.evidence_ids})


def test_b_has_no_cited_entries_only_observations(ro):
    tl = scenario_timeline(ro, "INC-B")
    assert not any(e.cited_by or e.detection_rules for e in tl.entries)
    assert {r for e in tl.entries for r in e.observation_rules} == {
        "ALERT-001", "IOC-002", "NET-001"}


def test_timeline_is_deterministic(ro):
    assert scenario_timeline(ro, "INC-A") == scenario_timeline(ro, "INC-A")
