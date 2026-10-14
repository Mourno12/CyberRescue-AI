"""CyberRescue Phase 2C — ransomware encryption activity (RANSOM-001)."""

from cyberrescue.detection.model import Detection, Observation
from cyberrescue.detection.rules.ransomware import MassEncryption
from tests._detection_factory import Evidence, at

DIRS = ["D:\\pgdata\\base\\16384", "D:\\exports\\crm", "E:\\backup", "D:\\exports\\finance"]


def renames(ev, n=34, *, ext="blackhaze", step=4, proc="bhz.exe", mixed=False):
    ids = []
    for k in range(n):
        path = f"{DIRS[k % len(DIRS)]}\\{1000 + k}"
        new = f"{path}.{(str(k % 3) if mixed else ext)}"
        ids.append(ev.file(at("14:05:00", k * step), "srv-db-01", "file_rename", path,
                           target=new, process=proc, user="svc_sqlbackup"))
    return ids


def notes(ev, n=6, start="14:07:16", proc="bhz.exe"):
    return [ev.file(at(start, k), "srv-db-01", "file_create",
                    f"{DIRS[k % len(DIRS)]}\\sub{k}\\RECOVER_YOUR_FILES.txt", process=proc)
            for k in range(n)]


def results(ev):
    return MassEncryption().evaluate(ev.view())


def cond(r, cid):
    return next(c for c in r.conditions if c.id == cid)


def test_full_ransomware_pattern_is_high_confidence():
    ev = Evidence()
    v = ev.proc(at("14:01:35"), "srv-db-01", "C:\\Windows\\System32\\vssadmin.exe",
                parent="bhz.exe", cmd="vssadmin.exe delete shadows /all /quiet")
    r = renames(ev)
    n = notes(ev)
    a = ev.alert(at("14:07:22"), "srv-db-01", "Ransomware.BlackHaze", process="bhz.exe")
    [d] = results(ev)
    assert isinstance(d, Detection) and d.confidence == "high" and d.severity == "critical"
    assert set(d.supporting_evidence_ids) == {v, *r, *n} and d.context_evidence_ids == (a,)
    assert cond(d, "mass_rename_common_extension").detail == {
        "renames": 34, "extension": "blackhaze", "share_percent": 100, "seconds": 132}
    assert cond(d, "ransom_note_drop").detail["file_name"] == "RECOVER_YOUR_FILES.txt"
    assert d.entities["ransom_note"] == "RECOVER_YOUR_FILES.txt"


def test_nineteen_renames_are_below_threshold():
    ev = Evidence()
    renames(ev, n=19)
    notes(ev)
    assert results(ev) == []


def test_renames_spread_beyond_the_window_do_not_fire():
    ev = Evidence()
    renames(ev, n=25, step=20)                       # 25 renames over 8 minutes
    notes(ev)
    assert results(ev) == []


def test_mixed_extensions_do_not_fire():
    ev = Evidence()                                  # logrotate-style .0/.1/.2
    renames(ev, n=40, mixed=True, proc="logrotate.exe")
    assert results(ev) == []


def test_uncorroborated_mass_rename_is_only_an_observation():
    ev = Evidence()                                  # e.g. a backup tool producing *.bak
    renames(ev, n=30, ext="bak", proc="backup.exe")
    [o] = results(ev)
    assert isinstance(o, Observation) and o.kind == "partial_match"


def test_any_single_corroboration_suffices():
    ev = Evidence()
    renames(ev)
    notes(ev)
    [d] = results(ev)
    assert isinstance(d, Detection) and d.confidence == "medium"
    ev = Evidence()
    renames(ev)
    ev.alert(at("14:07:22"), "srv-db-01", "Ransomware.X", process="BHZ.EXE")
    [d] = results(ev)
    assert isinstance(d, Detection) and cond(d, "vendor_alert").matched


def test_notes_need_three_directories_and_the_same_process():
    ev = Evidence()
    renames(ev)
    notes(ev, n=2)                                    # only 2 directories
    notes(ev, n=6, proc="explorer.exe")              # other process
    [o] = results(ev)
    assert isinstance(o, Observation)


def test_separate_hosts_and_processes_are_not_combined():
    ev = Evidence()
    renames(ev, n=15)
    renames(ev, n=15, proc="other.exe")
    assert results(ev) == []
