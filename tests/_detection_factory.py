"""Build EvidenceRecords for detection unit tests (no database needed).

Field shapes mirror what the Phase 2B telemetry adapter produces, so a rule
tested here behaves the same on ingested scenario evidence.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from cyberrescue.core.models import Asset, EvidenceRecord
from cyberrescue.detection.context import AssetContext, EvidenceView, ThreatIntel
from shared.mock_data import load_assets

INC = "INC-T-0001"
DAY = datetime(2026, 6, 13, tzinfo=timezone.utc)
IPS = {"srv-db-01": "10.20.1.15", "srv-app-01": "10.20.2.21", "srv-dc-01": "10.10.0.5",
       "ws-eng-014": "10.30.5.114", "ws-fin-007": "10.30.6.7", "srv-web-01": "172.16.10.10",
       "srv-backup-01": "10.20.4.30"}


def at(hhmmss: str, plus: int = 0) -> datetime:
    h, m, s = (int(x) for x in hhmmss.split(":"))
    return DAY.replace(hour=h, minute=m, second=s) + timedelta(seconds=plus)


def assets() -> AssetContext:
    return AssetContext(Asset(**{k: v for k, v in a.items() if k in Asset.model_fields})
                        for a in load_assets())


class Evidence:
    """Accumulates records; ``view()`` builds an EvidenceView."""

    def __init__(self, incident: str = INC) -> None:
        self.incident = incident
        self.records: list[EvidenceRecord] = []

    def add(self, when: datetime, kind: str, event_type: str, *, host: str | None = None,
            user: str | None = None, data: dict[str, Any] | None = None,
            raw: str = "") -> str:
        n = len(self.records) + 1
        eid = f"EV-{n:04d}"
        self.records.append(EvidenceRecord(
            id=eid, incident_id=self.incident, source="test.unit", source_ref=str(n),
            kind=kind, event_type=event_type, observed_at=when.isoformat(),
            ingested_at=DAY.isoformat(), host=host,
            asset_id=host if host in IPS else None, user=user, raw=raw or f"event {n}",
            data=data or {}, metadata={}, provenance="synthetic",
            content_sha256=f"{n:064x}", record_sha256="0" * 64, ingested_by="t",
            event_uid=f"u{n}"))
        return eid

    def view(self, intel: ThreatIntel | None = None) -> EvidenceView:
        return EvidenceView(self.incident, self.records,
                            intel=intel or ThreatIntel.from_mock(), assets=assets())

    # --- sensor shapes (same keys as cyberrescue/telemetry/scenarios.py) -------
    def proc(self, when, host, image, *, user="u1", parent="explorer.exe", cmd="",
             sha="0a" * 32, **kw) -> str:
        name = image.replace("/", "\\").rsplit("\\", 1)[-1]
        return self.add(when, "process", "process_start", host=host, user=user, data={
            "process.executable": image, "process.name": name, "process.parent.name": parent,
            "process.command_line": cmd or name, "process.hash.sha256": sha,
            "user.name": user}, **kw)

    def file(self, when, host, action, path, *, process="x.exe", user="u1",
             target=None) -> str:
        data = {"file.path": target or path, "process.name": process, "user.name": user}
        if target:
            data["file.original_path"] = path
        return self.add(when, "file", action, host=host, user=user, data=data)

    def auth(self, when, target, code, user, src_host=None, *, src_ip=None, logon="3",
             package="NTLM") -> str:
        data = {"event.code": str(code),
                "event.outcome": "failure" if code == 4625 else "success",
                "host.name": target, "user.name": user,
                "source.ip": src_ip or IPS.get(src_host or "", "10.99.0.1"),
                "winlog.logon.type": logon,
                "winlog.event_data.AuthenticationPackageName": package}
        if src_host:
            data["source.domain"] = src_host
        return self.add(when, "auth", str(code), host=target, user=user, data=data)

    def flow(self, when, host, dst, dport, *, out=1000, inb=1000, proto="tcp",
             src_ip=None) -> str:
        return self.add(when, "network", "flow", host=host, data={
            "source.ip": src_ip or IPS[host], "source.port": 50000, "destination.ip": dst,
            "destination.port": dport, "network.transport": proto, "source.bytes": out,
            "destination.bytes": inb})

    def connect(self, when, host, dst, dport, *, process="x.exe") -> str:
        return self.add(when, "network", "network_connect", host=host, data={
            "process.name": process, "source.ip": IPS[host], "destination.ip": dst,
            "destination.port": dport})

    def dns(self, when, host, name, answer, *, resolver="10.10.0.53") -> str:
        return self.add(when, "network", "dns_query", host=host, data={
            "source.ip": IPS[host], "destination.ip": resolver, "dns.question.name": name,
            "dns.answers": [answer] if answer else []})

    def proxy(self, when, host, url, *, verdict="allowed", status=200, user="u1") -> str:
        return self.add(when, "network", "http_request", host=host, user=user, data={
            "source.ip": IPS[host], "url.original": url, "event.action": verdict,
            "http.response.status_code": status})

    def http_in(self, when, host, client, *, status=200, agent="Mozilla/5.0") -> str:
        return self.add(when, "log", "http_access", host=host, data={
            "source.ip": client, "http.request.method": "GET", "url.path": "/",
            "http.response.status_code": status, "user_agent.original": agent})

    def alert(self, when, host, rule, *, process=None, sha=None, kind="edr_detection",
              src=None, dst=None) -> str:
        data = {"rule.name": rule, "event.severity_label": "high"}
        if process:
            data["process.name"] = process
        if sha:
            data["process.hash.sha256"] = sha
        if src:
            data["source.ip"] = src
        if dst:
            data["destination.ip"] = dst
        return self.add(when, "alert", kind, host=host, data=data)

    def service(self, when, host, name, image, *, user="SYSTEM") -> str:
        return self.add(when, "log", "7045", host=host, user=user, data={
            "event.code": "7045", "service.name": name, "service.executable": image,
            "user.name": user})

    def runkey(self, when, host, key, value, *, user="u1", process="x.exe") -> str:
        return self.add(when, "other", "registry_set", host=host, user=user, data={
            "registry.path": key, "registry.data.strings": [value], "process.name": process,
            "user.name": user})

    def mail(self, when, rcpt_user, attachment=None) -> str:
        return self.add(when, "log", "message_delivered", host="srv-mail-01", user=rcpt_user,
                        data={"email.to.address": f"{rcpt_user}@acme.example",
                              "email.attachments.file.name": [attachment] if attachment
                              else [], "event.action": "delivered"})

    def account(self, when, host, code, account, *, group=None, actor="admin1") -> str:
        data = {"event.code": str(code), "user.target.name": account, "user.name": actor}
        if group:
            data["group.name"] = group
        return self.add(when, "log", str(code), host=host, user=actor, data=data)


def scenario_core(path, keys=("A", "B", "C"), **svc_kwargs):
    """A file-backed Core with the committed scenarios ingested into their
    catalogue incidents. Returns (svc, collector)."""
    from cyberrescue.core.service import CoreService
    from cyberrescue.telemetry.catalog import CATALOG
    from cyberrescue.telemetry.importer import import_scenario
    from shared.mock_data import load_alert
    svc = CoreService.open(path, **svc_kwargs)
    svc.seed_assets_from_mock()
    collector = svc.register_actor("system", "collector", "synthetic", "collector:synthetic")
    for key in keys:
        alert = load_alert(CATALOG[key].incident_alias)
        svc.open_incident(alert["incident_id"], title=alert["title"],
                          primary_asset_id=alert["asset_id"])
        import_scenario(svc, key, collector_id=collector.id)
    return svc, collector


def investigated_core(path, keys=("A", "B", "C")):
    """A Core with scenarios ingested and detections persisted for each incident
    (via the explicit publisher), closed again so it can be opened read-only."""
    from cyberrescue.detection.engine import detect
    from cyberrescue.detection.publisher import persist
    from cyberrescue.telemetry.catalog import CATALOG
    svc, _ = scenario_core(path, keys=keys)
    detector = svc.register_actor("system", "detector", "engine", "detector:test")
    for key in keys:
        ref = CATALOG[key].incident_alias
        persist(svc, ref, detect(svc, ref), detector_id=detector.id)
    svc.conn.close()
    return path
