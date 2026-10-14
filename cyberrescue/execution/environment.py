"""The simulated environment - an in-memory model, never the real one.

``SimEnvironment.from_view`` builds a controlled world from one incident's
STRUCTURED evidence (``EvidenceView``: no raw lines) and the asset inventory:

* hosts       - inventory assets;
* processes   - (host, process name) seen starting, with the evidence ids;
* files       - (host, path) seen as an executable, written file, or the
                target of a service / autostart entry;
* indicators  - external destination addresses seen in network evidence;
* accounts    - account names seen in the evidence.

Every simulated action changes only this object (copy-on-write: ``with_``
returns a new environment, so a run never mutates shared state). Nothing here
can reach a process, file, socket, host or directory service: there is no I/O
at all.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field, replace

from cyberrescue.core.audit import canonical_json
from cyberrescue.detection.context import EvidenceView
from cyberrescue.detection.matchers import basename, normalize_ip

Key = tuple[str, str]


def _freeze(d: dict) -> dict:
    return {k: tuple(v) for k, v in sorted(d.items())}


@dataclass(frozen=True)
class SimEnvironment:
    hosts: frozenset[str]
    processes: dict[Key, tuple[str, ...]] = field(default_factory=dict)
    files: dict[Key, tuple[str, ...]] = field(default_factory=dict)
    indicators: dict[str, tuple[str, ...]] = field(default_factory=dict)
    accounts: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # simulated changes
    isolated: frozenset[str] = frozenset()
    imaged: frozenset[str] = frozenset()
    killed: frozenset[Key] = frozenset()
    quarantined: frozenset[Key] = frozenset()
    blocked: frozenset[str] = frozenset()
    disabled: frozenset[str] = frozenset()
    notifications: tuple[tuple[str, ...], ...] = ()

    @classmethod
    def from_view(cls, view: EvidenceView, inventory: list[str]) -> SimEnvironment:
        procs: dict[Key, list[str]] = defaultdict(list)
        files: dict[Key, list[str]] = defaultdict(list)
        ips: dict[str, list[str]] = defaultdict(list)
        accounts: dict[str, list[str]] = defaultdict(list)
        for e in view.events:
            if e.host and e.event_type == "process_start":
                name = e.s("process.name") or basename(e.s("process.executable") or "")
                if name:
                    procs[(e.host, name.lower())].append(e.id)
                if e.s("process.executable"):
                    files[(e.host, e.s("process.executable").lower())].append(e.id)
            if e.host and e.kind == "file" and e.s("file.path"):
                files[(e.host, e.s("file.path").lower())].append(e.id)
            if e.host and e.s("service.executable"):
                files[(e.host, e.s("service.executable").lower())].append(e.id)
            if e.host and e.event_type == "registry_set":
                for v in e.strings("registry.data.strings"):
                    files[(e.host, v.lower())].append(e.id)
            ip = normalize_ip(e.s("destination.ip"))
            if e.kind == "network" and ip:
                ips[ip].append(e.id)
            user = e.user or e.s("user.name")
            if user:
                accounts[user.lower()].append(e.id)
        return cls(hosts=frozenset(inventory), processes=_freeze(procs), files=_freeze(files),
                   indicators=_freeze(ips), accounts=_freeze(accounts))

    def with_(self, **changes) -> SimEnvironment:
        return replace(self, **changes)

    # --- observations used by the success criteria -----------------------------------
    def process_running(self, host: str, name: str) -> bool:
        k = (host, name.lower())
        return k in self.processes and k not in self.killed

    def file_present(self, host: str, path: str) -> bool:
        k = (host, path.lower())
        return k in self.files and k not in self.quarantined

    def fingerprint(self) -> str:
        """Content hash of the initial world (what the simulation started from)."""
        body = {"hosts": sorted(self.hosts),
                "processes": [[*k, list(v)] for k, v in sorted(self.processes.items())],
                "files": [[*k, list(v)] for k, v in sorted(self.files.items())],
                "indicators": {k: list(v) for k, v in sorted(self.indicators.items())},
                "accounts": {k: list(v) for k, v in sorted(self.accounts.items())}}
        return hashlib.sha256(canonical_json(body).encode()).hexdigest()
