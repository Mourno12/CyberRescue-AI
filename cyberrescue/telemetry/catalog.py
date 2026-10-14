"""Scenario catalogue and dataset layout — label-free.

The operational path (importer, CLI ``ingest``) needs to know which incident a
scenario belongs to and where its telemetry file is — and nothing else. This
module holds exactly that, so the importer never imports the generators
(``scenarios.py``) or the evaluation-only ground truth (``ground_truth.py``).

The scenario -> incident binding is configuration chosen by the operator, never
read from telemetry content.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cyberrescue.core.ids import LEGACY_ALIASES

REPO = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO / "datasets" / "cyberrescue" / "synthetic"


@dataclass(frozen=True)
class ScenarioInfo:
    key: str
    dataset: str
    incident_alias: str
    title: str

    @property
    def incident_id(self) -> str:
        return LEGACY_ALIASES[self.incident_alias]


CATALOG: dict[str, ScenarioInfo] = {s.key: s for s in (
    ScenarioInfo("A", "scenario-a", "INC-C", "Ransomware on the customer database"),
    ScenarioInfo("B", "scenario-b", "INC-B", "Suspected beaconing from the web frontend"),
    ScenarioInfo("C", "scenario-c", "INC-A", "Commodity trojan on an engineering workstation"),
)}


def scenario_info(key: str) -> ScenarioInfo:
    k = (key or "").strip().upper().removeprefix("SCENARIO-").removeprefix("SCENARIO_")
    if k not in CATALOG:
        raise KeyError(f"unknown scenario {key!r}; choose from {', '.join(CATALOG)}")
    return CATALOG[k]


def telemetry_relpath(info: ScenarioInfo) -> str:
    return f"telemetry/{info.dataset}.jsonl"


def ground_truth_relpath(info: ScenarioInfo) -> str:
    return f"ground_truth/{info.dataset}.json"


def telemetry_path(key: str, root: str | Path | None = None) -> Path:
    return Path(root or DEFAULT_ROOT) / telemetry_relpath(scenario_info(key))
