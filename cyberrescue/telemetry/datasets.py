"""Committed synthetic datasets: render, write and verify byte-for-byte.

Layout (``datasets/cyberrescue/synthetic/``)::

    manifest.json                 generator version, seeds, sha256, counts
    telemetry/scenario-a.jsonl    operational input  -> adapter -> Evidence
    ground_truth/scenario-a.json  EVALUATION ONLY    -> never ingested

Telemetry and ground truth live in separate trees with neutral file names, so
neither a path nor a ``source`` hints at a label. The manifest carries totals
only (no malicious/benign split). Rendering is deterministic: sorted keys,
ASCII-only JSON, ``\\n`` line endings (``.gitattributes`` pins ``eol=lf``), so
``check`` can regenerate every file in memory and compare bytes.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from cyberrescue.telemetry.catalog import (  # noqa: F401  (re-exported)
    DEFAULT_ROOT,
    ground_truth_relpath,
    telemetry_path,
    telemetry_relpath,
)
from cyberrescue.telemetry.ground_truth import GROUND_TRUTH_SCHEMA
from cyberrescue.telemetry.scenarios import GENERATOR_VERSION, SCENARIOS, build
from cyberrescue.telemetry.schema import TELEMETRY_SCHEMA

MANIFEST = "manifest.json"


def _json_bytes(obj: Any, *, indent: int | None = None) -> bytes:
    return (json.dumps(obj, sort_keys=True, ensure_ascii=True, indent=indent) + "\n").encode()


def render() -> dict[str, bytes]:
    """Every dataset file, keyed by path relative to the dataset root."""
    files: dict[str, bytes] = {}
    entries = []
    for spec in SCENARIOS.values():
        events, gt = build(spec.key)
        tel = b"".join(_json_bytes(e.model_dump(mode="json", exclude_none=True))
                       for e in events)
        truth = _json_bytes(gt.model_dump(mode="json"), indent=2)
        files[telemetry_relpath(spec.info)] = tel
        files[ground_truth_relpath(spec.info)] = truth
        entries.append({
            "scenario": spec.key,
            "dataset": spec.dataset,
            "title": spec.title,
            "incident_alias": spec.incident_alias,
            "incident_id": spec.incident_id,
            "seed": spec.seed,
            "window": {"start": spec.start.isoformat(), "end": spec.end.isoformat()},
            "telemetry": {
                "path": telemetry_relpath(spec.info),
                "sha256": hashlib.sha256(tel).hexdigest(),
                "events": len(events),
                "by_category": dict(sorted(Counter(e.category.value for e in events).items())),
                "by_sensor": dict(sorted(Counter(e.sensor for e in events).items())),
            },
            "ground_truth": {
                "path": ground_truth_relpath(spec.info),
                "sha256": hashlib.sha256(truth).hexdigest(),
                "evaluation_only": True,
            },
        })
    files[MANIFEST] = _json_bytes({
        "generator": GENERATOR_VERSION,
        "telemetry_schema": TELEMETRY_SCHEMA,
        "ground_truth_schema": GROUND_TRUTH_SCHEMA,
        "provenance": "synthetic",
        "notice": "SYNTHETIC data for testing and evaluation; not real telemetry. "
                  "ground_truth/ is evaluation-only and must never be ingested as evidence.",
        "scenarios": entries,
    }, indent=2)
    return files


def write(root: str | Path | None = None) -> list[Path]:
    root = Path(root or DEFAULT_ROOT)
    written = []
    for rel, data in render().items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        written.append(p)
    return written


def check(root: str | Path | None = None) -> list[str]:
    """Differences between the files on disk and a fresh deterministic render."""
    root = Path(root or DEFAULT_ROOT)
    problems = []
    for rel, data in render().items():
        p = root / rel
        if not p.is_file():
            problems.append(f"{rel}: missing")
        elif p.read_bytes() != data:
            problems.append(f"{rel}: differs from a fresh render "
                            f"(sha256 {hashlib.sha256(p.read_bytes()).hexdigest()[:12]} != "
                            f"{hashlib.sha256(data).hexdigest()[:12]})")
    return problems
