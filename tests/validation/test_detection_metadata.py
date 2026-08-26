"""Fast, focused metadata checks for detection YAML files.

Set DETECTION_PATHS to a newline-separated list of repository-relative paths to
validate only a subset (the CI workflow uses this for files changed in a PR).
Without it, every detection is checked.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest
import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DETECTIONS_DIRECTORY = REPOSITORY_ROOT / "detections"
THREAT_OBJECT_TYPES = frozenset({"TTP", "Anomaly"})


@dataclass(frozen=True)
class Detection:
    """The small metadata subset required by these validations."""

    path: Path
    title: str
    type: str | None
    fields: frozenset[str]


def _selected_paths() -> tuple[Path, ...]:
    """Return requested files, or all detection YAML files in stable order."""
    configured_paths = os.environ.get("DETECTION_PATHS")
    if configured_paths is None:
        return tuple(sorted(DETECTIONS_DIRECTORY.rglob("*.y*ml")))

    paths = []
    for value in configured_paths.splitlines():
        if not value.strip():
            continue
        path = (REPOSITORY_ROOT / value).resolve()
        if path.is_file() and DETECTIONS_DIRECTORY.resolve() in path.parents:
            paths.append(path)
    return tuple(sorted(set(paths)))


@lru_cache(maxsize=None)
def _load_detection(path: Path, mtime_ns: int, size: int) -> Detection:
    """Parse each unchanged YAML file once per pytest process.

    File metadata is part of the cache key so an in-process edit cannot return
    stale metadata. Both tests reuse the same cached Detection objects.
    """
    try:
        with path.open(encoding="utf-8") as stream:
            document: Any = yaml.safe_load(stream)
    except yaml.YAMLError as error:
        relative_path = path.relative_to(REPOSITORY_ROOT)
        pytest.fail(f"Invalid YAML in {relative_path}: {error}", pytrace=False)

    if not isinstance(document, dict):
        pytest.fail(
            f"{path.relative_to(REPOSITORY_ROOT)} must contain a YAML mapping.",
            pytrace=False,
        )

    return Detection(
        path=path,
        title=str(document.get("name") or document.get("title") or "<untitled>"),
        type=document.get("type"),
        fields=frozenset(document),
    )


@pytest.fixture(scope="session")
def detections() -> tuple[Detection, ...]:
    """Load the selected corpus once; pytest reuses it across all checks."""
    return tuple(
        _load_detection(path, path.stat().st_mtime_ns, path.stat().st_size)
        for path in _selected_paths()
    )


def _failure_message(field: str, missing: list[Detection], requirement: str) -> str:
    details = "\n".join(
        f"  - {detection.path.relative_to(REPOSITORY_ROOT)} "
        f"[{detection.type or 'missing type'}] {detection.title}"
        for detection in missing
    )
    return (
        f"{len(missing)} detection(s) missing top-level `{field}`.\n"
        f"Required for: {requirement}.\n\n"
        f"{details}\n\n"
        f"Fix: add a top-level `{field}:` field to each listed detection."
    )


def test_detections_include_references(detections: tuple[Detection, ...]) -> None:
    """Every detection must declare references (an empty list is explicit and valid)."""
    missing = [detection for detection in detections if "references" not in detection.fields]
    assert not missing, _failure_message("references", missing, "all detection types")


def test_ttp_and_anomaly_detections_include_threat_objects(
    detections: tuple[Detection, ...],
) -> None:
    """TTP and Anomaly detections require threat_objects; Hunting is exempt."""
    missing = [
        detection
        for detection in detections
        if detection.type in THREAT_OBJECT_TYPES and "threat_objects" not in detection.fields
    ]
    assert not missing, _failure_message(
        "threat_objects", missing, "TTP and Anomaly detections (Hunting is exempt)"
    )
