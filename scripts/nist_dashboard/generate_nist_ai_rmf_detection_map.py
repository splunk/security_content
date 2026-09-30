#!/usr/bin/env python3
"""Generate the NIST AI RMF detection-to-subcategory lookup from ESCU detections."""

from __future__ import annotations

import argparse
import csv
import io
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG = Path("scripts/nist_dashboard/nist_ai_rmf_data_sources.yml")
DEFAULT_DETECTIONS_DIR = Path("detections")
DEFAULT_RMF_LOOKUP = Path("lookups/csv/nist_ai_rmf_subcategories.csv")
DEFAULT_OUTPUT = Path("lookups/csv/detection_subcategory_map.csv")
DEFAULT_METADATA = Path("lookups/csv/detection_subcategory_map.yml")

FIELDNAMES = [
    "ai_system",
    "data_sources",
    "detection_name",
    "detection_status",
    "detection_type",
    "analytic_stories",
    "rmf_function",
    "subcategory_ids",
    "mapping_confidence",
    "mapping_source",
    "mapping_reason",
]

FUNCTION_ORDER = {
    "GOVERN": 1,
    "MAP": 2,
    "MEASURE": 3,
    "MANAGE": 4,
}


@dataclass(frozen=True)
class DataSourceSelector:
    name: str
    ai_system: str
    analytic_stories: tuple[str, ...] = ()


@dataclass(frozen=True)
class MappingRule:
    pattern: re.Pattern[str]
    subcategory_ids: tuple[str, ...]
    reason: str
    confidence: str = "high"


RULES: tuple[MappingRule, ...] = (
    MappingRule(
        re.compile(r"\b(non[- ]?compliant|unauthorized|unmanaged).*(device|ai|llm)|\b(local llm framework execution|model file creation)\b", re.I),
        ("Govern 1.6",),
        "AI system or access inventory signal",
    ),
    MappingRule(
        re.compile(r"\b(local llm|framework dns|model file creation|network connectivity|api endpoint scan|reconnaissance|cross[- ]?region)\b", re.I),
        ("Map 4.1",),
        "AI component, model, or service discovery signal",
    ),
    MappingRule(
        re.compile(r"\bwindows local llm framework execution\b", re.I),
        ("Map 4.2",),
        "AI system operating context signal",
    ),
    MappingRule(
        re.compile(r"\b(unusually large|excessive.*tokens?|excessive.*api requests?|memory exhaustion|application usage pattern|session origin|behavior anomaly|failed authentication)\b", re.I),
        ("Measure 2.4",),
        "Production behavior monitoring signal",
    ),
    MappingRule(
        re.compile(r"\b(prompt injection|jailbreak|ignore previous|system prompt override|hostile prompt|sentiment)\b", re.I),
        ("Measure 2.6",),
        "Prompt-behavior and harmful-content measurement signal",
    ),
    MappingRule(
        re.compile(r"\b(prompt injection|jailbreak|agentic|impersonation|rce|remote code|model loading|suspicious extension write|github suspicious|postgres suspicious|tool invocation)\b", re.I),
        ("Measure 2.7",),
        "AI security and resilience evaluation signal",
    ),
    MappingRule(
        re.compile(r"\b(sensitive data|credential|secret|api key|information extraction|system file|model exfiltration|data leakage|/etc/passwd|\.aws/credentials)\b", re.I),
        ("Measure 2.10",),
        "Sensitive information or data-protection signal",
    ),
    MappingRule(
        re.compile(r"\b(failed authentication|service crash|availability|memory exhaustion|excessive.*api requests?|security alerts?|critical alerts?|high risk filesystem|exec tool|delete guardrail|delete knowledge base|delete model invocation logging)\b", re.I),
        ("Manage 4.1",),
        "Post-deployment monitoring and response signal",
    ),
    MappingRule(
        re.compile(r"\b(high risk filesystem|exec tool|rce|remote code|incident|delete guardrail|delete knowledge base|delete model invocation logging)\b", re.I),
        ("Manage 4.3",),
        "Incident tracking or response signal",
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate lookups/csv/detection_subcategory_map.csv from ESCU detection "
            "metadata and a configured list of AI-related data sources."
        )
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help=f"Data source config. Default: {DEFAULT_CONFIG}")
    parser.add_argument(
        "--data-source",
        action="append",
        default=[],
        help="Additional data source name to include. The AI system defaults to the data source name.",
    )
    parser.add_argument("--detections-dir", type=Path, default=DEFAULT_DETECTIONS_DIR, help=f"Detections directory. Default: {DEFAULT_DETECTIONS_DIR}")
    parser.add_argument("--rmf-lookup", type=Path, default=DEFAULT_RMF_LOOKUP, help=f"NIST AI RMF subcategory lookup. Default: {DEFAULT_RMF_LOOKUP}")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help=f"CSV output path. Default: {DEFAULT_OUTPUT}")
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA, help=f"Lookup metadata YAML to bump when --output changes. Default: {DEFAULT_METADATA}")
    parser.add_argument("--modified-date", default=None, help="Metadata modification date in YYYY-MM-DD format. Default: today.")
    parser.add_argument("--no-metadata-update", action="store_true", help="Do not bump lookup metadata when --output changes.")
    parser.add_argument("--include-deprecated", action="store_true", help="Include detections under detections/deprecated and detections with deprecated status.")
    parser.add_argument("--dry-run", action="store_true", help="Write generated CSV to stdout instead of --output.")
    return parser.parse_args()


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def norm(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).casefold()


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return loaded


def load_selectors(config_path: Path, cli_data_sources: list[str]) -> list[DataSourceSelector]:
    selectors: list[DataSourceSelector] = []

    if config_path.exists():
        config = load_yaml(config_path)
        configured_sources = config.get("data_sources", [])
        if not isinstance(configured_sources, list):
            raise ValueError(f"{config_path}: data_sources must be a list")
        for item in configured_sources:
            if isinstance(item, str):
                selectors.append(DataSourceSelector(name=item, ai_system=item))
                continue
            if not isinstance(item, dict):
                raise ValueError(f"{config_path}: each data_sources entry must be a string or mapping")
            name = str(item.get("name", "")).strip()
            if not name:
                raise ValueError(f"{config_path}: data source entry is missing name")
            ai_system = str(item.get("ai_system") or name).strip()
            stories = tuple(as_list(item.get("analytic_stories") or item.get("analytic_story")))
            selectors.append(DataSourceSelector(name=name, ai_system=ai_system, analytic_stories=stories))

    for data_source in cli_data_sources:
        data_source = data_source.strip()
        if data_source:
            selectors.append(DataSourceSelector(name=data_source, ai_system=data_source))

    if not selectors:
        raise ValueError("No data sources configured. Add --data-source or provide a config file.")

    deduped: dict[tuple[str, str, tuple[str, ...]], DataSourceSelector] = {}
    for selector in selectors:
        deduped[(norm(selector.name), norm(selector.ai_system), tuple(norm(s) for s in selector.analytic_stories))] = selector
    return list(deduped.values())


def load_valid_subcategories(path: Path) -> dict[str, str]:
    valid: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        required = {"function", "subcategory_id"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"{path} is missing required columns: {', '.join(sorted(missing))}")
        for row in reader:
            subcategory_id = (row.get("subcategory_id") or "").strip()
            function = (row.get("function") or "").strip().upper()
            if subcategory_id:
                valid[subcategory_id] = function
    if not valid:
        raise ValueError(f"{path} did not contain any subcategory IDs")
    return valid


def detection_files(root: Path, include_deprecated: bool) -> list[Path]:
    files = sorted(root.rglob("*.yml"))
    if include_deprecated:
        return files
    return [path for path in files if "deprecated" not in {part.casefold() for part in path.parts}]


def selector_matches(selector: DataSourceSelector, detection_data_sources: set[str], detection_stories: set[str]) -> bool:
    if norm(selector.name) not in detection_data_sources:
        return False
    if selector.analytic_stories and not ({norm(story) for story in selector.analytic_stories} & detection_stories):
        return False
    return True


def confidence_rank(confidence: str) -> int:
    return {"review": 1, "medium": 2, "high": 3}.get(confidence, 1)


def derive_mapping(detection: dict[str, Any], valid_subcategories: dict[str, str]) -> tuple[list[str], str, str, str]:
    context_fields = [
        detection.get("name"),
        detection.get("type"),
        detection.get("status"),
        " ".join(as_list(detection.get("data_source"))),
        " ".join(as_list(detection.get("analytic_story"))),
    ]
    context = " ".join(str(field) for field in context_fields if field)

    subcategory_ids: list[str] = []
    reasons: list[str] = []
    confidence = "review"
    for rule in RULES:
        if rule.pattern.search(context):
            for subcategory_id in rule.subcategory_ids:
                if subcategory_id not in subcategory_ids:
                    subcategory_ids.append(subcategory_id)
            if rule.reason not in reasons:
                reasons.append(rule.reason)
            if confidence_rank(rule.confidence) > confidence_rank(confidence):
                confidence = rule.confidence

    if not subcategory_ids:
        subcategory_ids = ["Measure 2.4"]
        confidence = "review"
        reasons = ["AI data source matched, but no specific RMF rule matched"]

    invalid = [subcategory_id for subcategory_id in subcategory_ids if subcategory_id not in valid_subcategories]
    if invalid:
        raise ValueError(f"{detection.get('name', '<unnamed detection>')} mapped to unknown RMF subcategories: {', '.join(invalid)}")

    functions = sorted(
        {valid_subcategories[subcategory_id] for subcategory_id in subcategory_ids},
        key=lambda item: FUNCTION_ORDER.get(item, 99),
    )
    mapping_source = "generated_rule" if confidence != "review" else "generated_review"
    return subcategory_ids, "|".join(functions), confidence, "; ".join(reasons)


def rows_from_detections(
    detections_dir: Path,
    selectors: list[DataSourceSelector],
    valid_subcategories: dict[str, str],
    include_deprecated: bool,
) -> list[dict[str, str]]:
    rows_by_key: dict[tuple[str, str], dict[str, str]] = {}
    data_sources_by_key: dict[tuple[str, str], set[str]] = defaultdict(set)

    for path in detection_files(detections_dir, include_deprecated):
        detection = load_yaml(path)
        name = str(detection.get("name", "")).strip()
        if not name:
            continue

        status = str(detection.get("status", "")).strip()
        if not include_deprecated and status.casefold() == "deprecated":
            continue

        data_source_values = as_list(detection.get("data_source"))
        story_values = as_list(detection.get("analytic_story"))
        detection_data_sources = {norm(value) for value in data_source_values}
        detection_stories = {norm(value) for value in story_values}

        matched_by_ai_system: dict[str, set[str]] = defaultdict(set)
        for selector in selectors:
            if selector_matches(selector, detection_data_sources, detection_stories):
                matched_by_ai_system[selector.ai_system].add(selector.name)

        if not matched_by_ai_system:
            continue

        subcategory_ids, rmf_function, confidence, reason = derive_mapping(detection, valid_subcategories)
        for ai_system, matched_sources in matched_by_ai_system.items():
            key = (ai_system, name)
            data_sources_by_key[key].update(matched_sources)
            rows_by_key[key] = {
                "ai_system": ai_system,
                "data_sources": "",
                "detection_name": name,
                "detection_status": status,
                "detection_type": str(detection.get("type", "")).strip(),
                "analytic_stories": "|".join(story_values),
                "rmf_function": rmf_function,
                "subcategory_ids": "|".join(subcategory_ids),
                "mapping_confidence": confidence,
                "mapping_source": "generated_rule" if confidence != "review" else "generated_review",
                "mapping_reason": reason,
            }

    rows = list(rows_by_key.values())
    for row in rows:
        key = (row["ai_system"], row["detection_name"])
        row["data_sources"] = "|".join(sorted(data_sources_by_key[key], key=str.casefold))
    rows.sort(key=lambda row: (row["ai_system"].casefold(), row["data_sources"].casefold(), row["detection_name"].casefold()))
    return rows


def render_csv(rows: list[dict[str, str]]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=FIELDNAMES, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def write_csv_if_changed(content: str, output: Path | None) -> bool:
    if output is None:
        sys.stdout.write(content)
        return True

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and output.read_text(encoding="utf-8") == content:
        return False

    with output.open("w", newline="", encoding="utf-8") as handle:
        handle.write(content)
    return True


def validate_modified_date(value: str | None) -> str:
    if value is None:
        return date.today().isoformat()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("--modified-date must use YYYY-MM-DD format")
    return value


def bump_lookup_metadata(path: Path, modification_date: str) -> int:
    metadata = load_yaml(path)
    try:
        version = int(metadata.get("version", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{path}: version must be an integer") from exc

    metadata["version"] = version + 1
    metadata["modification_date"] = modification_date

    with path.open("w", encoding="utf-8", newline="\n") as handle:
        yaml.safe_dump(metadata, handle, sort_keys=False, width=120)
    return metadata["version"]


def main() -> int:
    args = parse_args()
    selectors = load_selectors(args.config, args.data_source)
    valid_subcategories = load_valid_subcategories(args.rmf_lookup)
    rows = rows_from_detections(args.detections_dir, selectors, valid_subcategories, args.include_deprecated)

    if not rows:
        raise ValueError("No detection mappings were generated. Check the configured data source names.")

    csv_content = render_csv(rows)
    output_changed = write_csv_if_changed(csv_content, None if args.dry_run else args.output)

    message = f"Generated {len(rows)} detection mappings from {len(selectors)} data source selectors."
    if not args.dry_run:
        if output_changed and not args.no_metadata_update:
            new_version = bump_lookup_metadata(args.metadata, validate_modified_date(args.modified_date))
            message += f" {args.metadata} bumped to version {new_version}."
        elif output_changed:
            message += " Output changed; metadata update skipped."
        else:
            message += " Output unchanged."

    print(message, file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
