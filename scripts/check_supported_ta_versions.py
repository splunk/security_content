#!/usr/bin/env python3
"""Check data source supported TA versions against Splunkbase."""
from __future__ import annotations

import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import requests
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic_settings import BaseSettings, CliApp, SettingsConfigDict
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.util import load_yaml_guess_indent


MONTH_NAMES = (
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)


class ExtraAllowedModel(BaseModel):
    """Base model that accepts fields outside the subset this script uses."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")


class SupportedTA(ExtraAllowedModel):
    name: str
    url: str
    version: str

    @field_validator("url", "version", mode="before")
    @classmethod
    def coerce_to_string(cls, value):
        if value is None:
            return value
        return str(value)


class DataSource(ExtraAllowedModel):
    creation_date: date
    modification_date: date
    name: str
    version: int
    supported_TA: List[SupportedTA] = Field(default_factory=list)
    raw_yaml: CommentedMap = Field(exclude=True, repr=False)
    source_path: Path = Field(exclude=True, repr=False)
    yaml_indent: Optional[int] = Field(default=None, exclude=True, repr=False)
    yaml_block_seq_indent: Optional[int] = Field(
        default=None,
        exclude=True,
        repr=False,
    )

    def get_latest_splunkbase_version(
        self,
        supported_ta: SupportedTA,
        session: Optional[requests.Session] = None,
        timeout: float = 15.0,
        cache: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, str]:
        """Return the latest Splunkbase release version and published time."""
        app_number = extract_splunkbase_app_number(supported_ta.url)

        if cache is not None and app_number in cache:
            return cache[app_number]

        client = session or requests.Session()
        url = f"https://splunkbase.splunk.com/api/v1/app/{app_number}/?include=release"
        response = client.get(
            url,
            headers={"User-Agent": "security-content-supported-ta-version-check/1.0"},
            timeout=timeout,
        )
        response.raise_for_status()

        try:
            payload = response.json()
        except ValueError as exc:
            raise ValueError(
                f"Splunkbase response for app {app_number} was not JSON"
            ) from exc

        try:
            latest_version = payload["release"]["title"]
        except (KeyError, TypeError) as exc:
            raise ValueError(
                f"Splunkbase response for app {app_number} "
                "did not contain release.title"
            ) from exc

        latest_version = str(latest_version)
        release_published_time = format_release_published_time(
            payload.get("release", {}).get("published_time")
            or "unknown release time"
        )

        if cache is not None:
            cache[app_number] = (latest_version, release_published_time)

        return latest_version, release_published_time


class CliSettings(BaseSettings):
    """Command line settings for supported TA version checks."""

    model_config = SettingsConfigDict(
        cli_parse_args=True,
        cli_kebab_case=True,
        cli_implicit_flags=True,
        cli_prog_name="check_supported_ta_versions.py",
    )

    data_sources_dir: Path = Field(
        default=Path("data_sources"),
        description="Directory containing data source YAML files.",
    )
    timeout: float = Field(
        default=15.0,
        description="Timeout, in seconds, for each Splunkbase API request.",
    )
    fail_on_update: bool = Field(
        default=False,
        description="Exit with a non-zero status when version differences are found.",
    )


def extract_splunkbase_app_number(url: str) -> str:
    parsed_url = urlparse(url)
    path_parts = [part for part in parsed_url.path.split("/") if part]

    for index, part in enumerate(path_parts):
        if (
            part == "app"
            and index + 1 < len(path_parts)
            and path_parts[index + 1].isdigit()
        ):
            return path_parts[index + 1]

    raise ValueError(f"Could not find a Splunkbase app number in URL: {url}")


def format_release_published_time(value) -> str:
    if value in (None, ""):
        return "unknown release time"

    published_time = str(value)
    if published_time == "unknown release time":
        return published_time

    try:
        parsed_time = datetime.fromisoformat(published_time.replace("Z", "+00:00"))
    except ValueError:
        return published_time

    if parsed_time.tzinfo is None:
        timezone_label = ""
    else:
        parsed_time = parsed_time.astimezone(timezone.utc)
        timezone_label = " UTC"

    month_name = MONTH_NAMES[parsed_time.month - 1]
    return (
        f"{month_name} {parsed_time.day}, {parsed_time.year} "
        f"{parsed_time.hour:02d}:{parsed_time.minute:02d}{timezone_label}"
    )


def find_data_source_files(data_sources_dir: Path) -> List[Path]:
    if not data_sources_dir.exists():
        return []

    return sorted(
        path
        for pattern in ("*.yml", "*.yaml")
        for path in data_sources_dir.glob(pattern)
        if path.is_file()
    )


def parse_data_source(path: Path) -> DataSource:
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True

    with path.open(encoding="utf-8") as file:
        data, indent, block_seq_indent = load_yaml_guess_indent(file, yaml=yaml)

    if not isinstance(data, CommentedMap):
        raise ValueError(f"{path} did not contain a YAML object")

    validation_data = dict(data)
    validation_data["raw_yaml"] = data
    validation_data["source_path"] = path
    validation_data["yaml_indent"] = indent
    validation_data["yaml_block_seq_indent"] = block_seq_indent
    return DataSource.model_validate(validation_data)


def load_data_sources(data_sources_dir: Path) -> List[DataSource]:
    data_sources = []
    for path in find_data_source_files(data_sources_dir):
        try:
            data_sources.append(parse_data_source(path))
        except Exception as exc:
            raise ValueError(f"Failed to parse {path}: {exc}") from exc

    return data_sources


def find_supported_ta_version_updates(
    data_sources: Iterable[DataSource],
    timeout: float,
) -> Tuple[
    List[Tuple[str, str, str, str]],
    List[Tuple[str, str]],
    Dict[str, str],
    List[str],
]:
    mismatches = []
    current_versions = []
    updates_by_app_number: Dict[str, str] = {}
    errors = []
    seen_tas = set()
    version_cache: Dict[str, Tuple[str, str]] = {}

    with requests.Session() as session:
        for data_source in data_sources:
            for supported_ta in data_source.supported_TA:
                ta_key = (supported_ta.name, supported_ta.url, supported_ta.version)
                if ta_key in seen_tas:
                    continue

                seen_tas.add(ta_key)

                try:
                    app_number = extract_splunkbase_app_number(supported_ta.url)
                    latest_version, release_published_time = (
                        data_source.get_latest_splunkbase_version(
                            supported_ta,
                            session=session,
                            timeout=timeout,
                            cache=version_cache,
                        )
                    )
                except Exception as exc:
                    errors.append(f"{supported_ta.name} ({supported_ta.url}): {exc}")
                    continue

                current_version = str(supported_ta.version)
                if latest_version != current_version:
                    mismatches.append(
                        (
                            supported_ta.name,
                            current_version,
                            latest_version,
                            release_published_time,
                        )
                    )
                    updates_by_app_number[app_number] = latest_version
                else:
                    current_versions.append((supported_ta.name, current_version))

    return mismatches, current_versions, updates_by_app_number, errors


def replace_yaml_line_value(line: str, new_value) -> str:
    line_without_newline = line.rstrip("\r\n")
    newline = line[len(line_without_newline):]

    key_part, separator, value_part = line_without_newline.partition(":")
    if not separator:
        raise ValueError(f"Could not replace YAML line value: {line_without_newline}")

    spacing_length = len(value_part) - len(value_part.lstrip(" "))
    spacing = value_part[:spacing_length]
    old_value = value_part[spacing_length:]

    comment = ""
    if old_value.startswith("'"):
        escaped_value = str(new_value).replace("'", "''")
        replacement = f"'{escaped_value}'"
    elif old_value.startswith('"'):
        escaped_value = str(new_value).replace("\\", "\\\\").replace('"', '\\"')
        replacement = f'"{escaped_value}"'
    else:
        if " #" in old_value:
            old_value, comment = old_value.split(" #", 1)
            comment = " #" + comment
        replacement = str(new_value)

    return f"{key_part}:{spacing}{replacement}{comment}{newline}"


def update_data_source_files(
    data_sources: Iterable[DataSource],
    updates_by_app_number: Dict[str, str],
    today: date,
) -> List[Tuple[str, str, str, str]]:
    updated_rows = []

    for data_source in data_sources:
        changed = False
        line_updates = {}
        lines = data_source.source_path.read_text(encoding="utf-8").splitlines(
            keepends=True,
        )
        raw_supported_tas = data_source.raw_yaml.get("supported_TA") or []

        for supported_ta in raw_supported_tas:
            try:
                app_number = extract_splunkbase_app_number(str(supported_ta["url"]))
            except ValueError:
                continue

            latest_version = updates_by_app_number.get(app_number)
            if latest_version is None:
                continue

            current_version = str(supported_ta["version"])
            if current_version == latest_version:
                continue

            version_line = supported_ta.lc.key("version")[0]
            line_updates[version_line] = replace_yaml_line_value(
                lines[version_line],
                latest_version,
            )
            changed = True
            updated_rows.append(
                (
                    str(data_source.source_path),
                    str(supported_ta["name"]),
                    current_version,
                    latest_version,
                )
            )

        if not changed:
            continue

        modification_date_line = data_source.raw_yaml.lc.key("modification_date")[0]
        line_updates[modification_date_line] = replace_yaml_line_value(
            lines[modification_date_line],
            today.isoformat(),
        )

        version_line = data_source.raw_yaml.lc.key("version")[0]
        line_updates[version_line] = replace_yaml_line_value(
            lines[version_line],
            int(data_source.raw_yaml["version"]) + 1,
        )

        for line_number, replacement_line in line_updates.items():
            lines[line_number] = replacement_line

        data_source.source_path.write_text("".join(lines), encoding="utf-8")

    return updated_rows


def format_markdown_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    empty_message: str,
) -> str:
    if not rows:
        return empty_message

    table_rows = [headers, *rows]
    widths = [
        max(len(str(row[column])) for row in table_rows)
        for column in range(len(headers))
    ]

    def format_row(row: Sequence[str]) -> str:
        cells = (
            str(value).ljust(widths[index])
            for index, value in enumerate(row)
        )
        return "| " + " | ".join(cells) + " |"

    separator = "| " + " | ".join("-" * width for width in widths) + " |"
    return "\n".join(
        [format_row(headers), separator, *(format_row(row) for row in rows)]
    )


def sort_table_rows_by_ta_name(
    rows: Sequence[Sequence[str]],
    ta_name_index: int = 0,
) -> List[Sequence[str]]:
    return sorted(rows, key=lambda row: str(row[ta_name_index]).casefold())


def main(argv: Optional[Sequence[str]] = None) -> int:
    settings = CliApp.run(
        CliSettings,
        cli_args=list(argv) if argv is not None else None,
    )

    data_sources = load_data_sources(settings.data_sources_dir)
    if not data_sources:
        print(f"No YAML files found in {settings.data_sources_dir}.")
        return 0

    mismatches, current_versions, updates_by_app_number, errors = (
        find_supported_ta_version_updates(
            data_sources,
            settings.timeout,
        )
    )

    if errors:
        print("\nErrors:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    updated_files = update_data_source_files(
        data_sources,
        updates_by_app_number,
        date.today(),
    )

    print("Supported TA version updates:")
    print(
        format_markdown_table(
            (
                "TA Name",
                "Current Version",
                "Updated Version",
                "Release Published Time",
            ),
            sort_table_rows_by_ta_name(mismatches),
            "No supported TA version updates found.",
        )
    )

    print("\nSupported TAs already current:")
    print(
        format_markdown_table(
            ("TA Name", "Current Version"),
            sort_table_rows_by_ta_name(current_versions),
            "No supported TAs were already current.",
        )
    )

    print("\nData source files updated:")
    print(
        format_markdown_table(
            ("File", "TA Name", "Previous Version", "Updated Version"),
            sort_table_rows_by_ta_name(updated_files, ta_name_index=1),
            "No data source files were updated.",
        )
    )

    if mismatches and settings.fail_on_update:
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
