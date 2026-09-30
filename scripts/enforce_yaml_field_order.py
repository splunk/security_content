#!/usr/bin/env python3
"""
Preserve-format YAML root field ordering.

The script only moves complete top-level YAML blocks. It does not parse and
dump YAML, so indentation, spaces, scalar style, comments, and nested content
inside each field block stay exactly as they were.
"""

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


BOM = b"\xef\xbb\xbf"
ROOT_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:(?:\s.*)?(?:\r?\n)?$")


class ConfigError(ValueError):
    """Raised when the field-order config cannot be read."""


class FieldOrderError(ValueError):
    """Raised when a YAML file cannot be safely reordered."""


@dataclass(frozen=True)
class FieldOrderConfig:
    target_paths: Tuple[str, ...]
    extensions: Tuple[str, ...]
    root_field_order: Tuple[str, ...]
    unknown_fields: str = "append"


@dataclass(frozen=True)
class RootBlock:
    key: str
    lines: Tuple[str, ...]
    line_number: int


@dataclass(frozen=True)
class OrderedText:
    text: str
    current_keys: Tuple[str, ...]
    desired_keys: Tuple[str, ...]


@dataclass(frozen=True)
class FileOrderResult:
    path: Path
    changed: bool
    detail: Optional[str] = None
    error: Optional[str] = None


def find_repo_root() -> Path:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return Path.cwd()


def parse_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_simple_yaml_config(config_path: Path) -> Dict[str, object]:
    data: Dict[str, object] = {}
    current_key: Optional[str] = None

    for lineno, raw_line in enumerate(config_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("- "):
            if current_key is None or not isinstance(data.get(current_key), list):
                raise ConfigError(f"{config_path}:{lineno}: list item without a list key")
            item = parse_scalar(line[2:])
            if not item:
                raise ConfigError(f"{config_path}:{lineno}: empty list item")
            data[current_key].append(item)  # type: ignore[index]
            continue

        if ":" not in line:
            raise ConfigError(f"{config_path}:{lineno}: expected 'key:' or 'key: value'")

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ConfigError(f"{config_path}:{lineno}: empty key")

        if value:
            data[key] = parse_scalar(value)
            current_key = None
        else:
            data[key] = []
            current_key = key

    return data


def as_string_list(data: Dict[str, object], key: str, default: Sequence[str]) -> Tuple[str, ...]:
    value = data.get(key, list(default))
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"Config key '{key}' must be a string or list of strings")
    return tuple(value)


def load_config(config_path: Path) -> FieldOrderConfig:
    if not config_path.exists():
        raise ConfigError(f"Field-order config not found: {config_path}")

    data = parse_simple_yaml_config(config_path)
    root_field_order = data.get("root_field_order", data.get("field_order"))
    if not isinstance(root_field_order, list) or not all(isinstance(item, str) for item in root_field_order):
        raise ConfigError("Config key 'root_field_order' must be a list of field names")

    duplicate_fields = sorted({field for field in root_field_order if root_field_order.count(field) > 1})
    if duplicate_fields:
        raise ConfigError(f"Duplicate field(s) in root_field_order: {', '.join(duplicate_fields)}")

    target_paths = as_string_list(data, "target_paths", ["detections/"])
    extensions = as_string_list(data, "extensions", [".yml", ".yaml"])
    normalized_extensions = tuple(ext if ext.startswith(".") else f".{ext}" for ext in extensions)

    unknown_fields = data.get("unknown_fields", "append")
    if not isinstance(unknown_fields, str):
        raise ConfigError("Config key 'unknown_fields' must be a string")
    if unknown_fields not in {"append", "fail"}:
        raise ConfigError("Config key 'unknown_fields' must be either 'append' or 'fail'")

    return FieldOrderConfig(
        target_paths=tuple(normalize_target_path(path) for path in target_paths),
        extensions=normalized_extensions,
        root_field_order=tuple(root_field_order),
        unknown_fields=unknown_fields,
    )


def normalize_target_path(path: str) -> str:
    normalized = path.replace("\\", "/").strip("/")
    return normalized


def relative_to_repo(path: Path, repo_root: Path) -> Path:
    absolute_path = path if path.is_absolute() else repo_root / path
    try:
        return absolute_path.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return path


def path_matches_config(path: Path, repo_root: Path, config: FieldOrderConfig) -> bool:
    if path.suffix not in config.extensions:
        return False

    rel_path = relative_to_repo(path, repo_root)
    rel_posix = rel_path.as_posix().strip("/")
    return any(rel_posix == target or rel_posix.startswith(f"{target}/") for target in config.target_paths)


def find_yaml_files(paths: Sequence[str], repo_root: Path, config: FieldOrderConfig) -> List[Path]:
    found: List[Path] = []

    for path_str in paths:
        path = Path(path_str)
        path = path if path.is_absolute() else repo_root / path

        if path.is_file():
            if path_matches_config(path, repo_root, config):
                found.append(path)
            continue

        if path.is_dir():
            for extension in config.extensions:
                for yaml_file in path.rglob(f"*{extension}"):
                    if path_matches_config(yaml_file, repo_root, config):
                        found.append(yaml_file)

    return sorted(set(found), key=lambda item: relative_to_repo(item, repo_root).as_posix())


def split_root_blocks(text: str) -> Tuple[Tuple[str, ...], Tuple[RootBlock, ...]]:
    lines = tuple(text.splitlines(keepends=True))
    starts: List[Tuple[int, str]] = []

    for index, line in enumerate(lines):
        match = ROOT_KEY_RE.match(line)
        if match:
            starts.append((index, match.group(1)))

    if not starts:
        return lines, tuple()

    preamble = lines[: starts[0][0]]
    blocks: List[RootBlock] = []
    seen: Dict[str, int] = {}
    duplicates: List[str] = []

    for index, (start, key) in enumerate(starts):
        end = starts[index + 1][0] if index + 1 < len(starts) else len(lines)
        if key in seen:
            duplicates.append(f"{key} at lines {seen[key]} and {start + 1}")
        else:
            seen[key] = start + 1
        blocks.append(RootBlock(key=key, lines=lines[start:end], line_number=start + 1))

    if duplicates:
        raise FieldOrderError(f"Duplicate root field(s): {', '.join(duplicates)}")

    return preamble, tuple(blocks)


def render_ordered_text(text: str, config: FieldOrderConfig) -> OrderedText:
    preamble, blocks = split_root_blocks(text)
    if not blocks:
        return OrderedText(text=text, current_keys=tuple(), desired_keys=tuple())

    block_by_key = {block.key: block for block in blocks}
    ordered_blocks: List[RootBlock] = []
    used_keys = set()

    for key in config.root_field_order:
        block = block_by_key.get(key)
        if block is not None:
            ordered_blocks.append(block)
            used_keys.add(key)

    unknown_blocks = [block for block in blocks if block.key not in used_keys]
    if unknown_blocks and config.unknown_fields == "fail":
        unknown_keys = ", ".join(block.key for block in unknown_blocks)
        raise FieldOrderError(f"Unknown root field(s) not configured: {unknown_keys}")

    ordered_blocks.extend(unknown_blocks)

    rendered_lines: List[str] = list(preamble)
    for block in ordered_blocks:
        rendered_lines.extend(block.lines)

    return OrderedText(
        text="".join(rendered_lines),
        current_keys=tuple(block.key for block in blocks),
        desired_keys=tuple(block.key for block in ordered_blocks),
    )


def describe_difference(current_keys: Sequence[str], desired_keys: Sequence[str]) -> str:
    for index, (current, desired) in enumerate(zip(current_keys, desired_keys), start=1):
        if current != desired:
            return f"position {index}: found '{current}', expected '{desired}'"
    if len(current_keys) != len(desired_keys):
        return "root field set changed during ordering"
    return "root fields are not in configured order"


def read_utf8_bytes(path: Path) -> Tuple[str, bool]:
    raw = path.read_bytes()
    has_bom = raw.startswith(BOM)
    if has_bom:
        raw = raw[len(BOM) :]
    try:
        return raw.decode("utf-8"), has_bom
    except UnicodeDecodeError as exc:
        raise FieldOrderError(f"File is not valid UTF-8: {exc}") from exc


def write_utf8_bytes(path: Path, text: str, has_bom: bool) -> None:
    raw = text.encode("utf-8")
    if has_bom:
        raw = BOM + raw
    path.write_bytes(raw)


def process_file(path: Path, config: FieldOrderConfig, fix: bool = False) -> FileOrderResult:
    try:
        original_text, has_bom = read_utf8_bytes(path)
        ordered = render_ordered_text(original_text, config)
    except (OSError, FieldOrderError) as exc:
        return FileOrderResult(path=path, changed=False, error=str(exc))

    changed = ordered.text != original_text
    if changed and fix:
        try:
            write_utf8_bytes(path, ordered.text, has_bom)
        except OSError as exc:
            return FileOrderResult(path=path, changed=False, error=str(exc))

    detail = describe_difference(ordered.current_keys, ordered.desired_keys) if changed else None
    return FileOrderResult(path=path, changed=changed, detail=detail)


def display_path(path: Path, repo_root: Path) -> str:
    try:
        return relative_to_repo(path, repo_root).as_posix()
    except OSError:
        return str(path)


def print_results(results: Sequence[FileOrderResult], repo_root: Path, fix: bool) -> int:
    errors = [result for result in results if result.error]
    changed = [result for result in results if result.changed]

    if errors:
        print("[FAIL] Field-order check could not process some file(s):")
        for result in errors:
            print(f"  - {display_path(result.path, repo_root)}: {result.error}")

    if changed and fix:
        print(f"[OK] Reordered root fields in {len(changed)} file(s):")
        for result in changed:
            print(f"  - {display_path(result.path, repo_root)}")
    elif changed:
        print(f"[FAIL] Root fields are not in configured order in {len(changed)} file(s):")
        for result in changed:
            detail = f": {result.detail}" if result.detail else ""
            print(f"  - {display_path(result.path, repo_root)}{detail}")
        print("\n[TIP] Run: python scripts/enforce_yaml_field_order.py --fix detections/")

    if not errors and not changed:
        print(f"[PASS] Root field order is valid for {len(results)} file(s)")

    return 1 if errors or (changed and not fix) else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check or fix top-level YAML field order without changing field formatting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python scripts/enforce_yaml_field_order.py --check detections/
  python scripts/enforce_yaml_field_order.py --fix detections/endpoint/file.yml
  python scripts/enforce_yaml_field_order.py --config .yamlfieldorder --check detections/
""",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Verify field order without changing files (default)")
    mode.add_argument("--fix", action="store_true", help="Rewrite files with configured root field order")
    parser.add_argument("--config", default=".yamlfieldorder", help="Path to field-order config")
    parser.add_argument("paths", nargs="*", help="YAML files or directories to process")

    args = parser.parse_args(argv)
    repo_root = find_repo_root()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = repo_root / config_path

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"[ERROR] {exc}")
        return 1

    input_paths = args.paths if args.paths else list(config.target_paths)
    yaml_files = find_yaml_files(input_paths, repo_root, config)
    if not yaml_files:
        print("[PASS] No configured YAML files found")
        return 0

    results = [process_file(path, config, fix=args.fix) for path in yaml_files]
    return print_results(results, repo_root, fix=args.fix)


if __name__ == "__main__":
    sys.exit(main())
