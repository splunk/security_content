#!/usr/bin/env python3

import re
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "detections"
MACROS = ROOT / "macros"
TYPES = {"TTP", "Anomaly"}
FIELDS = ("references", "threat_objects")
LOOKUP_COMMAND = re.compile(
    r"(?:^|\|)\s*lookup\b([^|]*)", re.IGNORECASE | re.MULTILINE
)
LOCAL_TRUE = re.compile(r"\blocal\s*=\s*(?:t|true)\b", re.IGNORECASE)


def is_empty(value):
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    return not value


def is_deprecated(path, content_root):
    return "deprecated" in path.relative_to(content_root).parts


def is_production(content):
    # Macros do not currently define a status; treat them as active unless a
    # status is explicitly present and is not production.
    return content.get("status", "production").lower() == "production"


def load_rules():
    files = sorted(RULES.rglob("*.yml")) + sorted(RULES.rglob("*.yaml"))
    rules = []
    for path in files:
        if is_deprecated(path, RULES):
            continue
        rule = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if (
            isinstance(rule, dict)
            and rule.get("type") in TYPES
            and is_production(rule)
        ):
            rules.append((path.relative_to(ROOT).as_posix(), rule))
    return rules


def load_macros():
    files = sorted(MACROS.rglob("*.yml")) + sorted(MACROS.rglob("*.yaml"))
    macros = []
    for path in files:
        if is_deprecated(path, MACROS):
            continue
        macro = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if (
            isinstance(macro, dict)
            and is_production(macro)
            and isinstance(macro.get("definition"), str)
        ):
            macros.append((path.relative_to(ROOT).as_posix(), macro))
    return macros


def test_missing_fields(rules):
    errors = {}
    for path, rule in rules:
        missing = [field for field in FIELDS if field not in rule]
        if missing:
            errors[path] = [f"missing: {', '.join(missing)}"]
    return errors


def test_empty_fields(rules):
    errors = {}
    for path, rule in rules:
        empty = [field for field in FIELDS if field in rule and is_empty(rule[field])]
        if empty:
            errors[path] = [f"empty: {', '.join(empty)}"]
    return errors


def test_lookup_local_flags(content):
    errors = {}
    for path, item in content:
        definition = item.get("search", item.get("definition", ""))
        violations = [
            match.group(0).strip()
            for match in LOOKUP_COMMAND.finditer(definition)
            if not LOCAL_TRUE.search(match.group(1))
        ]
        if violations:
            errors[path] = [
                f"lookup command(s) missing local=t/true: {len(violations)}"
            ]
    return errors


def print_table(rules, errors):
    rows = []
    for path, _ in rules:
        if path in errors:
            rows.append((path, "; ".join(errors[path])))
    headers = ("Rule", "Errors")
    widths = [max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(2)]
    line = "-+-".join("-" * width for width in widths)
    print(" | ".join(f"{headers[i]:<{widths[i]}}" for i in range(2)))
    print(line)
    for row in rows:
        print(" | ".join(f"{row[i]:<{widths[i]}}" for i in range(2)))


def main():
    rules = load_rules()
    macros = load_macros()
    content = rules + macros
    errors = test_missing_fields(rules)
    for path, fields in test_empty_fields(rules).items():
        errors.setdefault(path, []).extend(fields)
    for path, lookup_errors in test_lookup_local_flags(content).items():
        errors.setdefault(path, []).extend(lookup_errors)
    if errors:
        print_table(content, errors)
        print(
            f"\n{len(errors)} content item(s) failed out of "
            f"{len(rules)} rule(s) and {len(macros)} macro(s)"
        )
        return 1
    print(f"PASS: {len(rules)} rule(s) and {len(macros)} macro(s) checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
