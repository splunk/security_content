#!/usr/bin/env python3
"""
Analyze TTP detections with multiple risk_objects.

Finds all YAML files under detections/**/*.yml where:
  - type == TTP
  - rba.risk_objects has 2 or more entries

Aggregates results by the set of risk_object types and reports
files that do NOT follow the standard (1 user + 1 system) pattern.

Usage:
    uv run --with pyyaml scripts/analyze_ttp_risk_objects.py
"""

import os
import yaml
from collections import defaultdict

DETECTIONS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "detections")


def main():
    results = defaultdict(list)
    total_ttp_with_multi_risk = 0

    for root, dirs, files in os.walk(DETECTIONS_DIR):
        for fname in files:
            if not fname.endswith(".yml"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath) as f:
                    data = yaml.safe_load(f)
            except Exception:
                continue

            if not isinstance(data, dict):
                continue
            if data.get("type") != "TTP":
                continue

            rba = data.get("rba")
            if not isinstance(rba, dict):
                continue

            risk_objects = rba.get("risk_objects", [])
            if not isinstance(risk_objects, list) or len(risk_objects) < 2:
                continue

            total_ttp_with_multi_risk += 1
            types = tuple(sorted(ro.get("type", "unknown") for ro in risk_objects))
            results[types].append(fpath)

    print(f"Total TTP files with 2+ risk_objects: {total_ttp_with_multi_risk}\n")
    print("Aggregated by risk_object_type set:")
    for type_combo, files in sorted(results.items(), key=lambda x: -len(x[1])):
        print(f"  {list(type_combo)} — {len(files)} file(s)")

    print("\nNon-(1 user + 1 system) combos:")
    non_standard_total = 0
    for type_combo, files in sorted(results.items(), key=lambda x: -len(x[1])):
        if type_combo == ("system", "user"):
            continue
        non_standard_total += len(files)
        print(f"  {list(type_combo)} — {len(files)} file(s)")
        for f in files:
            print(f"    {os.path.relpath(f, DETECTIONS_DIR)}")

    print(f"\nTotal non-(1 user + 1 system): {non_standard_total}")


if __name__ == "__main__":
    main()
