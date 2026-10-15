"""
A simple script formatting the newest testing_artifacts/test_results_<timestamp>.yml
written by `contentctl-ng test run` to display on github actions
"""

import sys
from pathlib import Path

import yaml

RESULTS_DIR = Path("testing_artifacts")
STATUS_ICONS = {"pass": "🟢", "fail": "🔴", "error": "🔴", "skip": "🔵"}


def latest_results_file() -> Path | None:
    # Timestamps are YYYYmmdd_HHMMSS, so lexical order is chronological. The JUnit
    # files are named test_results_junit_*.xml and never match this glob.
    candidates = sorted(RESULTS_DIR.glob("test_results_*.yml"))
    return candidates[-1] if candidates else None


def main():
    results_file = latest_results_file()
    if results_file is None:
        print(f"Error: no test_results_*.yml found in {RESULTS_DIR.resolve()}.")
        sys.exit(1)

    with open(results_file, "r") as file:
        data = yaml.safe_load(file)

    totals = data["totals"]
    print(
        f"**Download the job artifacts of this run and view the complete results in {results_file.name} for troubleshooting failures.**\n"
    )
    print(" 📝 **Experimental or manual_test detections are not tested** 📝 **\n")
    print(
        f"Total tests: {totals['total_tests']} | passed: {totals['passed']} | failed: {totals['failed']} | "
        f"errored: {totals['errored']} | skipped: {totals['skipped']} | not run: {totals['not_run']}\n"
    )

    print(" 🏗️⚒️ **Test Details:**\n")
    print(f"{'Name':<80} | {'Status':<7} | {'Test Type':<22} | {'Message':<50}")
    print(f"{'----':<80} | {'------':<7} | {'---------':<22} | {'-------':<50}")
    for job in data["jobs"]:
        for test in job["tests"]:
            result = test.get("result")
            if result is None:
                status, message = "not run", ""
                icon = "🔴"
            else:
                status = result["status"]
                message = (result.get("message") or "").replace("\n", " ")
                icon = STATUS_ICONS.get(status, "🔴")
            name = (job.get("content_name") or "N/A").strip()
            print(
                f"{name:<80} | {icon} {status.upper():<7} | {test['strategy_name']:<22} | {message or '-':<50}"
            )

    print("\n")
    print("**Overall Status**")
    print("-------------------------------")
    if totals["total_tests"] < 1:
        print("🔵 - **CI Success: No detections to test**\n\n")
        sys.exit(0)
    if not totals["success"]:
        print("🔴 - **CI Failure: There are failed tests.**\n\n")
        for identity in totals["attention"]:
            print(f"- {identity}")
        sys.exit(1)
    print("🟢 - **CI Success: No failed tests.**\n\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
