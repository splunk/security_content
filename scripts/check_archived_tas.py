#!/usr/bin/env python3
"""Create or refresh one GitHub issue for each archived TA in active use."""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
DATA_SOURCES_DIR = ROOT / "data_sources"
DETECTIONS_DIR = ROOT / "detections"
SPLUNKBASE_API = "https://splunkbase.splunk.com/api/v1/app"
APP_URL_PATTERN = re.compile(
    r"https?://(?:www\.)?splunkbase\.splunk\.com/app/(\d+)(?:/|\b)", re.I
)
USER_AGENT = "splunk-threat-research-team/1.0"


def yaml_files(folder: Path):
    yield from sorted(folder.rglob("*.yml"))
    yield from sorted(folder.rglob("*.yaml"))


def load_yaml(path: Path) -> dict[str, Any] | None:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        print(f"Warning: skipping {path.relative_to(ROOT)}: {exc}", file=sys.stderr)
        return None
    return value if isinstance(value, dict) else None


def discover_used_tas() -> dict[str, dict[str, Any]]:
    """Return TAs grouped by app ID, including linked data sources/detections."""
    data_sources: dict[str, dict[str, Any]] = {}
    for path in yaml_files(DATA_SOURCES_DIR):
        obj = load_yaml(path)
        if not obj or not isinstance(obj.get("name"), str):
            continue
        data_sources[obj["name"].strip().casefold()] = {
            "name": obj["name"].strip(),
            "path": path.relative_to(ROOT).as_posix(),
            "supported_tas": obj.get("supported_TA") or [],
            "detections": [],
        }

    for path in yaml_files(DETECTIONS_DIR):
        detection = load_yaml(path)
        if not detection:
            continue
        if str(detection.get("status") or "").strip().casefold() == "deprecated":
            continue
        references = detection.get("data_source") or []
        if isinstance(references, str):
            references = [references]
        if not isinstance(references, list):
            continue
        detection_name = str(detection.get("name") or path.stem)
        detection_path = path.relative_to(ROOT).as_posix()
        for reference in references:
            if not isinstance(reference, str):
                continue
            source = data_sources.get(reference.strip().casefold())
            if source:
                source["detections"].append({"name": detection_name, "path": detection_path})

    tas: dict[str, dict[str, Any]] = {}
    for source in data_sources.values():
        if not source["detections"]:
            continue
        for ta in source["supported_tas"]:
            if not isinstance(ta, dict):
                continue
            url = str(ta.get("url") or "").strip()
            match = APP_URL_PATTERN.search(url)
            if not match:
                continue
            app_id = match.group(1)
            name = str(ta.get("name") or f"Splunkbase app {app_id}").strip()
            record = tas.setdefault(
                app_id,
                {
                    "app_id": app_id,
                    "name": name,
                    "url": f"https://splunkbase.splunk.com/app/{app_id}/",
                    "data_sources": {},
                },
            )
            if record["name"].startswith("Splunkbase app ") and name:
                record["name"] = name
            record["data_sources"][source["path"]] = source
    return tas


def get_json(url: str) -> Any:
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().casefold() in {"true", "1", "yes", "archived"}
    return value is True or value == 1


def splunkbase_archived(app_id: str) -> tuple[bool, str]:
    url = f"{SPLUNKBASE_API}/{app_id}/"
    payload = get_json(url)
    if not isinstance(payload, dict):
        raise ValueError("unexpected Splunkbase response")
    archived = truthy(payload.get("is_archived")) or truthy(payload.get("archive_status"))
    api_name = str(payload.get("title") or payload.get("name") or "").strip()
    return archived, api_name


def github_request(method: str, url: str, token: str, body: dict[str, Any] | None = None) -> Any:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
        return json.loads(raw.decode("utf-8")) if raw else None


def list_repo_issues(repo: str, token: str) -> list[dict[str, Any]]:
    """Read open and closed issues so an old issue can be reopened in place."""
    issues: list[dict[str, Any]] = []
    page = 1
    while True:
        query = urllib.parse.urlencode({"state": "all", "per_page": 100, "page": page})
        payload = github_request("GET", f"https://api.github.com/repos/{repo}/issues?{query}", token)
        if not isinstance(payload, list):
            raise ValueError("unexpected GitHub issues response")
        issues.extend(item for item in payload if isinstance(item, dict) and "pull_request" not in item)
        if len(payload) < 100:
            return issues
        page += 1


def issue_body(ta: dict[str, Any], repo: str, branch: str) -> str:
    lines = [
        f"<!-- archived-ta-tracker:{ta['app_id']} -->",
        f"**Splunkbase TA:** [{ta['name']}]({ta['url']})",
        "",
        "This archived Splunkbase TA is referenced by data source objects used by detections.",
        "",
        "### Data source objects and detections",
    ]
    for source in sorted(ta["data_sources"].values(), key=lambda item: item["name"].casefold()):
        source_url = f"https://github.com/{repo}/blob/{branch}/{source['path']}"
        lines.append(f"- [{source['name']}]({source_url})")
        detection_items = sorted(source["detections"], key=lambda item: item["name"].casefold())
        for detection in detection_items:
            detection_url = f"https://github.com/{repo}/blob/{branch}/{detection['path']}"
            lines.append(f"  - Detection: [{detection['name']}]({detection_url})")
    lines.extend(["", "_This issue is maintained automatically by the archived TA daily workflow._"])
    return "\n".join(lines)


def find_existing_issue(ta: dict[str, Any], issues: list[dict[str, Any]]) -> dict[str, Any] | None:
    marker = f"<!-- archived-ta-tracker:{ta['app_id']} -->"
    marked = [issue for issue in issues if marker in str(issue.get("body") or "")]
    if marked:
        return next((issue for issue in marked if issue.get("state") == "open"), marked[0])

    # Adopt a manually created issue only when its exact title and Splunkbase
    # URL both match. This avoids conflating two apps that happen to share a name.
    expected_title = f"{ta['name']} is archived on Splunkbase"
    for issue in issues:
        if issue.get("title") == expected_title and ta["url"] in str(issue.get("body") or ""):
            return issue
    return None


def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    branch = os.environ.get("GITHUB_REF_NAME", "develop").strip()
    if not repo or not token:
        print("GITHUB_REPOSITORY and GITHUB_TOKEN are required.", file=sys.stderr)
        return 2

    used_tas = discover_used_tas()
    print(f"Found {len(used_tas)} distinct TAs referenced by data sources used in detections.")
    issues = list_repo_issues(repo, token)
    api_root = f"https://api.github.com/repos/{repo}/issues"
    archived_count = 0

    for app_id, ta in sorted(used_tas.items(), key=lambda item: item[1]["name"].casefold()):
        try:
            archived, api_name = splunkbase_archived(app_id)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            print(f"Warning: could not check Splunkbase app {app_id}: {exc}", file=sys.stderr)
            continue
        if not archived:
            continue
        archived_count += 1
        if api_name:
            ta["name"] = api_name

        title = f"{ta['name']} is archived on Splunkbase"
        body = issue_body(ta, repo, branch)
        existing = find_existing_issue(ta, issues)
        try:
            if existing:
                issue_number = existing["number"]
                result = github_request(
                    "PATCH",
                    f"{api_root}/{issue_number}",
                    token,
                    {"title": title, "body": body, "state": "open"},
                )
                action = "Updated/reopened"
            else:
                result = github_request("POST", api_root, token, {"title": title, "body": body})
                action = "Created"
                issues.append(result)
            print(f"{action} issue #{result['number']}: {title}")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, KeyError, TypeError) as exc:
            print(f"Error: could not save issue for app {app_id}: {exc}", file=sys.stderr)
        time.sleep(0.15)

    print(f"Archived TAs currently in use: {archived_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
