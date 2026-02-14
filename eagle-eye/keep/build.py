#!/usr/bin/env python3
"""
Eagle Eye Build Script
======================
Parses all security-content YAML files (detections, stories, data_sources, macros)
and generates a self-contained HTML explorer at eagle-eye/discard/eagle-eye.html.

Usage:
    python eagle-eye/keep/build.py

Requirements:
    PyYAML (pip install pyyaml)
"""

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install it with: pip install pyyaml")
    sys.exit(1)


def find_repo_root():
    """Find the repository root (directory containing contentctl.yml)."""
    # Start from this script's location and walk up
    current = Path(__file__).resolve().parent
    for _ in range(10):
        if (current / "contentctl.yml").exists():
            return current
        current = current.parent
    # Fallback: try cwd
    if (Path.cwd() / "contentctl.yml").exists():
        return Path.cwd()
    print("ERROR: Could not find repository root (no contentctl.yml found).")
    sys.exit(1)


def load_yaml_files(directory):
    """Load all .yml files from a directory (non-recursively)."""
    results = []
    d = Path(directory)
    if not d.exists():
        return results
    for f in sorted(d.glob("*.yml")):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
                if data and isinstance(data, dict):
                    data["_file"] = str(f.relative_to(d.parent.parent) if d.parent.parent else f.name)
                    results.append(data)
        except Exception as e:
            print(f"  WARN: Skipping {f.name}: {e}")
    return results


def load_yaml_files_recursive(directory):
    """Load all .yml files from a directory recursively."""
    results = []
    d = Path(directory)
    if not d.exists():
        return results
    for f in sorted(d.rglob("*.yml")):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
                if data and isinstance(data, dict):
                    data["_file"] = str(f.relative_to(d.parent) if d.parent else f.name)
                    results.append(data)
        except Exception as e:
            print(f"  WARN: Skipping {f.name}: {e}")
    return results


def extract_macros_from_search(search_str):
    """Extract macro names from backtick-delimited references in a search string.

    Real SPL macros look like `macro_name` or `macro_name(arg)`.
    SPL inline comments use triple-backticks: ```comment text here```.
    We filter out comment text by excluding matches that contain spaces.
    """
    if not search_str:
        return []
    raw = re.findall(r"`([^`]+)`", search_str)
    # Real macro names are identifiers — never contain spaces.
    # SPL triple-backtick comments always have descriptive text with spaces.
    return [m for m in raw if " " not in m]


def load_mitre_attack():
    """Download and parse MITRE ATT&CK STIX data to build technique→tactics mapping."""
    cache_path = Path(__file__).resolve().parent / ".mitre-cache.json"

    # Try cache first (cache for 7 days)
    if cache_path.exists():
        import time
        age = time.time() - cache_path.stat().st_mtime
        if age < 7 * 86400:
            try:
                with open(cache_path, "r") as f:
                    cached = json.load(f)
                print(f"  Using cached MITRE ATT&CK data ({len(cached.get('techniques', {}))} techniques)")
                return cached
            except Exception:
                pass

    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    print("  Downloading MITRE ATT&CK data from GitHub...")

    try:
        import ssl
        req = urllib.request.Request(url, headers={"User-Agent": "eagle-eye-builder/1.0"})
        # Try default SSL context first, fall back to unverified (common on macOS)
        try:
            resp = urllib.request.urlopen(req, timeout=60)
        except Exception:
            ctx = ssl._create_unverified_context()
            req = urllib.request.Request(url, headers={"User-Agent": "eagle-eye-builder/1.0"})
            resp = urllib.request.urlopen(req, timeout=60, context=ctx)
        stix_data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"  WARN: Could not download MITRE ATT&CK data: {e}")
        print("  Matrix view will show technique IDs only (no names/tactics).")
        return {"techniques": {}, "tactics": {}, "tactic_order": []}

    # Parse tactics
    tactics_info = {}  # shortname → {name, id}
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "x-mitre-tactic" and not obj.get("revoked"):
            short = obj.get("x_mitre_shortname", "")
            name = obj.get("name", "")
            refs = obj.get("external_references", [])
            ext_id = next((r["external_id"] for r in refs if r.get("source_name") == "mitre-attack"), "")
            if short:
                tactics_info[short] = {"name": name, "id": ext_id}

    # Standard tactic order
    tactic_order = [
        "reconnaissance", "resource-development", "initial-access", "execution",
        "persistence", "privilege-escalation", "defense-evasion", "credential-access",
        "discovery", "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact",
    ]

    # Parse techniques
    techniques = {}  # ext_id → {name, tactics[], url, is_subtechnique}
    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        refs = obj.get("external_references", [])
        ext_id = next((r["external_id"] for r in refs if r.get("source_name") == "mitre-attack"), None)
        if not ext_id:
            continue
        name = obj.get("name", "")
        phases = obj.get("kill_chain_phases", [])
        tech_tactics = [p["phase_name"] for p in phases if p.get("kill_chain_name") == "mitre-attack"]
        is_sub = obj.get("x_mitre_is_subtechnique", False)
        techniques[ext_id] = {
            "name": name,
            "tactics": tech_tactics,
            "is_sub": is_sub,
        }

    result = {
        "techniques": techniques,
        "tactics": {k: v for k, v in tactics_info.items() if k in tactic_order},
        "tactic_order": tactic_order,
    }

    print(f"  Parsed {len(techniques)} techniques across {len(tactics_info)} tactics")

    # Cache
    try:
        with open(cache_path, "w") as f:
            json.dump(result, f)
    except Exception:
        pass

    return result


def build_detection_record(raw):
    """Extract relevant fields from a raw detection YAML dict."""
    tags = raw.get("tags", {})
    search = raw.get("search", "")
    macros = extract_macros_from_search(search)

    return {
        "name": raw.get("name", ""),
        "id": raw.get("id", ""),
        "version": raw.get("version"),
        "date": raw.get("date", ""),
        "author": raw.get("author", ""),
        "status": raw.get("status", ""),
        "type": raw.get("type", ""),
        "description": raw.get("description", ""),
        "search": raw.get("search", ""),
        "data_source": raw.get("data_source", []) or [],
        "analytic_story": tags.get("analytic_story", []) or [],
        "mitre_attack_id": tags.get("mitre_attack_id", []) or [],
        "cve": tags.get("cve", []) or [],
        "security_domain": tags.get("security_domain", ""),
        "asset_type": tags.get("asset_type", ""),
        "macros": macros,
        "file": raw.get("_file", ""),
    }


def build_story_record(raw):
    """Extract relevant fields from a raw story YAML dict."""
    tags = raw.get("tags", {})
    return {
        "name": raw.get("name", ""),
        "id": raw.get("id", ""),
        "version": raw.get("version"),
        "date": raw.get("date", ""),
        "author": raw.get("author", ""),
        "status": raw.get("status", ""),
        "description": raw.get("description", ""),
        "narrative": raw.get("narrative", ""),
        "references": raw.get("references", []) or [],
        "category": tags.get("category", []) or [],
        "file": raw.get("_file", ""),
    }


def build_datasource_record(raw):
    """Extract relevant fields from a raw data_source YAML dict."""
    return {
        "name": raw.get("name", ""),
        "id": raw.get("id", ""),
        "description": raw.get("description", ""),
        "source": raw.get("source", ""),
        "sourcetype": raw.get("sourcetype", ""),
        "supported_TA": raw.get("supported_TA", []) or [],
        "file": raw.get("_file", ""),
    }


def main():
    root = find_repo_root()
    print(f"Repository root: {root}")

    # --- Load content ---
    print("Loading detections...")
    raw_detections = load_yaml_files_recursive(root / "detections")
    # Filter out deprecated directory unless they have useful content
    detections = [build_detection_record(d) for d in raw_detections if d.get("name")]
    print(f"  Loaded {len(detections)} detections")

    print("Loading stories...")
    raw_stories = load_yaml_files(root / "stories")
    stories = [build_story_record(s) for s in raw_stories if s.get("name")]
    print(f"  Loaded {len(stories)} stories")

    print("Loading data sources...")
    raw_ds = load_yaml_files(root / "data_sources")
    data_sources = [build_datasource_record(ds) for ds in raw_ds if ds.get("name")]
    print(f"  Loaded {len(data_sources)} data sources")

    print("Loading macros...")
    raw_macros = load_yaml_files(root / "macros")
    macro_names = sorted(set(m.get("name", "") for m in raw_macros if m.get("name")))
    print(f"  Loaded {len(macro_names)} macros")

    print("Loading MITRE ATT&CK enrichment...")
    mitre_enrichment = load_mitre_attack()

    # --- Build data payload ---
    data = {
        "detections": detections,
        "stories": stories,
        "data_sources": data_sources,
        "macro_names": macro_names,
        "mitre": mitre_enrichment,
    }

    data_json = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    # Escape sequences that would break a <script type="application/json"> island:
    # - "</script>" or "</Script>" etc. in string values would close the tag early
    # - "<!--" could open an HTML comment
    data_json = data_json.replace("</", "<\\/")
    data_json = data_json.replace("<!--", "<\\!--")
    print(f"JSON payload: {len(data_json) / 1024:.0f} KB")

    # --- Load template ---
    template_path = Path(__file__).resolve().parent / "template.html"
    if not template_path.exists():
        print(f"ERROR: Template not found at {template_path}")
        sys.exit(1)

    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()

    # --- Inject data ---
    html = template.replace("%%DATA_JSON%%", data_json)

    # --- Write output ---
    output_dir = root / "eagle-eye" / "discard"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "eagle-eye.html"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\nGenerated: {output_path}")
    print(f"File size: {output_path.stat().st_size / 1024:.0f} KB")
    print("Open in a browser to explore.")


if __name__ == "__main__":
    main()
