# Eagle Eye Upgrade

## Overview

The goal of this effort is to build a tool that makes it much easier to understand the relationship between analytics, data sources, and the detection content. Right not it's difficult to see in a single view any complete picture. There is a fair amount of information on the detection yml files, but there's no chain or relationship that can be pivoted on to explore related detections based upon common characteristics.

A simple app, maybe a web app, would probably be able address this.

## Plan 1 - Claude Opus 4.6

Good, I've read all three files. The eagle-eye document describes a tool to visualize relationships between analytics, data sources, and detections. Let me research the workspace more deeply to understand the full scope of content and relationships.

Subagent: Research detection content structure

Reviewed 6 files and searched for YAML files
I now have a solid picture of the workspace. Here's what I see:

~2,175 detections across endpoint/cloud/network/web/application
~353 analytic stories grouping related detections
~230+ data sources describing telemetry sources with field-level detail
~150+ macros referenced in detection searches
The key relationship graph linking everything together flows through these fields in each detection YAML:

Field	Links to
tags.analytic_story	stories/
data_source	data_sources/
tags.mitre_attack_id	MITRE ATT&CK techniques
tags.cve	CVE references
tags.security_domain	domain (endpoint, access, network…)
search (backtick macros)	macros/
Before I draft a plan, let me clarify a few things:

Asked 3 questions (App type, Core views, Location)

What kind of app would you prefer for exploring detection relationships?
Static HTML site
- Python script generates a self-contained HTML/JS page you can open locally — zero server needed
Which views matter most to start with? (We can always add more later.)
Detection detail page
- Show a detection with all its linked stories, data sources, MITRE techniques, macros, Story detail page - Show a story with all its member detections and their common traits, Relationship graph - Interactive node/edge graph showing connections between content
Should the tool live inside the eagle-eye/ directory of this repo?
Yes, eagle-eye/: anything temporary (we wouldn't push in a pull request) in eagle-eye/discard, anything that we would ship in a pull request (core & required files) in the eagle-eye/keep directory
Planned static HTML site with detection and story details
Great choices. Let me draft the plan.

Plan: Eagle Eye — Static Relationship Explorer
TL;DR: A single Python build script in keep parses all YAML content (detections, stories, data sources, macros), extracts relationships, and outputs a self-contained HTML file into discard. The HTML page embeds all data as JSON and provides three views: detection detail, story detail, and an interactive relationship graph — all running client-side with zero server dependencies.

Steps

Create the build script — eagle-eye/keep/build.py

Walk detections, stories, data_sources, macros and parse every .yml file with PyYAML.
For each detection, extract: name, id, status, type, description, data_source, tags.analytic_story, tags.mitre_attack_id, tags.cve, tags.security_domain, tags.asset_type, and macro references (regex for backtick-delimited names in search).
For each story, extract: name, id, description, narrative, tags.category, references.
For each data source, extract: name, id, source, sourcetype, supported_TA.
Build a relationship index:
detection → story (via tags.analytic_story matching story name)
detection → data source (via data_source matching data source name)
detection → MITRE technique (via tags.mitre_attack_id)
detection → macro (via backtick references in search)
Serialize the full content + relationship index as a JSON blob.
Inject the JSON into an HTML template (embedded in the script or loaded from a companion template file in keep/) and write the output to eagle-eye/discard/eagle-eye.html.
Create the HTML template — eagle-eye/keep/template.html

Single-page app with three tab-style views:
Detection Detail — Searchable/filterable list of detections on the left; selecting one shows its full metadata and linked stories, data sources, MITRE IDs, CVEs, and macros as clickable chips on the right. Clicking a linked story or data source navigates to its detail.
Story Detail — Searchable list of stories on the left; selecting one shows its description, narrative, and all member detections listed with their type, status, and MITRE coverage.
Relationship Graph — Interactive force-directed graph (using vis.js Network loaded from CDN) where nodes = detections/stories/data sources/MITRE techniques, edges = relationships. Color-coded by node type. Click a node to focus and see its connections. Search box to filter/focus on a specific entity.
Pure vanilla JS + CSS; the only external dependency is vis-network from CDN (single <script> tag). The data JSON is injected as const DATA = {...}; inline.
.gitignore-friendly: the generated file goes to discard/, so it won't be committed.
Add a .gitignore — eagle-eye/discard/.gitignore

Ignore everything in discard/ except the .gitignore itself, so generated output is never committed.
Add a README — eagle-eye/keep/README.md

Brief usage instructions: python eagle-eye/keep/build.py → open eagle-eye/discard/eagle-eye.html in a browser.
Document the dependency on PyYAML (already in requirements.txt).
Verification

Run python eagle-eye/keep/build.py from the repo root.
Confirm eagle-eye/discard/eagle-eye.html is generated.
Open the HTML file in a browser and verify:
Searching for "Child Processes of Spoolsv exe" shows the detection with links to "Data Destruction", "Hermetic Wiper", "Windows Privilege Escalation" stories, "Sysmon EventID 1" / "Windows Event Log Security 4688" / "CrowdStrike ProcessRollup2" data sources, and MITRE T1068.
Clicking "Data Destruction" story shows all its member detections.
The graph view shows the detection as a node connected to its stories, data sources, and techniques.
Decisions

Static HTML over Flask: No runtime server to manage; just regenerate when content changes.
vis-network via CDN: Lightweight, well-documented graph library; avoids bundling JS dependencies. Falls back gracefully if offline (graph tab disabled, list views still work).
Generated output in discard/: Keeps the repo clean while the build script and template in keep/ are PR-shippable.
PyYAML only: The repo already lists it in requirements.txt, so no new dependencies.
