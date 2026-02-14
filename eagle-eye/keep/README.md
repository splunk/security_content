# Eagle Eye — Security Content Explorer

A lightweight tool that parses all detection YAML files and generates a self-contained HTML page for exploring relationships between detections, analytic stories, data sources, and MITRE ATT&CK techniques.

## Quick Start

```bash
# From the repo root
python eagle-eye/keep/build.py
```

Then open `eagle-eye/discard/eagle-eye.html` in a browser.

## Requirements

- Python 3.8+
- PyYAML (`pip install pyyaml`) — already listed in the repo's `requirements.txt`

## What It Does

The build script walks four content directories:

| Directory | Content |
|---|---|
| `detections/` | Detection rules (search, data sources, MITRE mappings, analytic stories) |
| `stories/` | Analytic stories that group related detections |
| `data_sources/` | Telemetry source definitions |
| `macros/` | Search macros referenced by detections |

It extracts key fields and relationships, serializes them as JSON, and injects the result into `template.html` to produce a single self-contained HTML file.

## Views

- **Detections** — Searchable/filterable list. Select a detection to see its description, linked analytic stories, data sources, MITRE techniques, CVEs, and macros. Click a story chip to jump to that story.
- **Stories** — Searchable/filterable list. Select a story to see its narrative, MITRE coverage across member detections, and a clickable list of all detections in that story.
- **Graph** — Interactive force-directed graph (powered by vis-network via CDN). Nodes are color-coded by type. Search to focus on specific entities. Click a node for details.

## File Layout

```
eagle-eye/
├── keep/              # PR-shippable files
│   ├── build.py       # Build script
│   ├── template.html  # HTML template
│   ├── README.md      # This file
│   └── eagle-eye.md   # Project overview
└── discard/           # Generated output (gitignored)
    ├── .gitignore
    └── eagle-eye.html # Generated explorer (after build)
```

## Regenerating

Run the build script again any time the content changes. The output file goes to `discard/` and is excluded from git via `.gitignore`.
