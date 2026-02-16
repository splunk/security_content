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

## Environments (Per-Detection Enablement Tracking)

Eagle Eye supports tracking per-detection enablement status across Splunk deployment environments. Each environment is a YAML sidecar file mapping detection UUIDs to a status: `done`, `now`, `blocked`, `later`, or `backlog`.

**Creating environments:**
- In the browser — click **+ New** in the header toolbar to create an environment, then click any enablement badge on a detection to set its status. Changes persist in `localStorage`.
- From a file — create a YAML file (see `environments/example.yml.template`) and place it in one of the search paths below.

**Environment file search order** (first match wins):
1. `--envs-dir <path>` CLI argument
2. `EAGLE_EYE_ENVS_DIR` environment variable
3. `eagle-eye/keep/environments/*.yml` (gitignored)
4. `~/.eagle-eye/envs/`

**Import / Export:** Use the **Import** and **Export** buttons in the header to move environments between the browser and YAML files on disk.

## AI Enrichment

Eagle Eye can send the current detection, story, data source, or MITRE technique context to an LLM for analysis. It works with any OpenAI-compatible API:

| Backend | Endpoint |
|---|---|
| Ollama | `http://localhost:11434/v1/chat/completions` |
| Docker Model Runner | `http://localhost:12434/engines/llama.cpp/v1/chat/completions` |
| OpenRouter | `https://openrouter.ai/api/v1/chat/completions` |

Click the **🤖 AI** button in the header to configure your endpoint, model, API key, and customize the prompt templates for each entity type.

Each detail panel (Detection, Story, Data Source, MITRE) has an **Ask AI** button that sends a context-rich prompt and streams the response. Follow-up questions maintain conversation context within the session.

> **Note:** AI features work most reliably when Eagle Eye is served by a local web server rather than opened directly as a `file://` page. Browsers restrict `fetch()` requests from `file://` origins, which can silently block calls to local AI endpoints. A simple solution:
>
> ```bash
> cd eagle-eye/discard
> python -m http.server 8080
> # Then open http://localhost:8080/eagle-eye.html
> ```

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

- **Detections** — Searchable/filterable list with enablement badges. Select a detection to see its description, linked analytic stories, data sources, MITRE techniques, CVEs, macros, enablement status, and AI analysis.
- **Stories** — Searchable/filterable list with enablement breakdown bars. Select a story to see its narrative, MITRE coverage, member detections, and enablement progress.
- **Data Sources** — Searchable list with enablement breakdown bars. Select a data source to see related stories, MITRE coverage, and detections.
- **MITRE** — Searchable list of techniques referenced by detections.
- **Matrix** — Full MITRE ATT&CK coverage matrix with gap analysis.
- **Graph** — Interactive ego-centric graph (powered by Cytoscape.js). Nodes are color-coded by type with enablement status rings. Search to focus on specific entities.

## File Layout

```
eagle-eye/
├── keep/                         # PR-shippable files
│   ├── build.py                  # Build script
│   ├── template.html             # HTML template
│   ├── README.md                 # This file
│   ├── eagle-eye.md              # Project overview
│   └── environments/
│       └── example.yml.template  # Documented env file example
└── discard/                      # Generated output (gitignored)
    ├── .gitignore
    └── eagle-eye.html            # Generated explorer (after build)
```

## Regenerating

Run the build script again any time the content changes. The output file goes to `discard/` and is excluded from git via `.gitignore`.
