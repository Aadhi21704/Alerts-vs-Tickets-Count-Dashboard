# CODING GUIDELINES

## General Principles

* Make the smallest change possible.
* Do not rewrite working code.
* Do not reformat unrelated files.
* Preserve existing code style.
* Prefer incremental improvements over large refactors.
* Avoid introducing unnecessary complexity.

---

## Before Making Changes

Always provide:

1. Files to modify
2. Reason for modification
3. Risks
4. Proposed implementation plan

For multi-file changes, wait for approval before modifying code.

---

## Development Philosophy

The project is actively evolving.

Prioritize:

1. Stability
2. Maintainability
3. Scalability
4. Speed of implementation

Avoid premature optimization.

Avoid building functionality that is not currently required.

---

## Architecture Rules

Maintain separation of concerns.

### Collectors

Collectors are responsible only for:

* Fetching data
* Filtering data
* Normalizing data

Collectors must not:

* Render UI
* Generate HTML
* Perform dashboard presentation logic
* Contain routing logic

---

### Comparator

Comparator is responsible only for:

* Comparing tool data against Jira data
* Producing comparison results

Comparator must not:

* Call APIs
* Render UI
* Contain vendor-specific API logic

The long-term goal is a tool-agnostic comparator.

---

### Dashboard

Dashboard is responsible only for:

* Displaying information
* Navigation
* User interaction

Dashboard must not:

* Perform data collection
* Contain API-specific logic
* Contain client mappings
* Contain filtering rules

---

### Configuration

All configuration belongs in config.py.

Examples:

* URLs
* Thresholds
* Client allowlists
* Client exclusions
* Client mappings
* Refresh intervals

Do not hardcode configuration values elsewhere.

---

## Frontend Guidelines

### Current Stack

* FastAPI
* HTML
* CSS
* Vanilla JavaScript

Do not introduce:

* React
* Vue
* Angular
* Django
* Streamlit

unless explicitly requested.

---

### Future Navigation Structure

Design frontend code with the following structure in mind:

Page 1:

/

Home Dashboard

↓

Page 2:

/tool/{tool_name}

↓

Page 3:

/tool/{tool_name}/client/{client_name}

Code should support dynamic routing and reusable rendering.

Avoid tool-specific UI implementations.

---

### Reusable UI Components

Prefer reusable rendering logic.

Avoid:

if tool == "sentinelone":
...

if tool == "wazuh":
...

Instead design generic rendering where possible.

Future tools should work with minimal UI changes.

---

### Dashboard Visualizations

Future charts and visualizations should live:

* Home Dashboard
* Tool Pages

Do not build client-level charts unless explicitly requested.

---

## Data Schema Guidelines

The project is moving toward a normalized tool schema.

Preferred structure:

{
"tool": "",
"client": "",
"count": 0,
"alerts": [],
"source": ""
}

Collectors should normalize vendor-specific data into this structure.

Avoid tool-specific data structures leaking into shared code.

---

## SentinelOne Guidelines

### MSSP

Uses allowlist filtering.

Controlled through:

MSSP_ALLOWED_CLIENTS

---

### Reseller

Does not use allowlist filtering.

Uses exclusions only.

---

### Greenko

Greenko-Energy-EDR must remain excluded.

Reason:

Only MDR is managed.

EDR alerts do not generate Jira tickets.

Current exclusion:

RESSELLER_EXCLUDED_CLIENTS

Do not remove unless explicitly requested.

---

## Wazuh Guidelines

Current allowed clients:

* Progility
* NCC
* Rainbow_Children_Hospitals

Current mapping:

NCC → NCC-Bihar

Rainbow deployment may not yet exist.

Do not create placeholder entries.

---

### Wazuh Source

Current source:

WHB API

Current assumptions:

* latest_per_client aggregation
* Rule Level >= 5
* 24 hour window

Do not change these assumptions without approval.

---

## Logging Guidelines

Preserve useful logging.

Do not remove logging without approval.

Prefer structured logging over ad-hoc debugging.

Avoid unnecessary console output.

---

## Error Handling Guidelines

Do not silently swallow exceptions unless explicitly justified.

Prefer:

* Clear error messages
* Logged failures
* Safe fallbacks

Avoid hiding failures.

---

## Security Guidelines

Never:

* Commit .env
* Commit credentials
* Commit API tokens
* Expose secrets in logs
* Hardcode credentials

Sensitive information must always come from environment variables.

---

## Git Workflow

Before significant changes:

Create a feature branch.

Example:

git checkout -b feature/tool-dashboard

Work should be grouped into focused commits.

Avoid mixing unrelated changes in a single commit.

---

## AI Assistant Workflow

When working on this repository:

1. Read:

   * PROJECT_RULES.md
   * ARCHITECTURE.md
   * TODO.md
   * CODING_GUIDELINES.md
   * PROJECT_STRUCTURE.md

2. Analyze before modifying.

3. Explain the implementation plan.

4. Make the smallest necessary change.

5. Preserve existing functionality.

Architecture decisions documented in project documentation take precedence over assumptions.
