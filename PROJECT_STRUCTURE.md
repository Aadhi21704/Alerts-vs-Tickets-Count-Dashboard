# PROJECT STRUCTURE

## Overview

This project validates security alerts against Jira tickets.

Architecture:

Tool Collectors
↓
Comparator
↓
Dashboard Schema
(latest.json)
↓
FastAPI
↓
Dashboard UI

Responsibilities must remain clearly separated.

---

# Root Directory

## config.py

Purpose:

Centralized project configuration.

Contains:

* API endpoints
* Tool settings
* Allowlists
* Exclusions
* Exact client mappings, including `SENTINELONE_CLIENT_MAPPING`
* Managed client registries
* Jira configuration

Must not contain:

* Collection logic
* Dashboard logic
* API calls

---

## run.py

Purpose:

Main collection orchestration.

Responsibilities:

* Run collectors
* Run Jira collection
* Run comparison
* Build dashboard schema
* Write latest.json

Must not contain:

* UI logic
* Template logic

---

## scheduler.py

Purpose:

Scheduled execution.

Responsibilities:

* Trigger run.py
* Control execution intervals

Must not contain:

* Collection logic
* Comparison logic
* UI logic

---

## latest.json

Purpose:

Canonical dashboard data source.

Current structure:

```json id="eywd2r"
{
  "timestamp": "",
  "tools": []
}
```

All dashboard pages consume data derived from this file.

---

# collectors/

Purpose:

Tool-specific data collection.

Responsibilities:

* API communication
* Data retrieval
* Filtering
* Mapping
* Normalization

Examples:

```text id="a3rjpb"
collectors/
├─ sentinelone.py
├─ wazuh.py
├─ securonix.py
```

Collectors must not:

* Render UI
* Compare data
* Generate dashboard output

---

## collectors/sentinelone.py

Purpose:

Collect SentinelOne alerts.

Sources:

* MSSP
* Reseller

Responsibilities:

* Fetch alerts
* Apply filtering
* Normalize record shape
* Preserve raw SentinelOne client names

---

## collectors/wazuh.py

Purpose:

Collect Wazuh alert data.

Source:

WHB API

Responsibilities:

* Fetch Wazuh data
* Apply allowlists
* Apply mappings
* Normalize records

Status:

Fully integrated

---

## collectors/securonix.py

Purpose:

Collect Securonix incidents.

Source:

Securonix SNYPR API

Responsibilities:

* Call `/ws/incident/get`
* Authenticate with WS token header `token`
* Query opened incidents in the configured 24-hour window
* Apply allowed-client filtering
* Normalize safe incident evidence records
* Exclude sensitive Securonix fields

Sensitive fields that must not be stored:

* `violatorText`
* `violatorId`
* `solrquery`

Status:

Fully integrated

---

# comparison/

Purpose:

Alert-to-ticket comparison.

Responsibilities:

* Compare tool alerts
* Compare Jira tickets
* Generate statuses
* Generate client comparison results

Must not:

* Call APIs
* Render UI
* Read templates

---

## comparison/comparator.py

Purpose:

Comparison engine.

Current responsibilities:

* Alert counts
* Ticket counts
* Client status
* Source aggregation
* Exact SentinelOne alias normalization before grouping
* Raw Securonix incident-list comparison

`compare_data()` accepts the configured SentinelOne client mapping. It applies
the same exact mapping to alert and Jira records before grouping them under a
canonical client name.

Collectors do not own or duplicate this alias mapping.

Future goal:

Remain tool-agnostic.

---

# app/

Purpose:

Dashboard application.

Contains:

* FastAPI routes
* Template rendering
* Dashboard presentation

Must not:

* Call vendor APIs directly
* Perform collection logic

---

## app/main.py

Purpose:

FastAPI entry point.

Responsibilities:

* Route handling
* Dashboard data loading
* Context preparation
* Template rendering

Current routes:

```text id="ctt9vk"
/                          Home Dashboard
/tool/{tool_name}          Tool Dashboard
/tool/{tool_name}/client/{client_name}
                           Client Dashboard
/api/dashboard             Canonical read-only dashboard API
/api/data                  Deprecated legacy compatibility API
/api/update                Disabled; returns HTTP 405
/health
```

Display-only transformations, including deltas and evidence ordering, are
prepared in context builders before template rendering.

---

# app/templates/

Purpose:

Dashboard HTML templates.

Templates should remain generic.

Current templates:

```text id="4f24qv"
dashboard.html
tool.html
client.html
```

These are the active server-rendered UI pages.

Responsibilities:

* Presentation
* Layout
* Display

Must not contain:

* Business logic
* Collection logic
* Comparison logic

---

## dashboard.html

Purpose:

Homepage.

Displays:

* Overall reconciliation status
* Alert and ticket totals
* Priority mismatch
* Tool health cards

---

## tool.html

Purpose:

Tool-level dashboard.

Displays:

* Tool status and totals
* Client reconciliation list
* Source tags
* Client investigation links

---

## client.html

Purpose:

Client drilldown page.

Displays:

* Alert counts
* Ticket counts
* Alert IDs
* Jira Ticket IDs
* Display-only evidence alignment

---

# app/static/

Purpose:

Frontend assets.

Contains:

* CSS

Current files:

```text id="1a1vbt"
style.css
```

---

## style.css

Purpose:

Dashboard styling.

Responsibilities:

* Dashboard, tool, and client page styling
* SOC status presentation
* Cards and evidence panels
* Navigation styling
* Responsive behavior

---

## app.js

Removed.

The active UI is server-rendered and no template references `app.js`. Do not
reintroduce it without a clear requirement.

---

# logs/

Purpose:

Application logs.

Contains:

* Collection logs
* Runtime logs
* Error logs

Must never contain:

* Secrets
* Credentials
* Tokens

---

# Future Structure

Expected future additions:

```text id="84trxt"
collectors/
├─ sentinelone.py
├─ wazuh.py
├─ defender.py
```

The architecture should scale by adding new collectors rather than redesigning existing folders.

---

# Ownership Rules

Collectors

Responsible for:

* Data collection
* Data normalization

---

Comparator

Responsible for:

* Alert vs ticket comparison

---

FastAPI

Responsible for:

* Routing
* Context generation
* Template rendering

---

Templates

Responsible for:

* Presentation only

---

Static Assets

Responsible for:

* Styling
* Frontend behavior

---

Configuration

Responsible for:

* All environment-specific settings
* Client metadata
* Tool metadata

---

Keep responsibilities separated.

Do not move functionality across layers without explicit architectural justification.
