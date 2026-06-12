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
* Client mappings
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
* Normalize records

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

Planned / In Progress

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
/api/data
/health
```

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

* Tool cards
* Tool summaries
* Future KPIs
* Future charts

---

## tool.html

Purpose:

Tool-level dashboard.

Displays:

* Tool counts
* Client list
* Source tags

---

## client.html

Purpose:

Client drilldown page.

Displays:

* Alert counts
* Ticket counts
* Alert IDs
* Jira Ticket IDs

---

# app/static/

Purpose:

Frontend assets.

Contains:

* CSS
* JavaScript

Current files:

```text id="1a1vbt"
style.css
app.js
```

---

## style.css

Purpose:

Dashboard styling.

Responsibilities:

* Layout
* Cards
* Navigation styling
* Responsive behavior

---

## app.js

Purpose:

Frontend interactions.

Current responsibilities:

* Dashboard refresh
* Client expansion behavior
* Data rendering

Future responsibilities:

* Dashboard enhancements
* Visualization support

Avoid placing business logic here.

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
├─ securonix.py
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
