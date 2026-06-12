# ARCHITECTURE

## Overview

This project validates security alerts from security tools against Jira tickets.

The project originally started as:

SentinelOne ↔ Jira

and is evolving into:

Tool ↔ Jira

where a Tool may include:

* SentinelOne
* Wazuh
* Securonix
* Microsoft Defender
* CrowdStrike
* Future security platforms

The architecture should remain generic and reusable.

---

# Current Architecture

Current flow:

SentinelOne Collector
↓
Jira Collector
↓
Comparator
↓
latest.json
↓
FastAPI API
↓
Dashboard UI

Current implementation is SentinelOne-focused.

The multi-tool architecture has not yet been fully implemented.

---

# Current Tools

## SentinelOne

Sources:

* MSSP
* Reseller

Current status:

Fully integrated.

Features:

* MSSP allowlist filtering
* Reseller exclusions
* Greenko EDR exclusion
* Jira comparison
* Dashboard integration

---

## Wazuh

Source:

WHB API

Current endpoint:

https://whb.nopalcyber.com/api/v1/integrations/wazuh-alert-counts

Current filters:

hours=24

min_rule_level=5

Aggregation:

latest_per_client

Current status:

Integration in progress.

Current allowed clients:

* Progility
* NCC
* Rainbow_Children_Hospitals

Current client mapping:

NCC → NCC-Bihar

---

# Future Architecture

Target flow:

Tool Collector
↓
Normalized Tool Data
↓
Jira Collector
↓
Comparator
↓
Dashboard JSON
↓
FastAPI API
↓
Dashboard UI

Each tool should normalize its vendor-specific data before comparison.

The comparator should remain tool-agnostic.

---

# Dashboard Navigation

## Page 1

/

Home Dashboard

Purpose:

Provide a high-level overview of all integrated tools.

Displays:

* Tool cards
* Total alerts
* Total tickets
* Mismatch summary
* Future charts
* Future KPIs
* Future health summaries

Example:

SentinelOne

Wazuh

Securonix

Clicking a tool navigates to:

/tool/{tool_name}

---

## Page 2

/tool/{tool_name}

Purpose:

Display information for a single tool.

Examples:

/tool/sentinelone

/tool/wazuh

/tool/securonix

Displays:

* Tool summary
* Total alerts
* Total tickets
* Client list
* Future tool-level visualizations

Clicking a client navigates to:

/tool/{tool_name}/client/{client_name}

---

## Page 3

/tool/{tool_name}/client/{client_name}

Purpose:

Display client-level details.

Examples:

/tool/sentinelone/client/quislex

/tool/wazuh/client/ncc-bihar

Displays:

* Alert IDs
* Jira Ticket IDs
* Counts
* Future drilldowns

---

# Routing Philosophy

Use reusable dynamic routes.

Preferred:

/tool/{tool_name}

/tool/{tool_name}/client/{client_name}

Avoid:

/sentinelone

/wazuh

/securonix

The UI should automatically support future tools without requiring new pages.

---

# Current JSON Structure

Current:

{
"clients": [...]
}

Current dashboard implementation consumes a client-based structure.

---

# Future JSON Structure

Target:

{
"tools": [
{
"tool": "SentinelOne",
"total_alerts": 0,
"total_tickets": 0,
"clients": [...]
}
]
}

This migration has not yet been completed.

The future dashboard should consume tool-based data rather than client-based data.

---

# Normalized Tool Schema

Target collector output:

{
"tool": "",
"client": "",
"count": 0,
"alerts": [],
"source": ""
}

This schema is a target architecture and has not yet been fully implemented.

Current SentinelOne collectors still use their existing structures.

Reason:

* Allows comparison logic to remain tool-agnostic.
* Allows future tools to plug into the same workflow.
* Prevents vendor-specific logic from leaking into shared code.

Collectors should handle vendor-specific data conversion.

Comparator should not require vendor-specific logic.

---

# Design Philosophy

Collectors:

Responsible for:

* Fetching data
* Filtering data
* Normalizing data

Collectors should not contain:

* Dashboard logic
* UI logic
* Routing logic

---

Comparator:

Responsible only for comparison.

Comparator should not:

* Call vendor APIs
* Render UI
* Contain dashboard logic

---

Dashboard:

Responsible only for presentation.

Dashboard should not:

* Fetch vendor data directly
* Contain client mappings
* Implement comparison logic

---

Configuration:

Should live in:

config.py

Avoid duplicating configuration elsewhere.

---

# Current UI

Technology:

* FastAPI
* HTML
* CSS
* Vanilla JavaScript

Current dashboard:

Client
├─ Alert IDs
└─ Jira Ticket IDs

The current UI is operational and should remain functional until the navigation refactor is implemented.

---

# Planned UI

Home Dashboard
↓
Tool Page
↓
Client Page

Home Dashboard:

* Tool cards
* Total alerts
* Total tickets
* Mismatch summary
* Future charts
* Future KPIs

Tool Page:

* Tool summary
* Client list

Client Page:

* Alert IDs
* Jira Ticket IDs
* Counts

This navigation architecture has not yet been implemented.

---

# Future Features

Planned:

* Wazuh integration
* Tool-level dashboards
* Dashboard visualizations
* Teams notifications
* Additional security tool integrations

The architecture should support these features without requiring major redesign.
