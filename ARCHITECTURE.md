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

The architecture must remain generic and reusable.

---

# Current Architecture

Current implemented flow:

Tool Collector
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

The dashboard architecture is now tool-based rather than SentinelOne-specific.

---

# Implemented Features

## Canonical Dashboard Schema

Implemented:

```json
{
  "timestamp": "...",
  "tools": [
    {
      "tool": "SentinelOne",
      "tool_key": "sentinelone",
      "clients": [...]
    }
  ]
}
```

This schema is now the source of truth.

---

## Dashboard Navigation

Implemented:

Home Dashboard
↓
Tool Page
↓
Client Page

Routes:

/

/tool/{tool_name}

/tool/{tool_name}/client/{client_name}

The routing layer is reusable and supports future tools without requiring new pages.

---

## Managed Client Registry

Implemented.

Managed clients appear even when:

alert_count = 0
ticket_count = 0

Example:

CapLaw
Alerts: 0
Tickets: 0

This prevents managed clients from disappearing during inactive periods.

---

## Client Drilldowns

Implemented.

Client pages display:

* Alert IDs
* Jira Ticket IDs
* Alert counts
* Ticket counts

---

## Source Tags

Implemented.

Supported:

[MSSP]

[RESELLER]

These tags are displayed on tool pages.

---

# Current Tools

## SentinelOne

Status:

Fully integrated.

Sources:

* MSSP
* Reseller

Implemented:

* MSSP allowlist filtering
* Reseller exclusions
* Managed client registry
* Source tagging
* Jira comparison
* Dashboard integration
* Client drilldowns

Current exclusion:

Greenko-Energy-EDR

This exclusion must remain in place.

---

## Wazuh

Status:

Not yet integrated.

Current source:

WHB API

Endpoint:

https://whb.nopalcyber.com/api/v1/integrations/wazuh-alert-counts

Current parameters:

hours=24
limit=500

Current aggregation:

latest_per_client

Current threshold:

Rule Level >= 5

Current allowed clients:

* Progility
* NCC
* Rainbow_Children_Hospitals

Current mapping:

NCC → NCC-Bihar

Expected future architecture:

WHB API
↓
Wazuh Collector
↓
Normalized Wazuh Data
↓
Comparator
↓
Dashboard

---

# Current Dashboard Structure

## Page 1

/

Home Dashboard

Displays:

* Tool cards
* Total alerts
* Total tickets
* Future mismatch summaries
* Future charts
* Future KPIs

---

## Page 2

/tool/{tool_name}

Displays:

* Tool summary
* Tool counts
* Client list
* Source tags

Examples:

/tool/sentinelone

/tool/wazuh

---

## Page 3

/tool/{tool_name}/client/{client_name}

Displays:

* Alert IDs
* Jira Ticket IDs
* Alert counts
* Ticket counts

Examples:

/tool/sentinelone/client/QuisLex

/tool/wazuh/client/NCC-Bihar

---

# Design Philosophy

Collectors

Responsible for:

* Fetching data
* Filtering data
* Normalizing data

Collectors must not contain:

* UI logic
* Dashboard logic
* Routing logic

---

Comparator

Responsible only for:

* Grouping
* Comparison
* Result generation

Comparator must not:

* Call vendor APIs
* Render UI

---

Dashboard

Responsible only for:

* Presentation
* Navigation
* User interaction

Dashboard must not:

* Fetch vendor data directly
* Contain comparison logic
* Contain client mappings

---

Configuration

All configuration belongs in:

config.py

Avoid duplicating configuration elsewhere.

---

# Planned Work

Next milestone:

* Wazuh Collector
* Wazuh Jira Integration
* Wazuh Comparator
* Wazuh Dashboard Integration

Future milestones:

* Client normalization framework
* Dashboard visualizations
* Teams notifications
* Additional security tool integrations
