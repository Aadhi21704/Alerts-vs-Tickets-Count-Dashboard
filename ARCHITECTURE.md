# ARCHITECTURE

## Overview

This project collects alerts from security tools and validates that corresponding Jira tickets exist.

Current flow:

Tool Collector
↓
Normalized Data
↓
Comparator
↓
Dashboard JSON
↓
Dashboard UI

---

# Current Tools

## SentinelOne

Sources:

* MSSP
* Reseller

Current status:

Fully integrated.

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

---

# Dashboard Hierarchy

Target hierarchy:

Tool
├─ Clients
│   ├─ Alert IDs
│   └─ Jira Ticket IDs

Example:

SentinelOne
├─ QuisLex
├─ NopalCyber

Wazuh
├─ Progility
├─ NCC-Bihar

---

# Current JSON Structure

Current:

{
"clients": [...]
}

---

# Future JSON Structure

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

---

# Normalized Tool Schema

All tools should eventually return normalized data.

Preferred structure:

{
"tool": "",
"client": "",
"count": 0,
"alerts": [],
"source": ""
}

Reason:

Allows comparison logic to remain tool-agnostic.

Collectors should handle vendor-specific data conversion.

Comparator should not need vendor-specific logic.

---

# Design Philosophy

Collectors:

Responsible for gathering and normalizing data.

Comparator:

Responsible only for comparison.

Dashboard:

Responsible only for presentation.

Keep these concerns separated.

---

# Current UI

FastAPI
HTML
CSS
Vanilla JavaScript

Current UI shows:

Client
├─ Alert IDs
└─ Jira Ticket IDs

---

# Planned UI

Tool
├─ Total Alerts
├─ Total Tickets
└─ Clients

Example:

SentinelOne
├─ Total Alerts
├─ Total Tickets
└─ Clients

Wazuh
├─ Total Alerts
├─ Total Tickets
└─ Clients

The UI refactor has not yet been completed.
