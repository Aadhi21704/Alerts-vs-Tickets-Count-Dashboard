# PROJECT STRUCTURE

## Purpose

This project validates security alerts from multiple security tools against Jira tickets.

The architecture is evolving from:

SentinelOne ↔ Jira

to:

Tool ↔ Jira

where Tool may include:

* SentinelOne
* Wazuh
* Securonix
* Microsoft Defender
* CrowdStrike
* Future security platforms

The architecture should remain generic and reusable.

---

# Current Structure

config.py

Purpose:

Centralized configuration.

Contains:

* URLs
* Refresh intervals
* Allowlists
* Exclusions
* Client mappings
* Tool-specific configuration

---

collectors/

Purpose:

Fetch and normalize tool data.

Responsibilities:

* API calls
* Data collection
* Filtering
* Data normalization

Examples:

collectors/sentinelone.py

collectors/wazuh.py

Future:

collectors/securonix.py

collectors/defender.py

---

comparison/

Purpose:

Compare tool data against Jira data.

Responsibilities:

* Group data
* Compare counts
* Build comparison results

Should eventually become tool-agnostic.

---

app/

Purpose:

Dashboard application.

Contains:

* FastAPI routes
* Dashboard endpoints
* Frontend serving

---

app/static/

Purpose:

Frontend assets.

Contains:

* CSS
* JavaScript

Responsibilities:

* Rendering
* Navigation
* User interaction

Must not contain:

* API collection logic
* Client mappings
* Business rules

---

app/templates/

Purpose:

Frontend templates.

Contains:

* HTML templates

Responsibilities:

* Layout
* Page structure

---

run.py

Purpose:

Main collection orchestrator.

Responsibilities:

* Execute collectors
* Execute Jira collection
* Execute comparison
* Generate dashboard data

---

scheduler.py

Purpose:

Scheduled execution.

Responsibilities:

* Trigger dashboard refreshes
* Run collection jobs on schedule

---

latest.json

Purpose:

Dashboard data output.

Acts as the current dashboard data source.

Generated automatically.

Should never contain secrets.

Should never be committed.

---

logs/

Purpose:

Application logging.

Contains:

* Dashboard logs
* Collection logs
* Error logs

Should never contain secrets.

---

# Current Data Flow

Tool Collector
↓
Normalized Tool Data
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

---

# Current Dashboard

Current implementation:

Single-page dashboard.

Displays:

* Client list
* Alert counts
* Ticket counts
* Alert IDs
* Jira Ticket IDs

---

# Future Dashboard Structure

The dashboard is moving toward a multi-page architecture.

---

Page 1

/

Home Dashboard

Displays:

* Tool cards
* Total alerts
* Total tickets
* Mismatch summary
* Future charts
* Future KPIs

Examples:

SentinelOne

Wazuh

Securonix

---

Page 2

/tool/{tool_name}

Examples:

/tool/sentinelone

/tool/wazuh

/tool/securonix

Displays:

* Tool summary
* Tool counts
* Client list
* Future tool-level visualizations

---

Page 3

/tool/{tool_name}/client/{client_name}

Examples:

/tool/sentinelone/client/quislex

/tool/wazuh/client/ncc-bihar

Displays:

* Alert IDs
* Jira Ticket IDs
* Client-level counts
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

The UI should automatically support future tools.

---

# Current Schema

Current dashboard structure:

{
"clients": [...]
}

---

# Future Schema

Target structure:

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

This schema should support any future tool without requiring UI redesign.

---

# Normalized Tool Schema

Preferred collector output:

{
"tool": "",
"client": "",
"count": 0,
"alerts": [],
"source": ""
}

Reason:

Allows collectors to normalize vendor-specific data before comparison.

The comparator should not need vendor-specific knowledge.

---

# Responsibility Rules

Collectors must not:

* Modify UI
* Render HTML
* Implement dashboard routing

---

Comparator must not:

* Call vendor APIs
* Render UI
* Contain dashboard logic

---

Dashboard must not:

* Fetch vendor data directly
* Contain client mappings
* Implement comparison logic

---

Configuration must live in:

config.py

and not be duplicated elsewhere.

---

# Future Features

Planned:

* Wazuh integration
* Tool-level dashboards
* Dashboard visualizations
* Teams notifications
* Additional security tool integrations

The architecture should support these features without major redesign.
