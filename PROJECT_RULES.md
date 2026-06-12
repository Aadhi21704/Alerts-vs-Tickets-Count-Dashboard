# PROJECT RULES

## Purpose

This project validates security alerts against Jira tickets.

The project originally started as:

SentinelOne ↔ Jira

and is evolving into:

Tool ↔ Jira

where a Tool can be:

* SentinelOne
* Wazuh
* Securonix
* Microsoft Defender
* CrowdStrike
* FortiAnalyzer
* Future security platforms

The architecture must remain generic and reusable for future security tools.

---

## Critical Development Rules

### Rule 1

Do not redesign working code unless explicitly requested.

Prefer minimal, targeted changes.

Avoid large rewrites.

---

### Rule 2

Before modifying multiple files, analyze first and provide:

1. Files to modify
2. Reason for modification
3. Risks
4. Proposed implementation plan

Wait for approval before applying changes.

---

### Rule 3

Current stack:

* FastAPI
* HTML
* CSS
* Vanilla JavaScript

Do not introduce:

* Django
* Streamlit
* React
* New frontend frameworks

unless explicitly requested.

---

### Rule 4

Do not hardcode client-specific logic outside config.py.

The following belong in config.py:

* Client allowlists
* Client exclusions
* Client mappings
* Tool-specific configuration

---

### Rule 5

Preserve backward compatibility whenever possible.

Avoid breaking existing dashboard functionality.

---

### Rule 6

Collectors must not contain UI logic.

UI must not contain collector logic.

Comparator must not contain API calls.

Maintain separation of concerns.

---

## Dashboard Rules

### Current Direction

The dashboard is evolving into a multi-page monitoring platform.

Do not assume the dashboard will remain a single page.

---

### Required Navigation Structure

Page 1:

/

Home Dashboard

Displays:

* Tool cards
* Total alerts
* Total tickets
* Mismatch summary
* Future charts
* Future KPIs

Clicking a tool navigates to:

/tool/{tool_name}

---

Page 2:

/tool/{tool_name}

Displays:

* Tool summary
* Client list
* Tool-level metrics

Clicking a client navigates to:

/tool/{tool_name}/client/{client_name}

---

Page 3:

/tool/{tool_name}/client/{client_name}

Displays:

* Alert IDs
* Jira Ticket IDs
* Client counts
* Future drilldowns

---

### Routing Rules

Use reusable dynamic routes.

Preferred structure:

/tool/{tool_name}

/tool/{tool_name}/client/{client_name}

Examples:

/tool/sentinelone

/tool/wazuh

/tool/securonix

Do not create separate hardcoded pages for each tool.

The UI must automatically support new tools.

---

### Visualization Rules

Future charts and visualizations belong on:

Home Dashboard

and optionally:

Tool pages

Do not design charts at the client level.

---

## SentinelOne Rules

### MSSP

Uses allowlist filtering.

Allowed clients are configured in:

MSSP_ALLOWED_CLIENTS

---

### Reseller

Does NOT use allowlist filtering.

Only exclusions should be used.

---

### Greenko

Greenko-Energy-EDR must always be excluded.

Reason:

Only MDR is managed.

EDR alerts do not generate Jira tickets.

This exclusion currently exists in:

RESSELLER_EXCLUDED_CLIENTS

Do not remove unless explicitly requested.

---

## Wazuh Rules

Current allowed clients:

* Progility
* NCC
* Rainbow_Children_Hospitals

Current mapping:

NCC → NCC-Bihar

Rainbow_Children_Hospitals → Rainbow_Children_Hospitals

Rainbow may not appear in data until WHB deployment is completed.

This is expected.

Do not create placeholder clients.

---

### Wazuh Data Source

Current source:

WHB API

Current endpoint:

https://whb.nopalcyber.com/api/v1/integrations/wazuh-alert-counts

Current aggregation:

latest_per_client

Current severity threshold:

Rule Level >= 5

Do not change these assumptions unless explicitly requested.

---

## Jira Rules

### SentinelOne

Issue Type = SentinelOne

Client information is extracted from the Site Name field in the Jira description table.

---

### Wazuh

Issue Type = Wazuh Alert

Client information comes from Tenant Name.

---

## Alert Relationship

For all currently supported tools:

1 Alert = 1 Jira Ticket

This assumption is critical to comparison logic.

Do not introduce aggregation logic unless explicitly requested.

---

## Future Architecture

All tools should eventually be normalized into a common schema.

Preferred structure:

{
"tool": "",
"client": "",
"count": 0,
"alerts": [],
"source": ""
}

Collectors should normalize vendor-specific data.

Comparators should remain tool-agnostic.

---

## Future Direction

Current goal:

Monitor alert counts versus Jira ticket counts.

Future goals:

* Teams notifications
* Additional tools
* Tool-level dashboards
* Dashboard visualizations

Do not implement future features unless explicitly requested.

---

## Security

Never commit:

* .env
* API tokens
* Secrets
* Credentials

Never expose credentials in logs.

Never hardcode credentials in source code.

---

## AI Assistant Rules

When working on this repository:

* Read PROJECT_RULES.md
* Read ARCHITECTURE.md
* Read TODO.md
* Read CODING_GUIDELINES.md
* Read PROJECT_STRUCTURE.md

before proposing significant changes.

Architecture decisions documented in those files take precedence over assumptions.
