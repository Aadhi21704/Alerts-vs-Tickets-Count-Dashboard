# TODO

## High Priority

### Dashboard Schema Refactor

Current:

clients

Future:

tools → clients

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

Reason:

The dashboard is evolving from a SentinelOne-specific dashboard into a generic Tool-vs-Jira dashboard.

Status:

Not started.

---

### Dashboard Navigation Refactor

Current:

Single page dashboard.

Future:

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

↓

Page 2:

/tool/{tool_name}

Displays:

* Tool summary
* Client list

↓

Page 3:

/tool/{tool_name}/client/{client_name}

Displays:

* Alert IDs
* Jira Ticket IDs
* Client-level counts

Status:

Not started.

---

### Dynamic Tool Routing

Implement reusable routing.

Preferred routes:

/tool/{tool_name}

/tool/{tool_name}/client/{client_name}

Examples:

/tool/sentinelone

/tool/wazuh

/tool/securonix

Do not create hardcoded pages for each tool.

Status:

Not started.

---

### Wazuh Collector

Create:

collectors/wazuh.py

Responsibilities:

* Call WHB API
* Apply allowlist filtering
* Apply client mapping
* Normalize data

Current endpoint:

https://whb.nopalcyber.com/api/v1/integrations/wazuh-alert-counts

Current filters:

hours=24
min_rule_level=5

Status:

Not started.

---

### Wazuh Jira Integration

Fetch:

Issue Type = Wazuh Alert

Client source:

Tenant Name

Map Jira tickets to Wazuh clients.

Status:

Not started.

---

### Wazuh Comparator

Compare:

Wazuh alerts ↔ Jira tickets

Maintain the same comparison behavior currently used for SentinelOne.

Status:

Not started.

---

## Medium Priority

### Common Tool Schema

All collectors should return normalized structures.

Preferred structure:

{
"tool": "",
"client": "",
"count": 0,
"alerts": [],
"source": ""
}

Reason:

Allows all future tools to plug into the same comparison engine.

Status:

Planned.

---

### Generic Client Mapping Framework

Current:

WAZUH_CLIENT_MAPPING

Future:

CLIENT_MAPPINGS = {
"wazuh": {...},
"sentinelone": {...},
"securonix": {...}
}

Status:

Planned.

---

### Tool-Agnostic Comparator

Current:

Comparator is SentinelOne-oriented.

Future:

Comparator operates on normalized tool data regardless of vendor.

Status:

Planned.

---

## Future

### Dashboard Visualizations

Potential additions:

* Tool-level charts
* Alert trends
* Ticket trends
* Mismatch trends
* Tool health summaries

Charts should live on the Home Dashboard page.

Do not design charts at client level.

Status:

Future.

---

### Teams Notifications

When mismatches occur:

Mismatch
↓
Teams Notification

Status:

Future.

---

### Additional Tool Integrations

Potential future tools:

* Securonix
* Microsoft Defender
* CrowdStrike
* FortiAnalyzer
* Other security platforms

Status:

Future.

---

### Alert ID Drilldowns

Current:

Count comparison is sufficient.

Future:

Display alert IDs when available.

Example:

SentinelOne:

* Already available

Wazuh:

* Waiting for WHB API enhancement

Status:

Future.
