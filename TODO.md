# TODO

## Completed

### Dashboard Foundation

* [x] Canonical `tools[]` dashboard schema
* [x] Home → Tool → Client navigation
* [x] Dynamic tool routing
* [x] Dynamic client routing
* [x] Tool pages
* [x] Client pages
* [x] Client drilldowns
* [x] Alert ID display
* [x] Jira Ticket ID display
* [x] Managed client registry
* [x] MSSP source tags
* [x] Reseller source tags
* [x] SentinelOne dashboard integration
* [x] SentinelOne Jira comparison
* [x] Greenko EDR exclusion
* [x] Tool-card homepage

---

## High Priority

### Wazuh Collector

Create:

collectors/wazuh.py

Responsibilities:

* Call WHB API
* Retrieve client alert counts
* Apply allowlist filtering
* Apply client mapping
* Normalize data
* Return comparison-ready output

Current source:

WHB API

Current endpoint:

https://whb.nopalcyber.com/api/v1/integrations/wazuh-alert-counts

Current parameters:

hours=24

Current threshold:

Rule Level >= 5

Status:

Not started

---

### Wazuh Jira Integration

Fetch:

Issue Type = Wazuh Alert

Client source:

Tenant Name

Requirements:

* Extract client names
* Apply mappings
* Produce comparison-ready Jira records

Status:

Not started

---

### Wazuh Comparator Integration

Integrate Wazuh into the existing comparison workflow.

Requirements:

* Reuse existing comparison behavior
* Reuse managed client framework where applicable
* Preserve tool-agnostic architecture

Status:

Not started

---

### Wazuh Dashboard Integration

Add Wazuh to:

latest.json

Requirements:

* Appear as a separate tool card
* Use existing navigation structure
* Require no UI redesign

Expected result:

Home
↓
SentinelOne

Wazuh

Status:

Not started

---

## Medium Priority

### Client Normalization Framework

Current issue:

Observed client names may differ from managed client names.

Example:

AM Green

vs

AM Green Ammonia Pvt Ltd

Future structure:

CLIENT_MAPPINGS = {
"sentinelone": {},
"wazuh": {}
}

Purpose:

* Prevent duplicate client identities
* Provide canonical client naming
* Improve dashboard consistency

Status:

Planned

---

### Generic Tool Schema

Continue migration toward fully normalized tool output.

Target structure:

{
"tool": "",
"client": "",
"count": 0,
"alerts": [],
"source": ""
}

Purpose:

* Simplify onboarding future tools
* Reduce vendor-specific logic

Status:

Planned

---

### Tool-Agnostic Comparator

Current comparator still contains SentinelOne-oriented assumptions.

Goal:

Comparator should operate entirely on normalized tool data.

Requirements:

* No vendor-specific branching
* Reusable across all tools

Status:

Planned

---

## Low Priority

### Dashboard Metrics

Add:

* Mismatch counts
* Equal counts
* Tool health summaries

Status:

Future

---

### Dashboard Visualizations

Potential additions:

* Alert trends
* Ticket trends
* Mismatch trends
* Tool summaries

Requirements:

* Home dashboard only
* Optional tool-level views

Status:

Future

---

### Teams Notifications

Workflow:

Mismatch
↓
Teams Notification

Requirements:

* Tool context
* Client context
* Count summary

Status:

Future

---

### Additional Tool Integrations

Potential future tools:

* Securonix
* Microsoft Defender
* CrowdStrike
* FortiAnalyzer

Requirements:

* Plug into existing architecture
* No dashboard redesign

Status:

Future

---

## Notes

Current active development focus:

1. Wazuh Collector ✅
2. Wazuh Jira Integration ✅
3. Wazuh Comparator ✅
4. Wazuh Dashboard Integration ✅
5. Timestamp display polish ✅

Do not redesign the dashboard unless explicitly requested.

Prefer extending the existing architecture over introducing new patterns.
