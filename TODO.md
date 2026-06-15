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
* [x] Wazuh collector integration
* [x] Wazuh Jira integration
* [x] Wazuh comparator integration
* [x] Wazuh dashboard integration
* [x] UI Phase 1 polished homepage
* [x] UI Phase 2 polished tool and client pages
* [x] Client evidence display ordering

### Application Cleanup

* [x] Stop tracking Python cache files
* [x] Lock down `/api/update` with HTTP 405
* [x] Remove unused `app/static/app.js`
* [x] Keep `/api/data` as deprecated legacy compatibility
* [x] Add canonical read-only `/api/dashboard`

---

## Completed Wazuh Work

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

Completed

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

Completed

---

### Wazuh Comparator Integration

Integrate Wazuh into the existing comparison workflow.

Requirements:

* Reuse existing comparison behavior
* Reuse managed client framework where applicable
* Preserve tool-agnostic architecture

Status:

Completed

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

Completed

---

## Medium Priority

### React Migration Planning

Plan a future frontend migration using:

`GET /api/dashboard`

Requirements:

* Preserve current routes during migration
* Do not use deprecated `/api/data`
* Keep the canonical `tools[]` schema

Status:

Planned

---

### Auto-Refresh Strategy

Define a low-risk refresh approach for the current server-rendered pages and
any future React frontend.

Status:

Planned

---

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

### Optional Charts and UI Polish

Potential additions:

* Small trend charts
* Additional responsive polish
* Optional tool-level visual summaries

Charts must remain optional and must not replace the status-first dashboard
design.

Status:

Future

---

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

Completed development milestones:

1. Wazuh Collector ✅
2. Wazuh Jira Integration ✅
3. Wazuh Comparator ✅
4. Wazuh Dashboard Integration ✅
5. Timestamp display polish ✅

Current active development focus:

1. Stable dashboard release `dashboard-ui-v1.1`
2. React migration planning
3. Auto-refresh strategy
4. Client normalization improvements
5. Optional charts and polish

Do not replace the stable dashboard unless explicitly requested.

Prefer extending the existing architecture over introducing new patterns.
