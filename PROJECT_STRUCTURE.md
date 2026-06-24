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

`latest.json` is generated runtime output from `run.py`. It must not be
manually edited or committed.

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
├─ microsoft_sentinel.py
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
* Preserve safe SentinelOne source identifiers for exact-ID correlation

Safe SentinelOne evidence includes:

* Source alert ID
* SentinelOne threat ID
* Threat URL ID when present
* Threat name and timestamps as supporting metadata only, not match keys

Collectors must not store raw SentinelOne payloads in dashboard output.

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
* Preserve safe grouped WHB `by_rule[]` evidence for managed clients

Wazuh source evidence:

* `by_rule[].id` is exposed as `sample_alert_id`
* `sample_alert_id` is representative grouped evidence and must not be treated
  as every individual alert ID when the grouped rule `count` is greater than 1
* Safe fields are sample alert ID, rule ID, count, level, location, and
  description
* Raw `full_log`, `data`, or raw payload fields must not be stored in dashboard
  output

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
* Preserve safe Securonix source identifiers for exact-ID correlation
* Exclude sensitive Securonix fields

Safe Securonix source evidence includes:

* `id` / `securonix_incident_id`
* `securonix_incident_url`
* Created and updated timestamps as supporting metadata only, not match keys
* Status, priority, risk score, and incident type as supporting metadata only,
  not match keys

Sensitive fields that must not be stored:

* `violatorText`
* `violatorId`
* `solrquery`

Status:

Fully integrated

---

## collectors/microsoft_sentinel.py

Purpose:

Collect Microsoft Sentinel incidents.

Current enabled client:

* ContractPodAi / CPAi

Responsibilities:

* Request Azure Management API tokens with client credentials
* Cache and refresh tokens per configured client
* Query Microsoft SecurityInsights incidents for the configured 24-hour window
* Use `$top=1000`
* Follow `nextLink` pagination
* Normalize safe incident records
* Preserve safe Microsoft Sentinel identifiers for exact-ID correlation

Safe Microsoft Sentinel source evidence includes:

* Incident name
* Incident GUID from the final `/incidents/{guid}` ARM ID segment
* Incident number
* Incident ARM ID
* Workspace name
* Title, severity, and status as supporting metadata only
* Created and updated timestamps as supporting metadata only

Collectors must not store raw Sentinel payloads, entities, accounts, IPs,
alert details, tokens, secrets, or auth headers in dashboard output.

Status:

Integrated for CPAi only

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
* Shared exact-ID correlation helper utilities for SentinelOne, Securonix,
  and Microsoft Sentinel
* Exact SentinelOne alias normalization before grouping
* Exact SentinelOne source-to-Jira ID correlation
* Exact Securonix incident-ID source-to-Jira correlation
* Exact Microsoft Sentinel incident-ID source-to-Jira correlation
* Wazuh coverage-first correlation comparison

`compare_data()` accepts the configured SentinelOne client mapping. It applies
the same exact mapping to alert and Jira records before grouping them under a
canonical client name.

Collectors do not own or duplicate this alias mapping.

SentinelOne, Securonix, and Microsoft Sentinel use the shared exact-ID helper
for the repeated source index, ticket match, strict/correlated ticket, metadata
drift, and coverage-total flow. Tool-specific identifier extraction remains
separate and must stay exact.

SentinelOne uses exact-ID correlation. It matches Jira tickets only when
`sentinelone_threat_id` or `sentinelone_threat_url_id` exactly matches a
current SentinelOne source identifier such as `id`,
`sentinelone_source_id`, or `sentinelone_threat_id`. It does not match Azure
or Microsoft Sentinel IDs, threat names, timestamps, client/site alone,
summary text, or fuzzy similarity.

Wazuh uses the correlation resilience flow. Its comparison uses source alert
counts and correlated Jira tickets as the primary coverage signal. Strict
tenant-field ticket counts and metadata drift are retained as secondary
evidence.

Wazuh must remain separate from the shared exact-ID helper. It uses grouped WHB
evidence, tenant-field tracking, and configured source-evidence hints rather
than simple current-source exact-ID matching.

Securonix uses exact incident-ID correlation. It matches Jira tickets only
when `securonix_incident_id` or `securonix_incident_url_id` exactly matches a
current Securonix source incident identifier such as `id`,
`securonix_incident_id`, or the `id=` value from `securonix_incident_url`.
It does not match tenant labels alone, policy names, Solr queries, timestamps,
account/resource names, incident type, priority/risk/status, summary text, or
fuzzy similarity.

Microsoft Sentinel uses exact-ID correlation for the `microsoft_sentinel`
tool key. It matches Jira tickets only when exact Microsoft Sentinel evidence
matches a current source incident:

* Exact Incident ARM ID
* Exact incident GUID from API incident name or final ARM incident segment
* Exact incident GUID from Jira Incident URL
* Numeric Incident ID only within the same configured client/workspace

It does not match title, Jira summary alone, timestamps, tenant/client alone,
severity, or fuzzy similarity. CPAi matching requires Jira Tenant Name
`ContractPodAi` and summary containing `CPAi`; LeahAI uses the same Jira tenant
and must not be included in CPAi matching.

SOC coverage language:

* Covered / Equal: alert coverage is complete
* Missing Tickets / Mismatch: source alerts lack Jira coverage
* Review: Jira has more tickets than source alerts and needs review for source
  API delay, pagination/window mismatch, Jira/source refresh timing,
  duplicates, stale tickets, or real triage

The dashboard label is `Review`, not `Triaging`.

Coverage deltas are `correlated_ticket_count - alert_count`. Equal coverage
is `0`, missing tickets are negative values, and extra tickets are reported
separately as `extra_ticket_count` rather than as `+x` wording.

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

For Wazuh only, the client page presents coverage-first insight and compact
grouped source evidence from WHB. SentinelOne and Securonix use exact-ID
ticket evidence instead.

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

The CSS/template cleanup was display-only. It grouped repeated styles and
template class branches without changing dashboard behavior, wording, routes,
filters, client search, timestamps, or status labels.

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

If tool-specific correlation grows, move that logic into cleaner plugin-style
modules instead of adding unrelated logic to collectors or templates.

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
