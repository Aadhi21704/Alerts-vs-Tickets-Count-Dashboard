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
* Microsoft Sentinel
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

The current UI is a polished server-rendered dashboard built with FastAPI,
Jinja templates, and CSS. The active UI does not depend on a standalone
`app.js` file; the legacy frontend script has been removed.

Stable UI release: `dashboard-ui-v1.1`.

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

## Dashboard SOC Coverage Labels

The dashboard uses coverage-first SOC labels across tools:

* Equal means source alert or incident coverage is balanced with Jira tickets.
* Mismatch means source alerts or incidents are missing Jira ticket coverage.
* Review means extra Jira tickets exist and should be reviewed for source API
  delay, pagination/window mismatch, Jira/source refresh timing, duplicates,
  stale tickets, or real triage.

Delta display rules:

* Equal coverage displays `0`.
* Missing tickets display a negative delta, for example `-2`.
* Extra tickets are displayed as `x extra tickets`.
* The UI must not display `+0` or `+x`.

Metadata drift is secondary evidence. It must not become the primary red
coverage state by itself.

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
* Exact client alias normalization
* Source tagging
* Exact-ID Jira correlation
* Dashboard integration
* Client drilldowns

### SentinelOne Exact-ID Correlation

SentinelOne uses exact identifier matching between current source alerts and
Jira tickets. Jira tickets count as correlated coverage only when SentinelOne
evidence in Jira exactly matches a current SentinelOne source identifier.

Source identifiers used for matching:

* `id`
* `sentinelone_source_id`
* `sentinelone_threat_id`
* SentinelOne threat URL ID when present

Jira identifiers used for matching:

* `sentinelone_threat_id`
* `sentinelone_threat_url_id`

SentinelOne does not match on:

* Azure or Microsoft Sentinel incident IDs
* Threat name
* Timestamps
* Client or site alone
* Jira summary text
* Fuzzy similarity

Matched Jira tickets are attributed to the matched source alert's canonical
client. The parsed Jira client is retained as strict metadata. If it differs
from the matched source client, the ticket is marked with
`client_metadata_drift`. Metadata drift is secondary evidence and is not a
coverage failure by itself.

SentinelOne coverage behavior:

* Missing exact source-to-Jira matches produce Mismatch / Missing Tickets.
* Extra matched Jira tickets produce Review.
* Equal exact-ID coverage produces Equal / Covered.

### SentinelOne Client Normalization

`SENTINELONE_CLIENT_MAPPING` in `config.py` maps approved raw aliases to
managed canonical client names.

Current mappings:

* `AM Green` to `AM Green Ammonia Pvt Ltd`
* `HNG` to `HEALTHNET GLOBAL LIMITED`
* `Sudhakar_PVC` to `Sudhakar PVC products pvt ltd`
* `Progility` to `Progility Technologies Pvt. Ltd.`
* `STAR_NRG` to `STAR HOSPITALS`
* `STAR_Banjara` to `STAR HOSPITALS`
* `Greenko-Energy-MDR` to `Greenko Energy Projects Private Limited`

The STAR mappings represent two sites under one reseller account. The
Greenko MDR mapping represents a managed site under the Greenko Energy
Projects Private Limited reseller account.

Normalization occurs in the SentinelOne comparison flow before alerts and
Jira tickets are grouped. Both sides therefore use the same canonical client
identity.

Mapping is exact dictionary lookup only. Fuzzy matching, substring matching,
and automatic case-insensitive matching are not allowed.

SentinelOne and Jira collectors preserve the raw client names returned by
their sources. Normalization logic must not be duplicated across collectors.

Current exclusion:

Greenko-Energy-EDR

This exclusion must remain in place. `Greenko-Energy-EDR` must not be mapped
to or included under the managed Greenko account.

---

## Wazuh

Status:

Fully integrated.

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

Implemented architecture:

WHB API
↓
Wazuh Collector
↓
Normalized Wazuh Data
↓
Comparator
↓
Dashboard

Wazuh Jira tickets and client drilldowns are included in the canonical
dashboard schema.

### Wazuh Coverage and Correlation Semantics

Wazuh is currently the only tool using the correlation resilience flow. It is
the first reference implementation of a future SOC pattern that can be
extended to other tools later. SentinelOne now has exact-ID correlation, but
does not use Wazuh's tenant-field and client-hint resilience flow. Securonix
now uses exact incident-ID correlation.

Coverage is the primary Wazuh signal:

* Source alert counts from WHB are compared against correlated Jira tickets.
* Correlated Jira tickets are resolved by safe tenant-field evidence or by
  configured Wazuh Jira client hints.
* Strict tenant-field ticket counts are tracked separately as metadata quality
  evidence.
* Metadata drift is secondary. A Jira ticket resolved from source evidence
  because the Tenant Name field is missing is still coverage, not a coverage
  failure.

Wazuh statuses:

* Equal / Covered means source alert coverage is complete.
* Mismatch / Missing Tickets means source alerts exist without matching Jira
  coverage.
* Review means Jira tickets exceed source alerts and should be reviewed for
  source API delay, pagination/window mismatch, Jira/source refresh timing,
  duplicates, stale tickets, or real triage.

Wazuh delta semantics:

* `0` means coverage is equal.
* Negative values mean tickets are missing, for example `-2`.
* The UI must not display `+0` or `+x`.
* Extra tickets should be communicated as `x extra tickets`, not as a positive
  signed delta.

Wazuh source evidence:

* WHB `by_rule[].id` is stored as `sample_alert_id`.
* `sample_alert_id` is representative grouped evidence from a WHB rule row. It
  is not necessarily every individual alert ID when `count > 1`.
* Safe evidence fields include sample alert ID, rule ID, count, level,
  location, and description.
* Raw `full_log`, `data`, and other raw payloads must not be stored in
  dashboard output or displayed.

---

## Securonix

Status:

Fully integrated.

Current source:

Securonix SNYPR incident API

Endpoint:

`GET {SECURONIX_BASE_URL}/ws/incident/get`

Authentication:

WS token header named `token`.

Current parameters:

* `type=list`
* `rangeType=opened`
* `order=desc`
* 24-hour opened incident window

Current allowed clients:

* QuisLex
* NopalCyber

Jira integration:

* Project: NSIR
* Issue type: Security Incident
* Client source: Tenant Name labels field

Securonix uses exact incident-ID correlation between current SNYPR source
incidents and Jira Security Incident tickets.

Source identifiers used for matching:

* `id`
* `securonix_incident_id`
* `securonix_incident_url`, using its `id=` query value

Jira identifiers used for matching:

* `customfield_10116` / `SCNX-Incident-ID`
* `customfield_10120` / `Securonix Incident URL`, using its `id=` query value
* Description fallback for the same safe labels

Securonix does not match on:

* Tenant or client labels alone
* Policy name
* Solr query
* Timestamps
* Account or resource names
* Incident type
* Priority, risk, or status
* Jira summary text
* Fuzzy similarity

Matched Jira tickets are attributed to the matched source incident's client.
The parsed Jira tenant/client is retained as strict metadata. If it differs
from the matched source client, the ticket is marked with
`client_metadata_drift`. Metadata drift is secondary evidence and is not a
coverage failure by itself.

Sensitive Securonix fields are excluded and must not be stored or displayed:

* `violatorText`
* `violatorId`
* `solrquery`
* Raw descriptions and raw payloads

---

## Microsoft Sentinel

Status:

Integrated for the approved CPAi client only.

Tool key:

`microsoft_sentinel`

Current enabled client:

* ContractPodAi / CPAi

Pending future Microsoft Sentinel clients:

* Kshema_General_Insurance_Limited
* LeahAI
* FileJet

### CPAi Jira Mapping

CPAi Jira tickets are selected using both Jira tenant and summary evidence:

* Jira Tenant Name = `ContractPodAi`
* Jira summary must contain `CPAi`

This summary rule is required because LeahAI tickets also use Jira Tenant
Name `ContractPodAi`. LeahAI tickets must not be included in CPAi matching.

### Microsoft Sentinel Authentication

Each Microsoft Sentinel client has its own Azure application and workspace
configuration:

* tenant ID
* client ID
* client secret
* subscription ID
* resource group name
* workspace name

The collector requests an Azure Management API token using client credentials.
Observed token lifetime is about 3599 seconds. Tokens are generated, cached,
and refreshed per configured client. Tokens and secrets must never be stored
in `latest.json`.

### Microsoft Sentinel Source Collection

The collector uses the Microsoft SecurityInsights incidents API.

Current behavior:

* 24-hour incident window using `properties.createdTimeUtc`
* `$top=1000`
* `properties/createdTimeUtc desc` ordering
* Follows `nextLink` pagination
* Stores only safe normalized fields

Safe source fields include incident name, incident GUID, incident number,
incident ARM ID, workspace name, title, severity, status, created/updated
times, optional activity times, and optional alert count. Raw Sentinel
payloads, entities, accounts, IPs, alert details, tokens, and secrets must
not be stored or displayed.

The incident GUID must be extracted from the final `/incidents/{guid}` ARM ID
segment. The first GUID in an ARM ID can be the subscription ID and must not
be used as the incident GUID.

### Microsoft Sentinel Jira Extraction

CPAi Jira extraction reads safe identifiers from Jira description ADF:

* Incident ID
* Incident ARM ID
* Incident ARM GUID
* Incident URL
* Incident URL GUID
* Created Time(UTC)
* Last Modified Time(UTC)

Raw Jira descriptions are not stored in dashboard output.

### Microsoft Sentinel Exact-ID Correlation

Microsoft Sentinel uses exact source-to-Jira correlation.

Matching priority:

* Exact Incident ARM ID
* Exact incident GUID from API incident name or final ARM incident segment
* Exact incident GUID from Jira Incident URL
* Numeric Incident ID only within the same configured client/workspace

Microsoft Sentinel does not match on:

* Title
* Jira summary alone
* Timestamp
* Tenant or client alone
* Severity
* Fuzzy similarity

Coverage behavior:

* Missing exact source-to-Jira matches produce Mismatch / Missing Tickets.
* Extra matched Jira tickets produce Review.
* Equal exact-ID coverage produces Equal / Covered.

---

# Current Dashboard Structure

## Page 1

/

Home Dashboard

Displays:

* Overall reconciliation status
* Total alerts
* Total tickets
* Priority mismatch
* Tool health cards

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

/tool/securonix

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

/tool/securonix/client/QuisLex

---

# Dashboard APIs

## Canonical Read-Only API

`GET /api/dashboard` returns the canonical dashboard data exactly as loaded
from `latest.json`. This is the API intended for a future React migration.

It must remain read-only and must not transform the canonical `tools[]`
schema.

## Deprecated Compatibility API

`GET /api/data` remains available only as a deprecated compatibility endpoint
for legacy single-tool consumers. New frontend work must not depend on it.

## Direct Update API

`POST /api/update` is disabled and returns HTTP 405. It must not be re-enabled
and must never write to `latest.json`; dashboard data is generated by the
scheduled collector workflow.

---

# Design Philosophy

Collectors

Responsible for:

* Fetching data
* Filtering data
* Normalizing source record shape
* Preserving raw client names for comparison-time canonicalization

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

Future milestones:

* Expand client normalization only through approved exact mappings
* Consider moving tool-specific correlation into cleaner plugin-style modules
  if the comparator grows too large
* Avoid fuzzy matching unless explicitly approved for a specific audited use
  case
* React migration planning using the stabilized `/api/dashboard`
* Auto-refresh strategy
* Optional dashboard visualizations
* Teams notifications
* Additional security tool integrations
