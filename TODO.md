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
* [x] SentinelOne safe source/Jira identifier extraction
* [x] SentinelOne exact-ID Jira correlation
* [x] Greenko EDR exclusion
* [x] Tool-card homepage
* [x] Wazuh collector integration
* [x] Wazuh Jira integration
* [x] Wazuh comparator integration
* [x] Wazuh dashboard integration
* [x] Wazuh Jira correlation resilience
* [x] Wazuh coverage-first status semantics
* [x] Wazuh grouped WHB source evidence display model
* [x] Securonix collector integration
* [x] Securonix Jira integration
* [x] Securonix safe source/Jira identifier extraction
* [x] Securonix exact incident-ID Jira correlation
* [x] Securonix comparator integration
* [x] Securonix dashboard integration
* [x] Microsoft Sentinel CPAi collector integration
* [x] Microsoft Sentinel CPAi Jira extraction
* [x] Microsoft Sentinel CPAi exact-ID Jira correlation
* [x] Microsoft Sentinel dashboard backend integration
* [x] Shared exact-ID comparator helper for SentinelOne, Securonix, and
      Microsoft Sentinel
* [x] UI Phase 1 polished homepage
* [x] UI Phase 2 polished tool and client pages
* [x] Client evidence display ordering
* [x] SentinelOne client normalization v1
* [x] Exact mapping for `AM Green`
* [x] Exact mapping for `HNG`
* [x] Exact mapping for `Sudhakar_PVC`
* [x] Exact mapping for `Progility`
* [x] Reseller site normalization
* [x] Map `STAR_NRG` to `STAR HOSPITALS`
* [x] Map `STAR_Banjara` to `STAR HOSPITALS`
* [x] Map `Greenko-Energy-MDR` to `Greenko Energy Projects Private Limited`
* [x] Preserve `Greenko-Energy-EDR` exclusion

### Application Cleanup

* [x] Stop tracking Python cache files
* [x] Lock down `/api/update` with HTTP 405
* [x] Remove unused `app/static/app.js`
* [x] Keep `/api/data` as deprecated legacy compatibility
* [x] Add canonical read-only `/api/dashboard`
* [x] Codebase slimdown v1
* [x] CSS/template cleanup v1

---

## Current Supported Tools

* SentinelOne
* Wazuh
* Securonix
* Microsoft Sentinel CPAi

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

* Compare WHB source alert counts against correlated Jira tickets
* Preserve strict tenant-field ticket counts separately
* Treat metadata drift as secondary evidence, not as a coverage failure
* Reuse managed client framework where applicable
* Preserve tool-agnostic architecture

Status:

Completed

---

### Wazuh Correlation Resilience

Wazuh is the first implementation of the coverage-first SOC pattern.
SentinelOne now uses exact-ID correlation, but it does not use Wazuh's
tenant-field and client-hint resilience flow. Securonix now uses exact
incident-ID correlation.

Implemented behavior:

* Correlated Wazuh Jira tickets count as coverage when resolved safely by
  Tenant Name or configured source-evidence hints.
* Strict Tenant Name counts remain visible as metadata quality evidence.
* Metadata drift does not turn complete coverage into a failure.
* Missing tickets are represented as negative coverage deltas, for example
  `-2`.
* Equal coverage displays `0`, not `+0`.
* Extra tickets are communicated as `x extra tickets` and should be reviewed
  for source API delay, pagination/window mismatch, Jira/source refresh timing,
  duplicates, stale tickets, or real triage.
* WHB grouped `by_rule[].id` is exposed as `sample_alert_id`.
* `sample_alert_id` is representative grouped evidence and not every
  individual alert ID when the row count is greater than 1.
* Raw `full_log`, `data`, and other raw payloads must not be stored or shown.

Status:

Completed for Wazuh only

---

## Completed SentinelOne Correlation Work

### SentinelOne Exact-ID Correlation

SentinelOne Jira tickets now count as correlated coverage only when exact
SentinelOne evidence matches a current source alert.

Implemented matching keys:

* Source `id`
* `sentinelone_source_id`
* `sentinelone_threat_id`
* SentinelOne threat URL ID when present

Explicitly not used for matching:

* Azure or Microsoft Sentinel incident IDs
* Threat name
* Timestamps
* Client/site alone
* Jira summary text
* Fuzzy similarity

Coverage behavior:

* Missing exact matches become Mismatch / Missing Tickets.
* Extra matched Jira tickets become Review.
* Equal exact-ID coverage is Equal / Covered.
* Metadata drift remains secondary evidence.

Status:

Completed

---

## Completed Securonix Correlation Work

### Securonix Exact Incident-ID Correlation

Securonix Jira tickets now count as correlated coverage only when exact
Securonix incident evidence matches a current source incident.

Implemented source matching keys:

* Source `id`
* `securonix_incident_id`
* `id=` value from `securonix_incident_url`

Implemented Jira matching keys:

* `customfield_10116` / `SCNX-Incident-ID`
* `customfield_10120` / `Securonix Incident URL`
* `id=` value from the Jira Securonix incident URL
* Description fallback for the same safe labels

Explicitly not used for matching:

* Tenant or client labels alone
* Policy name
* Solr query
* Timestamps
* Account or resource names
* Incident type
* Priority, risk, or status
* Jira summary text
* Fuzzy similarity

Coverage behavior:

* Missing exact matches become Mismatch / Missing Tickets.
* Extra matched Jira tickets become Review.
* Equal exact-ID coverage is Equal / Covered.
* Metadata drift remains secondary evidence.

Raw descriptions, Solr queries, raw payloads, secrets, and raw `full_log`,
`data`, or `raw` fields must not be stored or shown.

Status:

Completed

---

## Completed Microsoft Sentinel Work

### Microsoft Sentinel CPAi Exact-ID Correlation

Microsoft Sentinel is supported as a dashboard backend tool with tool key
`microsoft_sentinel`.

Current enabled client:

* ContractPodAi / CPAi

Implemented CPAi Jira mapping:

* Jira Tenant Name = `ContractPodAi`
* Jira summary must contain `CPAi`
* LeahAI tickets also use Jira Tenant Name `ContractPodAi` and must not be
  included in CPAi matching

Implemented source collection:

* Microsoft SecurityInsights incidents API
* 24-hour window using `properties.createdTimeUtc`
* `$top=1000`
* `nextLink` pagination support
* Per-client token generation, caching, and refresh
* Safe normalized incident fields only

Implemented Jira extraction:

* Incident ID
* Incident ARM ID
* Incident ARM GUID
* Incident URL
* Incident URL GUID
* Created Time(UTC)
* Last Modified Time(UTC)

Implemented matching keys:

* Exact Incident ARM ID
* Exact incident GUID from API incident name or final ARM incident segment
* Exact incident GUID from Jira Incident URL
* Numeric Incident ID only within the same configured client/workspace

Explicitly not used for matching:

* Title
* Jira summary alone
* Timestamp
* Tenant or client alone
* Severity
* Fuzzy similarity

Tokens, secrets, raw Jira descriptions, raw Sentinel payloads, entities,
accounts, IPs, and alert details must not be stored or shown.

Status:

Completed for CPAi only

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

### Microsoft Sentinel Future Clients

Pending approval and credentials:

* Kshema_General_Insurance_Limited
* LeahAI
* FileJet

LeahAI requires special care because its Jira Tenant Name is also
`ContractPodAi`; Jira summary evidence must distinguish LeahAI from CPAi.

Status:

Pending

---

### Global Review Status Wording

Visible dashboard wording now uses `Review` for extra-ticket states. Future
work can refine the supporting copy after more operational evidence is
collected.

Status:

Completed

---

### Toggleable Filters and Search UI

Add dashboard filters/search only after the core multi-tool coverage model is
stable.

Status:

Pending

---

### React Migration Planning

Plan a future frontend migration using:

`GET /api/dashboard`

Requirements:

* Preserve current routes during migration
* Do not use deprecated `/api/data`
* Keep the canonical `tools[]` schema
* Use the stabilized API model across SentinelOne, Wazuh, and Securonix

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

Completed v1:

* Exact dictionary mapping through `SENTINELONE_CLIENT_MAPPING`
* SentinelOne and Jira names normalized before comparison grouping
* Raw collector client names preserved
* Alert and ticket totals preserved

Confirmed reseller site aliases:

* `STAR_NRG` and `STAR_Banjara` belong to `STAR HOSPITALS`
* `Greenko-Energy-MDR` belongs to `Greenko Energy Projects Private Limited`

Unknown future aliases still require manual confirmation. Do not introduce
fuzzy, substring, or automatic case-insensitive mappings.

Status:

V1 and confirmed reseller site normalization completed

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

Current comparator uses shared exact-ID helper utilities for SentinelOne,
Securonix, and Microsoft Sentinel. Tool-specific identifier extraction remains
separate and exact.

Wazuh remains a separate grouped/evidence-based correlation path and must not
be merged into the shared exact-ID helper.

Goal:

Comparator should continue reducing duplication while preserving exact
matching behavior and output compatibility.

Requirements:

* Keep SentinelOne, Securonix, and Microsoft Sentinel exact-ID matching
  reusable through shared helpers
* Keep Wazuh separate unless a future audited requirement proves it can safely
  use a generic pattern
* Evaluate whether the Wazuh coverage/correlation model should become the
  generic SOC pattern for additional tools
* Consider moving tool-specific correlation into plugin-style modules if the
  comparator becomes hard to maintain

Status:

V1 completed; further cleanup planned

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
5. Securonix Integration ✅
6. Timestamp display polish ✅

Current active development focus:

1. Stable dashboard release `dashboard-ui-v1.1`
2. Stabilize the canonical API and data model across all integrated tools
3. Keep coverage labels consistent: Equal, Mismatch, Review
4. Keep `latest.json` as generated runtime output only
5. React migration planning
6. Optional charts and polish

Do not replace the stable dashboard unless explicitly requested.

Prefer extending the existing architecture over introducing new patterns.

Avoid fuzzy matching unless explicitly approved after a separate evidence
audit.
