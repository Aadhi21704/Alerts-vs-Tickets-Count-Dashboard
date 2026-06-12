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
* Future security platforms

The architecture must support onboarding additional tools without requiring dashboard redesign.

---

# Current Project State

The following items are considered completed and should not be reimplemented:

* Canonical `tools[]` dashboard schema
* Home → Tool → Client navigation
* Dynamic tool routing
* Dynamic client routing
* Tool pages
* Client pages
* Managed client registry
* Source tags
* SentinelOne dashboard integration
* SentinelOne Jira integration
* SentinelOne comparator integration
* Alert ID drilldowns
* Jira Ticket ID drilldowns

Future work should extend this architecture rather than replace it.

---

# Critical Development Rules

## Rule 1

Do not redesign working code unless explicitly requested.

Prefer minimal, targeted changes.

Avoid large-scale rewrites.

---

## Rule 2

Before modifying multiple files:

Analyze and present:

1. Files to modify
2. Reason for modification
3. Risks
4. Implementation plan

Wait for approval before making changes.

---

## Rule 3

Do not introduce new frameworks.

Current stack:

* FastAPI
* HTML
* CSS
* Vanilla JavaScript

Do not migrate to:

* Django
* Streamlit
* React
* Vue
* Angular

unless explicitly requested.

---

## Rule 4

Do not duplicate architecture.

If a feature already exists:

* Extend it
* Reuse it

Do not create parallel implementations.

Examples:

* Reuse tool routing
* Reuse comparator behavior
* Reuse dashboard schema

---

## Rule 5

Preserve backward compatibility whenever practical.

Existing routes and functionality should continue working unless explicitly replaced.

---

## Rule 6

Do not hardcode client-specific logic outside config.py.

The following belong in config.py:

* Allowlists
* Exclusions
* Client mappings
* Managed client registries
* Tool configuration

---

## Rule 7

Do not place business logic in templates.

Templates are presentation only.

Business logic belongs in:

* Collectors
* Comparator
* FastAPI backend

---

# Dashboard Rules

## Navigation

Current navigation model:

Home
↓
Tool
↓
Client

This navigation model is considered stable.

Do not redesign it unless explicitly requested.

---

## Homepage

The homepage should focus on:

* Tool cards
* Tool summaries
* Dashboard KPIs
* Future visualizations

The homepage should NOT become a client listing page again.

---

## Tool Pages

Tool pages should display:

* Tool summary
* Client list
* Source tags
* Alert counts
* Ticket counts

Tool pages must remain generic.

No tool-specific UI pages should be created.

---

## Client Pages

Client pages are the primary drilldown layer.

Client pages should display:

* Alert counts
* Ticket counts
* Alert IDs
* Jira Ticket IDs

Additional future drilldowns should be added here rather than creating additional navigation levels.

---

# SentinelOne Rules

## Sources

Current sources:

* MSSP
* Reseller

---

## MSSP

Uses allowlist filtering.

Configured through:

MSSP_ALLOWED_CLIENTS

---

## Reseller

Uses exclusion filtering.

Configured through:

RESSELLER_EXCLUDED_CLIENTS

---

## Greenko

Greenko-Energy-EDR must always remain excluded.

Reason:

We do not manage EDR for Greenko.

EDR alerts do not generate Jira tickets.

Do not remove this exclusion unless explicitly requested.

---

## Managed Client Registry

Dashboard visibility must be controlled independently from collector filtering.

Clients should remain visible even when:

* Alert count = 0
* Ticket count = 0

Do not reuse filtering lists as dashboard visibility lists.

---

## Source Tags

Current supported source tags:

* MSSP
* RESELLER

Source tags should be displayed whenever possible.

Unknown source ownership should be displayed as:

UNKNOWN

rather than guessed.

---

# Wazuh Rules

Current source:

WHB API

Current endpoint:

https://whb.nopalcyber.com/api/v1/integrations/wazuh-alert-counts

Current requirements:

* hours = 24
* rule.level >= 5

Current allowed clients:

* Progility
* NCC
* Rainbow_Children_Hospitals

Current mapping:

* NCC → NCC-Bihar

Rainbow may not appear until WHB deployment is completed.

This is expected behavior.

Do not create placeholder alerts or clients.

---

# Jira Rules

## SentinelOne

Issue Type:

SentinelOne

---

## Wazuh

Issue Type:

Wazuh Alert

Client source:

Tenant Name

---

# Alert Relationship

Current assumption:

1 Alert = 1 Jira Ticket

Comparison logic depends on this assumption.

Do not introduce aggregation logic unless requirements change.

---

# Comparator Rules

Comparator should move toward tool-agnostic behavior.

Comparator responsibilities:

* Compare alerts
* Compare tickets
* Generate statuses

Comparator must not:

* Call APIs
* Render UI
* Contain dashboard logic

---

# Future Integrations

Future tools may include:

* Wazuh
* Securonix
* Microsoft Defender
* CrowdStrike
* FortiAnalyzer

Future integrations should plug into the existing architecture.

They should not require:

* Dashboard redesign
* Route redesign
* Template duplication

---

# Future Dashboard Features

Potential additions:

* Tool KPIs
* Alert trends
* Ticket trends
* Mismatch trends
* Tool health summaries
* Visual charts

These additions should fit within the existing navigation structure.

---

# Security

Never commit:

* .env
* API tokens
* Secrets
* Credentials

Never expose:

* Tokens
* Passwords
* Secrets

Never log credentials.

---

# Current Development Focus

Current priority order:

1. Wazuh Collector
2. Wazuh Jira Integration
3. Wazuh Comparator Integration
4. Wazuh Dashboard Integration

Do not redesign the dashboard while these tasks are in progress.
