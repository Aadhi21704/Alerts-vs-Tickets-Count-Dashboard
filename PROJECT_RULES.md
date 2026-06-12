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
* Future security platforms

---

## Critical Development Rules

### Rule 1

Do not redesign working code unless explicitly requested.

Prefer minimal, targeted changes.

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

unless explicitly requested.

---

### Rule 4

Do not hardcode client-specific logic outside config.py.

Client filtering, exclusions and mappings must live inside config.py.

---

### Rule 5

Preserve backward compatibility whenever possible.

Avoid breaking existing dashboard functionality.

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

Current client mapping:

NCC -> NCC-Bihar

Rainbow may not appear in data until WHB deployment is completed.

This is expected.

Do not create placeholder clients.

---

## Jira Rules

SentinelOne tickets:

Issue Type = SentinelOne

Wazuh tickets:

Issue Type = Wazuh Alert

---

## Alert Relationship

For all currently supported tools:

1 Alert = 1 Jira Ticket

This assumption is critical to comparison logic.

---

## Future Direction

Current goal:

Monitor alert counts versus Jira ticket counts.

Future goal:

Generate Teams notifications for mismatches.

Do not implement Teams integration unless explicitly requested.

---

## Security

Never commit:

* .env
* API tokens
* Secrets

Never expose credentials in logs.
