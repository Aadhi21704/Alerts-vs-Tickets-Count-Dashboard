# TODO

## High Priority

### Dashboard Schema Refactor

Current:

clients

Future:

tools -> clients

Status:

Not started.

---

### Dashboard UI Refactor

Add top-level Tool containers.

Current:

Client list

Future:

Tool
└─ Clients

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

Status:

Not started.

---

### Wazuh Jira Integration

Fetch:

Issue Type = Wazuh Alert

Map tickets to clients.

Status:

Not started.

---

### Wazuh Comparator

Compare:

Wazuh alerts ↔ Jira tickets

Status:

Not started.

---

## Medium Priority

### Generic Client Mapping Framework

Current:

WAZUH_CLIENT_MAPPING

Future:

Tool-specific mappings in a centralized framework.

Status:

Planned.

---

### Common Tool Schema

All collectors should return normalized structures.

Status:

Planned.

---

## Future

### Teams Notifications

Send notifications for mismatches.

Status:

Future.

---

### Additional Tool Integrations

Potential future tools:

* Securonix
* Microsoft Defender
* CrowdStrike
* Others

Status:

Future.
