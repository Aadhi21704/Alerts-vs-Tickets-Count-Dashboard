# CODING GUIDELINES

## General Principles

* Make the smallest change possible.
* Do not rewrite working code.
* Do not redesign stable architecture.
* Prefer extending existing implementations.
* Preserve existing behavior unless explicitly requested otherwise.

---

# Before Making Changes

Always identify:

1. Files to modify
2. Reason for modification
3. Risks
4. Implementation plan

Before implementing multi-file changes, present the plan first and wait for approval.

---

# Scope Control

Stay focused on the requested task.

Do not:

* Refactor unrelated code
* Rename unrelated variables
* Reformat unrelated files
* Introduce side changes

If an unrelated issue is discovered:

* Document it
* Report it
* Do not automatically fix it

unless explicitly requested.

---

# Existing Architecture

The following architecture is already implemented:

Home
↓
Tool
↓
Client

Do not redesign this navigation structure.

Extend it when necessary.

---

# Dashboard Development

Current dashboard architecture is considered stable.

When making dashboard changes:

* Reuse existing routes
* Reuse existing templates
* Reuse existing schema

Avoid creating:

* Tool-specific pages
* Duplicate routes
* Duplicate templates

The dashboard should remain generic.

---

# Schema Changes

The canonical dashboard structure is:

```json
{
  "timestamp": "",
  "tools": []
}
```

All future work should build on this structure.

Do not introduce competing dashboard schemas.

---

# Collectors

Collectors are responsible only for:

* API communication
* Data retrieval
* Filtering
* Mapping
* Normalization

Collectors must not:

* Generate HTML
* Contain UI logic
* Perform dashboard rendering
* Contain FastAPI route logic

---

# Comparator

Comparator responsibilities:

* Compare alerts
* Compare tickets
* Generate statuses

Comparator must not:

* Call APIs
* Render UI
* Read templates
* Generate HTML

Keep comparator logic tool-agnostic whenever possible.

---

# FastAPI Layer

FastAPI is responsible for:

* Routes
* Data loading
* Context generation
* Template rendering

Avoid placing business rules directly in route handlers.

Prefer helper functions when logic becomes reusable.

---

# Templates

Templates should contain presentation logic only.

Allowed:

* Loops
* Conditionals
* Display formatting

Avoid:

* Business logic
* Complex calculations
* Data transformation

Prepare data before sending it to templates.

---

# Configuration

Configuration belongs in:

config.py

Examples:

* API endpoints
* Client mappings
* Managed client registries
* Allowlists
* Exclusions
* Tool settings

Do not hardcode configuration values elsewhere.

---

# Client Names

Client names should be treated as canonical identifiers.

When normalization is required:

* Normalize at the collection/comparison layer
* Do not normalize inside templates

Future client mapping logic should remain centralized.

---

# Error Handling

Prefer explicit error handling.

Avoid:

```python
except:
    pass
```

Use:

```python
except SpecificException:
```

whenever practical.

Do not silently discard useful debugging information.

---

# Logging

Preserve useful logs.

Log:

* Collection failures
* API failures
* Mapping issues
* Comparison issues

Do not log:

* Tokens
* Passwords
* Secrets

Avoid excessive logging noise.

---

# Backward Compatibility

When changing schemas or APIs:

* Provide compatibility layers when needed
* Avoid breaking working routes immediately
* Migrate incrementally

Remove compatibility code only after migration is complete.

---

# Testing

Whenever significant functionality changes:

Validate:

* Existing behavior
* New behavior
* Edge cases

Particularly validate:

* Alert-only clients
* Ticket-only clients
* Managed clients
* Zero-count clients
* Source tags
* Client drilldowns

---

# Future Tool Integrations

Future tools should integrate through:

1. Collector
2. Jira integration
3. Comparator
4. Dashboard schema

Do not create custom dashboard implementations for individual tools.

The goal is:

Tool
↓
Normalized Data
↓
Comparator
↓
Dashboard

for every supported platform.

---

# Security

Never:

* Commit secrets
* Commit credentials
* Commit API tokens

Never print sensitive values to logs.

Always assume repositories may eventually become shared.

---

# Preferred Development Approach

For large tasks:

1. Analyze
2. Design
3. Review
4. Implement
5. Validate

Avoid implementing before the design has been reviewed.

This project values correctness and maintainability over speed.
