# CODING GUIDELINES

## General

* Make the smallest change possible.
* Do not rewrite working code.
* Do not reformat unrelated files.
* Preserve existing code style.

## Before Changes

Always identify:

* Files to modify
* Reason for modification
* Risks

before making changes.

## Dashboard

Current UI is working.

Do not redesign UI unless explicitly requested.

Prefer incremental improvements.

## Collectors

Each collector is responsible only for:

* Fetching data
* Normalizing data

Collectors should not contain dashboard logic.

Collectors should not contain UI logic.

## Comparator

Comparator should remain tool-agnostic.

Avoid vendor-specific logic whenever possible.

## Config

Client mappings, exclusions and allowlists belong in config.py.

Do not hardcode them elsewhere.

## Logging

Preserve existing logging.

Do not remove useful logs without approval.

## Secrets

Never expose tokens.

Never print secrets to logs.

Never commit credentials.
