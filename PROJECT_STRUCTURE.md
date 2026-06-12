# PROJECT STRUCTURE

config.py
Configuration only

collectors/
Fetch and normalize tool data

comparison/
Compare tool data against Jira

app/
Dashboard API and frontend

app/static/
CSS and JavaScript

app/templates/
HTML templates

run.py
Collection execution

scheduler.py
Scheduled execution

latest.json
Dashboard data output

logs/
Application logs

## Rules

Collectors must not modify UI.

UI must not contain comparison logic.

Comparator must not contain tool-specific API calls.

Keep responsibilities separated.
