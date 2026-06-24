from pathlib import Path
from datetime import datetime
from datetime import timezone
import json
import scheduler
from zoneinfo import ZoneInfo
from config import REFRESH_INTERVAL_MINUTES
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="SentinelOne Jira Dashboard")

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = BASE_DIR / "latest.json"

app.mount("/static", StaticFiles(directory="app/static"), name="static")

templates = Jinja2Templates(directory="app/templates")


def load_dashboard_data():

    with open(DATA_FILE, "r") as f:
        return json.load(f)


def format_dashboard_timestamp(timestamp):

    if not isinstance(timestamp, str):
        return "Unknown"

    try:

        parsed_timestamp = datetime.fromisoformat(
            timestamp
        )

        local_timestamp = (
            parsed_timestamp.astimezone(
                ZoneInfo("Asia/Kolkata")
            )
        )

        return local_timestamp.strftime(
            "%d %b %Y, %I:%M %p IST"
        )

    except ValueError:
        return timestamp


def find_tool(data, tool_name):

    return next(
        (
            tool
            for tool in data.get("tools", [])
            if tool.get("tool_key") == tool_name
        ),
        None
    )


def find_client(tool, client_name):

    return next(
        (
            client
            for client in tool.get("clients", [])
            if client.get("client") == client_name
        ),
        None
    )


def first_present(record, field_names):
    for field_name in field_names:
        value = record.get(
            field_name
        )

        if value not in (
            None,
            ""
        ):
            return value

    return ""


def status_tone(status):
    if status == "Equal":
        return "equal"

    if status == "Review":
        return "warning"

    return "mismatch"


def status_display_fields(status):
    tone = status_tone(
        status
    )

    return {
        "status_tone": tone,
        "status_badge_class":
            f"status-badge--{tone}",
        "page_hero_class":
            f"page-hero--{tone}",
        "tool_health_card_class":
            f"tool-health-card--{tone}",
        "client_status_row_class":
            f"client-status-row--{tone}"
    }


def dashboard_hero_class(status):
    if status == "Equal":
        return "status-hero--clear"

    if status == "Review":
        return "status-hero--warning"

    return "status-hero--attention"


def priority_card_fields(status, priority_issue):
    if priority_issue:
        return {
            "priority_card_class":
                "priority-card--attention",
            "priority_badge_class":
                "status-badge--mismatch",
            "priority_badge_text":
                "Action Required"
        }

    if status == "Review":
        return {
            "priority_card_class":
                "priority-card--warning",
            "priority_badge_class":
                "status-badge--warning",
            "priority_badge_text":
                "Review"
        }

    return {
        "priority_card_class":
            "priority-card--clear",
        "priority_badge_class":
            "status-badge--equal",
        "priority_badge_text":
            "All Clear"
    }


def timestamp_fields(record):
    if record.get("_record_type") == "ticket":
        return (
            "created",
            "jira_created",
            "status_time",
            "updated",
            "updatedAt",
            "updated_at",
            "createdAt",
            "created_at",
            "timestamp",
            "createdTimeUtc",
            "lastModifiedTimeUtc",
            "microsoft_sentinel_created_time_utc",
            "microsoft_sentinel_last_modified_time_utc"
        )

    return (
        "created",
        "createdAt",
        "created_at",
        "timestamp",
        "updated",
        "updatedAt",
        "updated_at",
        "detectedAt",
        "threatCreatedAt",
        "firstSeen",
        "lastSeen",
        "last_seen",
        "latest_timestamp",
        "latestTimestamp",
        "display_time",
        "createdTimeUtc",
        "lastModifiedTimeUtc",
        "microsoft_sentinel_created_time_utc",
        "microsoft_sentinel_last_modified_time_utc",
        "sentinelone_created_at",
        "sentinelone_updated_at"
    )


def raw_timestamp_value(record):
    return first_present(
        record,
        timestamp_fields(record)
    )


def parse_display_datetime(value):
    if value in (None, ""):
        return None

    if isinstance(value, (int, float)):
        if value >= 100000000000:
            return datetime.fromtimestamp(
                value / 1000,
                tz=timezone.utc
            )

        return None

    value_text = str(value).strip()

    if (
        value_text.isdigit()
        and len(value_text) >= 12
    ):
        try:
            return datetime.fromtimestamp(
                int(value_text) / 1000,
                tz=timezone.utc
            )
        except (OverflowError, ValueError):
            return None

    normalized_value = value_text

    if normalized_value.endswith("Z"):
        normalized_value = (
            normalized_value[:-1]
            + "+00:00"
        )

    try:
        parsed_datetime = datetime.fromisoformat(
            normalized_value
        )
    except ValueError:
        return None

    if parsed_datetime.tzinfo is None:
        parsed_datetime = parsed_datetime.replace(
            tzinfo=timezone.utc
        )

    return parsed_datetime


def timestamp_sort_value(value):
    parsed_datetime = parse_display_datetime(
        value
    )

    if parsed_datetime is None:
        return str(value or "")

    return parsed_datetime.astimezone(
        timezone.utc
    ).isoformat()


def format_display_time(value):
    if value in (None, ""):
        return ""

    parsed_datetime = parse_display_datetime(
        value
    )

    if parsed_datetime is None:
        return str(value).strip()

    return parsed_datetime.astimezone(
        ZoneInfo("Asia/Kolkata")
    ).strftime(
        "%d %b %Y, %I:%M %p IST"
    )


def display_identifier(record, tool_key):
    if tool_key == "microsoft_sentinel":
        return first_present(
            record,
            (
                "microsoft_sentinel_incident_id",
                "incident_number",
                "display_id",
                "microsoft_sentinel_provider_incident_id",
                "providerIncidentId",
                "id"
            )
        )

    if tool_key == "wazuh":
        return first_present(
            record,
            (
                "sample_alert_id",
                "wazuh_alert_id",
                "id",
                "rule_id"
            )
        )

    return first_present(
        record,
        (
            "display_id",
            "id",
            "securonix_incident_id",
            "sentinelone_threat_id",
            "key",
            "jira_key"
        )
    )


def normalized_identifier(value):
    if value is None:
        return ""

    return str(value).strip().casefold()


def source_match_identifiers(record, tool_key):
    identifiers = []

    if tool_key == "microsoft_sentinel":
        fields = (
            "microsoft_sentinel_incident_arm_id",
            "microsoft_sentinel_incident_name",
            "microsoft_sentinel_incident_guid",
            "microsoft_sentinel_incident_id",
            "incident_number",
            "id"
        )
    elif tool_key == "securonix":
        fields = (
            "id",
            "securonix_incident_id",
            "securonix_incident_url"
        )
    elif tool_key == "sentinelone":
        fields = (
            "id",
            "sentinelone_source_id",
            "sentinelone_threat_id",
            "sentinelone_threat_url_id"
        )
    elif tool_key == "wazuh":
        fields = (
            "sample_alert_id",
            "rule_id",
            "id"
        )
    else:
        fields = ("id",)

    for field_name in fields:
        identifier = normalized_identifier(
            record.get(field_name)
        )

        if identifier:
            identifiers.append(identifier)

    return sorted(set(identifiers))


def ticket_match_identifiers(record, tool_key):
    identifiers = []

    if tool_key == "microsoft_sentinel":
        fields = (
            "microsoft_sentinel_incident_arm_id",
            "microsoft_sentinel_incident_arm_guid",
            "microsoft_sentinel_incident_url_guid",
            "microsoft_sentinel_incident_id"
        )
    elif tool_key == "securonix":
        fields = (
            "securonix_incident_id",
            "securonix_incident_url_id",
            "securonix_incident_url"
        )
    elif tool_key == "sentinelone":
        fields = (
            "sentinelone_threat_id",
            "sentinelone_threat_url_id"
        )
    elif tool_key == "wazuh":
        fields = (
            "wazuh_alert_id",
            "rule_id"
        )
    else:
        fields = ("key", "jira_key")

    for field_name in fields:
        identifier = normalized_identifier(
            record.get(field_name)
        )

        if identifier:
            identifiers.append(identifier)

    return sorted(set(identifiers))


def enrich_record(record, tool_key, record_type):
    enriched = {
        **record
    }
    enriched["_record_type"] = record_type
    raw_timestamp = raw_timestamp_value(
        enriched
    )
    enriched["_display_id"] = display_identifier(
        enriched,
        tool_key
    )
    enriched["display_id"] = enriched["_display_id"]
    enriched["_raw_timestamp"] = raw_timestamp
    enriched["_sort_timestamp"] = timestamp_sort_value(
        raw_timestamp
    )
    enriched["_display_timestamp"] = format_display_time(
        raw_timestamp
    )
    enriched["display_time"] = enriched["_display_timestamp"]

    return enriched


def _sort_timestamp(record):
    value = record.get(
        "_sort_timestamp",
        ""
    )

    if value is None:
        return ""

    return str(value)


def align_evidence_records(alerts, tickets, tool_key):
    enriched_alerts = [
        enrich_record(
            alert,
            tool_key,
            "source"
        )
        for alert in alerts
    ]
    enriched_tickets = [
        enrich_record(
            ticket,
            tool_key,
            "ticket"
        )
        for ticket in tickets
    ]

    ticket_order = {}
    ticket_by_identifier = {}
    matched_source_indexes = set()

    for ticket_index, ticket in enumerate(enriched_tickets):
        for identifier in ticket_match_identifiers(
            ticket,
            tool_key
        ):
            ticket_order.setdefault(
                identifier,
                ticket_index
            )
            ticket_by_identifier.setdefault(
                identifier,
                ticket
            )

    ordered_alerts = []
    unmatched_alerts = []

    for alert_index, alert in enumerate(enriched_alerts):
        matched_ticket_index = None
        matched_identifier = None

        for identifier in source_match_identifiers(
            alert,
            tool_key
        ):
            if identifier in ticket_order:
                matched_ticket_index = ticket_order[
                    identifier
                ]
                matched_identifier = identifier
                break

        alert["_matched_ticket_index"] = matched_ticket_index
        alert["_matched_identifier"] = matched_identifier

        if matched_ticket_index is None:
            unmatched_alerts.append(
                alert
            )
        else:
            matched_source_indexes.add(
                alert_index
            )
            ordered_alerts.append(
                alert
            )

    ordered_alerts.sort(
        key=lambda record: (
            record.get("_matched_ticket_index", 0),
            _sort_timestamp(record)
        ),
        reverse=False
    )
    unmatched_alerts.sort(
        key=_sort_timestamp,
        reverse=True
    )

    for source_order, alert in enumerate(ordered_alerts):
        matched_ticket = ticket_by_identifier.get(
            alert.get("_matched_identifier")
        )

        if matched_ticket is not None:
            matched_ticket["_matched_source_order"] = source_order

    matched_tickets = []
    unmatched_tickets = []

    for ticket in enriched_tickets:
        if ticket.get("_matched_source_order") is not None:
            matched_tickets.append(
                ticket
            )
        else:
            unmatched_tickets.append(
                ticket
            )

    matched_tickets.sort(
        key=lambda record: (
            record.get("_matched_source_order", 999999),
            _sort_timestamp(record)
        )
    )
    unmatched_tickets.sort(
        key=_sort_timestamp,
        reverse=True
    )

    return (
        ordered_alerts + unmatched_alerts,
        matched_tickets + unmatched_tickets
    )


def build_soc_display(
    alert_count,
    ticket_count,
    coverage_status=None,
    coverage_delta=None,
    missing_ticket_count=None,
    extra_ticket_count=None
):

    if coverage_delta is None:
        coverage_delta = ticket_count - alert_count

    if missing_ticket_count is None:
        missing_ticket_count = max(
            -coverage_delta,
            0
        )

    if extra_ticket_count is None:
        extra_ticket_count = max(
            coverage_delta,
            0
        )

    if (
        missing_ticket_count > 0
        or coverage_status == "Missing Tickets"
    ):
        display_status = "Mismatch"
    elif (
        extra_ticket_count > 0
        or coverage_status == "Review"
    ):
        display_status = "Review"
    else:
        display_status = "Equal"

    delta_display = (
        f"{extra_ticket_count} extra tickets"
        if extra_ticket_count
        else str(coverage_delta)
    )

    return {
        "coverage_delta": coverage_delta,
        "coverage_delta_display": delta_display,
        "coverage_display_status": display_status,
        "tool_display_status": display_status,
        "missing_ticket_count": missing_ticket_count,
        "extra_ticket_count": extra_ticket_count
    }


def build_tool_context(tool):

    clients = [
        build_client_context(
            client,
            tool.get("tool_key", "")
        )
        for client in tool.get("clients", [])
    ]
    has_correlation_ui = (
        tool.get("tool_key") == "wazuh"
    )

    if not has_correlation_ui:
        clients = [
            {
                key: value
                for key, value in client.items()
                if key not in {
                    "strict_ticket_count",
                    "correlated_ticket_count",
                    "metadata_drift_count"
                }
            }
            for client in clients
        ]

    clients.sort(
        key=lambda client: (
            client.get("status") == "Equal",
            client.get(
                "client",
                ""
            ).casefold()
        )
    )

    mismatch_count = sum(
        1
        for client in clients
        if client.get("tool_display_status", client.get("status"))
        == "Mismatch"
    )
    warning_count = sum(
        1
        for client in clients
        if client.get("tool_display_status", client.get("status"))
        == "Review"
    )

    alert_count = tool.get(
        "alert_count",
        tool.get(
            "total_alerts",
            tool.get(
                "total_sentinel_count",
                0
            )
        )
    )
    ticket_count = tool.get(
        "ticket_count",
        tool.get(
            "total_tickets",
            tool.get(
                "total_jira_count",
                0
            )
        )
    )
    delta = alert_count - ticket_count
    coverage_delta = tool.get(
        "coverage_delta_total",
        ticket_count - alert_count
    )
    extra_ticket_total = tool.get(
        "extra_ticket_total",
        max(coverage_delta, 0)
    )
    missing_ticket_total = tool.get(
        "missing_ticket_total",
        max(-coverage_delta, 0)
    )

    soc_display = build_soc_display(
        alert_count,
        ticket_count,
        coverage_delta=coverage_delta,
        missing_ticket_count=missing_ticket_total,
        extra_ticket_count=extra_ticket_total
    )

    tool_context = {
        **tool,
        "clients": clients,
        "alert_count": alert_count,
        "ticket_count": ticket_count,
        "delta": delta,
        "delta_display": soc_display[
            "coverage_delta_display"
        ],
        "coverage_delta": soc_display[
            "coverage_delta"
        ],
        "missing_ticket_total": missing_ticket_total,
        "extra_ticket_total": extra_ticket_total,
        "client_count": len(clients),
        "mismatch_count": mismatch_count,
        "warning_count": warning_count,
        "review_count": mismatch_count + warning_count,
        "tool_display_status": soc_display[
            "tool_display_status"
        ],
        "status": soc_display[
            "tool_display_status"
        ],
        **status_display_fields(
            soc_display["tool_display_status"]
        )
    }

    if not has_correlation_ui:
        for key in (
            "strict_total_tickets",
            "correlated_total_tickets",
            "metadata_drift_total"
        ):
            tool_context.pop(
                key,
                None
            )

    return tool_context


def build_client_context(client, tool_key=""):

    alerts = client.get(
        "alerts",
        client.get(
            "sentinel_alerts",
            []
        )
    )
    tickets = client.get(
        "tickets",
        client.get(
            "jira_tickets",
            []
        )
    )
    source_evidence = client.get(
        "source_evidence",
        client.get(
            "wazuh_source_evidence",
            alerts
        )
    )
    display_alerts, display_tickets = align_evidence_records(
        source_evidence,
        tickets,
        tool_key
    )
    alert_count = client.get(
        "alert_count",
        client.get(
            "sentinel_count",
            0
        )
    )
    ticket_count = client.get(
        "ticket_count",
        client.get(
            "jira_count",
            0
        )
    )
    delta = alert_count - ticket_count
    coverage_delta = client.get(
        "coverage_delta",
        ticket_count - alert_count
    )
    extra_ticket_count = client.get(
        "extra_ticket_count",
        max(coverage_delta, 0)
    )
    missing_ticket_count = client.get(
        "missing_ticket_count",
        max(-coverage_delta, 0)
    )
    coverage_status = client.get(
        "coverage_status",
        client.get(
            "status",
            (
                "Equal"
                if alert_count == ticket_count
                else "Mismatch"
            )
        )
    )
    soc_display = build_soc_display(
        alert_count,
        ticket_count,
        coverage_status=coverage_status,
        coverage_delta=coverage_delta,
        missing_ticket_count=missing_ticket_count,
        extra_ticket_count=extra_ticket_count
    )

    display_status = soc_display[
        "tool_display_status"
    ]

    return {
        **client,
        "alert_count": alert_count,
        "ticket_count": ticket_count,
        "delta": delta,
        "delta_display": soc_display[
            "coverage_delta_display"
        ],
        **soc_display,
        "alerts": display_alerts,
        "source_evidence": display_alerts,
        "wazuh_source_evidence": display_alerts,
        "display_tickets": display_tickets,
        "status": client.get(
            "status",
            (
                "Equal"
                if alert_count == ticket_count
                else "Mismatch"
            )
        ),
        **status_display_fields(
            display_status
        )
    }


def build_homepage_tool_context(tool):

    alert_count = tool["alert_count"]
    ticket_count = tool["ticket_count"]
    bar_maximum = max(
        alert_count,
        ticket_count,
        1
    )

    return {
        **tool,
        "alert_bar_percentage": round(
            (alert_count / bar_maximum) * 100
        ),
        "ticket_bar_percentage": round(
            (ticket_count / bar_maximum) * 100
        )
    }


@app.get("/")
def dashboard(request: Request):

    data = load_dashboard_data()

    tools = [
        build_homepage_tool_context(
            build_tool_context(tool)
        )
        for tool in data.get("tools", [])
    ]

    total_alerts = sum(
        tool["alert_count"]
        for tool in tools
    )
    total_tickets = sum(
        tool["ticket_count"]
        for tool in tools
    )
    mismatch_count = sum(
        tool["mismatch_count"]
        for tool in tools
    )
    review_only_count = sum(
        max(
            tool.get("review_count", 0)
            - tool.get("mismatch_count", 0),
            0
        )
        for tool in tools
    )
    total_delta = sum(
        tool.get("coverage_delta", 0)
        for tool in tools
    )
    total_extra_tickets = sum(
        tool.get("extra_ticket_total", 0)
        for tool in tools
    )
    total_delta_display = (
        f"{total_extra_tickets} extra tickets"
        if total_extra_tickets
        else str(total_delta)
    )

    mismatch_issues = []
    affected_tools = []
    affected_clients = []

    for tool in tools:

        tool_has_mismatch = False

        for client in tool["clients"]:

            if client.get("tool_display_status") != "Mismatch":
                continue

            tool_has_mismatch = True
            client_name = client.get(
                "client",
                ""
            )
            mismatch_issues.append(
                {
                    "tool": tool["tool"],
                    "tool_key": tool["tool_key"],
                    "client": client_name,
                    "alert_count":
                        client["alert_count"],
                    "ticket_count":
                        client["ticket_count"],
                    "delta": client.get(
                        "coverage_delta",
                        0
                    ),
                    "delta_display":
                        client.get(
                            "coverage_delta_display",
                            "0"
                        )
                }
            )

            if client_name not in affected_clients:
                affected_clients.append(
                    client_name
                )

        if tool_has_mismatch:
            affected_tools.append(
                tool["tool"]
            )

    mismatch_issues.sort(
        key=lambda issue: (
            -abs(issue["delta"]),
            issue["tool"].casefold(),
            issue["client"].casefold()
        )
    )

    dashboard_context = {
        "alert_count": total_alerts,
        "ticket_count": total_tickets,
        "total_delta": total_delta,
        "total_delta_display":
            total_delta_display,
        "mismatch_count": mismatch_count,
        "review_count": mismatch_count + review_only_count,
        "review_only_count": review_only_count,
        "affected_tools": affected_tools,
        "affected_clients": affected_clients,
        "priority_issue": (
            mismatch_issues[0]
            if mismatch_issues
            else None
        ),
        "has_wazuh": any(
            tool["tool_key"] == "wazuh"
            for tool in tools
        )
    }

    dashboard_context["status"] = (
        "Mismatch"
        if mismatch_count
        else (
            "Review"
            if review_only_count
            else "Equal"
        )
    )
    dashboard_context.update(
        {
            "status_hero_class":
                dashboard_hero_class(
                    dashboard_context["status"]
                ),
            **status_display_fields(
                dashboard_context["status"]
            ),
            **priority_card_fields(
                dashboard_context["status"],
                dashboard_context["priority_issue"]
            )
        }
    )

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "timestamp": format_dashboard_timestamp(
                data.get("timestamp")
            ),
            "refresh_interval_seconds":
                REFRESH_INTERVAL_MINUTES * 60,
            "refresh_interval_minutes":
                REFRESH_INTERVAL_MINUTES,
            "dashboard": dashboard_context,
            "tools": tools
        }
    )


@app.get("/tool/{tool_name}")
def tool_dashboard(
    request: Request,
    tool_name: str
):

    data = load_dashboard_data()
    tool = find_tool(data, tool_name)

    if tool is None:
        raise HTTPException(
            status_code=404,
            detail="Tool not found"
        )

    tool_context = build_tool_context(
        tool
    )

    return templates.TemplateResponse(
        "tool.html",
        {
            "request": request,
            "tool": tool_context
        }
    )


@app.get(
    "/tool/{tool_name}/client/{client_name}"
)
def client_dashboard(
    request: Request,
    tool_name: str,
    client_name: str
):

    data = load_dashboard_data()
    tool = find_tool(data, tool_name)

    if tool is None:
        raise HTTPException(
            status_code=404,
            detail="Tool not found"
        )

    client = find_client(
        tool,
        client_name
    )

    if client is None:
        raise HTTPException(
            status_code=404,
            detail="Client not found"
        )

    client_context = build_client_context(
        client,
        tool_name
    )

    return templates.TemplateResponse(
        "client.html",
        {
            "request": request,
            "tool": tool,
            "client": client_context
        }
    )


@app.get("/health")
def health():
    return {"status": "running"}


@app.get("/api/data")
def get_data():

    data = load_dashboard_data()

    # Deprecated legacy compatibility endpoint for single-tool consumers.
    if isinstance(data, dict) and "tools" in data:

        tools = data.get(
            "tools",
            []
        )

        sentinelone = next(
            (
                tool
                for tool in tools
                if tool.get("tool_key")
                == "sentinelone"
            ),
            None
        )

        if sentinelone is None:
            return []

        legacy_data = {
            key: value
            for key, value
            in sentinelone.items()
            if key not in {
                "tool",
                "tool_key"
            }
        }

        legacy_data["timestamp"] = data.get(
            "timestamp"
        )

        return [
            legacy_data
        ]

    return data


@app.get("/api/dashboard")
def get_dashboard_data():

    return load_dashboard_data()


@app.post("/api/update")
async def update_data():

    raise HTTPException(
        status_code=405,
        detail=(
            "Dashboard data is generated by the scheduled collector. "
            "Direct updates are disabled."
        )
    )
