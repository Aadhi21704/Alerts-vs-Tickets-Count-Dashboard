from pathlib import Path
from datetime import datetime
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
        build_client_context(client)
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
        ]
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


def build_client_context(client):

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

    return {
        **client,
        "alert_count": alert_count,
        "ticket_count": ticket_count,
        "delta": delta,
        "delta_display": soc_display[
            "coverage_delta_display"
        ],
        **soc_display,
        "display_tickets": (
            list(reversed(tickets))
            if alerts and tickets
            else tickets
        ),
        "status": client.get(
            "status",
            (
                "Equal"
                if alert_count == ticket_count
                else "Mismatch"
            )
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
        client
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
