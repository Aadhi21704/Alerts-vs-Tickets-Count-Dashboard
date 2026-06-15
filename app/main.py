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


def build_tool_context(tool):

    clients = [
        build_client_context(client)
        for client in tool.get("clients", [])
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
        if client.get("status") != "Equal"
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

    return {
        **tool,
        "clients": clients,
        "alert_count": alert_count,
        "ticket_count": ticket_count,
        "delta": delta,
        "delta_display": f"{delta:+d}",
        "client_count": len(clients),
        "mismatch_count": mismatch_count,
        "status":
            "Equal"
            if mismatch_count == 0
            else
            "Mismatch"
    }


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

    return {
        **client,
        "alert_count": alert_count,
        "ticket_count": ticket_count,
        "delta": delta,
        "delta_display": f"{delta:+d}",
        "display_tickets": (
            list(reversed(tickets))
            if alerts and tickets
            else tickets
        ),
        "status": (
            "Equal"
            if alert_count == ticket_count
            else "Mismatch"
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
    delta = alert_count - ticket_count

    return {
        **tool,
        "delta": delta,
        "delta_display": f"{delta:+d}",
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
    total_delta = total_alerts - total_tickets

    mismatch_issues = []
    affected_tools = []
    affected_clients = []

    for tool in tools:

        tool_has_mismatch = False

        for client in tool["clients"]:

            if client.get("status") == "Equal":
                continue

            tool_has_mismatch = True
            client_name = client.get(
                "client",
                ""
            )
            client_delta = (
                client["alert_count"]
                - client["ticket_count"]
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
                    "delta": client_delta,
                    "delta_display":
                        f"{client_delta:+d}"
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
            f"{total_delta:+d}",
        "mismatch_count": mismatch_count,
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
        "Equal"
        if dashboard_context["mismatch_count"] == 0
        else
        "Mismatch"
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
