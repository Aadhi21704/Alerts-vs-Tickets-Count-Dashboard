from pathlib import Path
from datetime import datetime
import json
import scheduler
from zoneinfo import ZoneInfo
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
        {
            **client,
            "alert_count": client.get(
                "alert_count",
                client.get(
                    "sentinel_count",
                    0
                )
            ),
            "ticket_count": client.get(
                "ticket_count",
                client.get(
                    "jira_count",
                    0
                )
            )
        }
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

    return {
        **tool,
        "clients": clients,
        "alert_count": tool.get(
            "alert_count",
            tool.get(
                "total_alerts",
                tool.get(
                    "total_sentinel_count",
                    0
                )
            )
        ),
        "ticket_count": tool.get(
            "ticket_count",
            tool.get(
                "total_tickets",
                tool.get(
                    "total_jira_count",
                    0
                )
            )
        ),
        "client_count": len(clients),
        "mismatch_count": mismatch_count,
        "status":
            "Equal"
            if mismatch_count == 0
            else
            "Mismatch"
    }


@app.get("/")
def dashboard(request: Request):

    data = load_dashboard_data()

    tools = [
        build_tool_context(tool)
        for tool in data.get("tools", [])
    ]

    dashboard_context = {
        "tool_count": len(tools),
        "alert_count": sum(
            tool["alert_count"]
            for tool in tools
        ),
        "ticket_count": sum(
            tool["ticket_count"]
            for tool in tools
        ),
        "mismatch_count": sum(
            tool["mismatch_count"]
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

    client_context = {
        **client,
        "alert_count": client.get(
            "alert_count",
            client.get(
                "sentinel_count",
                0
            )
        ),
        "ticket_count": client.get(
            "ticket_count",
            client.get(
                "jira_count",
                0
            )
        )
    }

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

    # Temporary compatibility for the existing single-tool frontend.
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


@app.post("/api/update")
async def update_data(request: Request):

    payload = await request.json()

    with open(DATA_FILE, "w") as f:
        json.dump([payload], f, indent=4)

    return {
        "success": True
    }
