import json
import os
from datetime import datetime, UTC
from pathlib import Path

import urllib3

from dotenv import load_dotenv

from logger import logger

from config import (
    MANAGED_CLIENTS,
    REFRESH_INTERVAL_MINUTES,
    SENTINELONE_CLIENT_MAPPING,
    SENTINELONE_SOURCES,
    STALE_AFTER_MINUTES,
    WAZUH_CLIENT_MAPPING
)

from collectors.sentinelone import (
    fetch_sentinelone_alerts
)

from collectors.wazuh import (
    fetch_wazuh_alerts
)

from collectors.securonix import (
    fetch_securonix_incidents
)

from collectors.jira import (
    fetch_jira_tickets,
    fetch_securonix_jira_tickets,
    fetch_wazuh_jira_tickets_for_correlation
)

from comparison.comparator import (
    compare_data,
    compare_list_data,
    compare_wazuh_correlation_data
)

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

load_dotenv()

DATA_FILE = Path("latest.json")


def _utc_now():
    return datetime.now(UTC)


def _iso(timestamp):
    return timestamp.isoformat()


def _duration_seconds(started_at, finished_at):
    return round(
        (
            finished_at
            - started_at
        ).total_seconds(),
        3
    )


def _load_previous_dashboard():
    if not DATA_FILE.exists():
        return {}

    try:
        with DATA_FILE.open(
            "r",
            encoding="utf-8"
        ) as f:
            return json.load(f)
    except Exception:
        logger.warning(
            "Unable to read previous latest.json metadata"
        )
        return {}


def _previous_tool(previous_dashboard, tool_key):
    for tool in previous_dashboard.get(
        "tools",
        []
    ):
        if tool.get("tool_key") == tool_key:
            return tool

    return {}


def _previous_last_success(previous_dashboard, tool_key):
    previous_tool = _previous_tool(
        previous_dashboard,
        tool_key
    )

    previous_collection = previous_tool.get(
        "collection",
        {}
    )

    return previous_collection.get(
        "last_success_at"
    )


def _safe_error(tool_name, exception):
    exception_type = type(exception).__name__

    request_error_types = {
        "ConnectionError",
        "ConnectTimeout",
        "HTTPError",
        "ProxyError",
        "ReadTimeout",
        "RequestException",
        "SSLError",
        "Timeout"
    }

    if exception_type in request_error_types:
        safe_detail = "API request failed"
    elif exception_type == "JSONDecodeError":
        safe_detail = "Invalid API response"
    elif exception_type == "ValueError":
        safe_detail = "Configuration or response validation failed"
    else:
        safe_detail = "Collection failed"

    return {
        "type": exception_type,
        "message": f"{tool_name} collection failed",
        "safe_detail": safe_detail
    }


def _tool_collection(
    status,
    started_at,
    finished_at,
    last_success_at,
    error=None
):
    return {
        "status": status,
        "last_attempt_at": _iso(started_at),
        "last_success_at": last_success_at,
        "duration_seconds": _duration_seconds(
            started_at,
            finished_at
        ),
        "error": error
    }


def _failed_tool(
    tool_name,
    tool_key,
    started_at,
    finished_at,
    error,
    previous_dashboard
):
    return {
        "tool": tool_name,
        "tool_key": tool_key,
        "clients": [],
        "total_alerts": 0,
        "total_tickets": 0,
        "collection": _tool_collection(
            "failed",
            started_at,
            finished_at,
            _previous_last_success(
                previous_dashboard,
                tool_key
            ),
            error
        )
    }


def _require_env(name):
    value = os.getenv(name)

    if not value:
        raise ValueError(
            f"{name} not set"
        )

    return value


def _atomic_write_json(path, data):
    temp_path = path.with_name(
        f"{path.name}.tmp"
    )

    with temp_path.open(
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            data,
            f,
            indent=2
        )
        f.write("\n")
        f.flush()
        os.fsync(
            f.fileno()
        )

    os.replace(
        temp_path,
        path
    )


def _collect_sentinelone(
    previous_dashboard
):
    tool_name = "SentinelOne"
    tool_key = "sentinelone"
    started_at = _utc_now()

    try:
        jira_email = _require_env(
            "JIRA_EMAIL"
        )
        jira_token = _require_env(
            "JIRA_API_TOKEN"
        )

        sentinel_alerts = []

        for source in SENTINELONE_SOURCES:

            source_name = source["name"]
            api_token = _require_env(
                source["token_env"]
            )

            source_alerts = fetch_sentinelone_alerts(
                source_name,
                source["url"],
                api_token,
                source["filter_clients"]
            )

            logger.info(
                f"{source_name.upper()}: "
                f"{len(source_alerts)} alerts retrieved"
            )

            sentinel_alerts.extend(
                source_alerts
            )

        logger.info(
            f"Total SentinelOne: "
            f"{len(sentinel_alerts)} alerts retrieved"
        )

        jira_tickets = fetch_jira_tickets(
            jira_email,
            jira_token
        )

        logger.info(
            f"Jira: "
            f"{len(jira_tickets)} tickets retrieved"
        )

        sentinelone_result = compare_data(
            sentinel_alerts,
            jira_tickets,
            managed_clients=MANAGED_CLIENTS.get(
                "sentinelone",
                {}
            ),
            client_mapping=SENTINELONE_CLIENT_MAPPING
        )

        finished_at = _utc_now()
        tool_result = {
            key: value
            for key, value
            in sentinelone_result.items()
            if key != "timestamp"
        }
        tool_result.update(
            {
                "tool": tool_name,
                "tool_key": tool_key,
                "collection": _tool_collection(
                    "success",
                    started_at,
                    finished_at,
                    _iso(finished_at)
                )
            }
        )

        return tool_result

    except Exception as exception:
        finished_at = _utc_now()
        error = _safe_error(
            tool_name,
            exception
        )
        logger.exception(
            f"{tool_name} collection failed"
        )

        return _failed_tool(
            tool_name,
            tool_key,
            started_at,
            finished_at,
            error,
            previous_dashboard
        )


def _collect_wazuh(
    previous_dashboard
):
    tool_name = "Wazuh"
    tool_key = "wazuh"
    started_at = _utc_now()

    try:
        jira_email = _require_env(
            "JIRA_EMAIL"
        )
        jira_token = _require_env(
            "JIRA_API_TOKEN"
        )
        whb_api_key = _require_env(
            "WHB_API_KEY"
        )

        wazuh_alert_counts = fetch_wazuh_alerts(
            whb_api_key
        )

        logger.info(
            f"Wazuh: "
            f"{sum(
                record['count']
                for record in wazuh_alert_counts
            )} alerts retrieved"
        )

        wazuh_jira_tickets = (
            fetch_wazuh_jira_tickets_for_correlation(
                jira_email,
                jira_token
            )
        )

        logger.info(
            f"Wazuh Jira: "
            f"{len(wazuh_jira_tickets)} "
            f"tickets retrieved"
        )

        wazuh_result = compare_wazuh_correlation_data(
            wazuh_alert_counts,
            wazuh_jira_tickets,
            source="wazuh",
            managed_clients=sorted(
                set(
                    WAZUH_CLIENT_MAPPING.values()
                )
            )
        )

        finished_at = _utc_now()
        wazuh_result.update(
            {
                "tool": tool_name,
                "tool_key": tool_key,
                "collection": _tool_collection(
                    "success",
                    started_at,
                    finished_at,
                    _iso(finished_at)
                )
            }
        )

        return wazuh_result

    except Exception as exception:
        finished_at = _utc_now()
        error = _safe_error(
            tool_name,
            exception
        )
        logger.exception(
            f"{tool_name} collection failed"
        )

        return _failed_tool(
            tool_name,
            tool_key,
            started_at,
            finished_at,
            error,
            previous_dashboard
        )


def _collect_securonix(
    previous_dashboard
):
    tool_name = "Securonix"
    tool_key = "securonix"
    started_at = _utc_now()

    try:
        jira_email = _require_env(
            "JIRA_EMAIL"
        )
        jira_token = _require_env(
            "JIRA_API_TOKEN"
        )
        securonix_base_url = _require_env(
            "SECURONIX_BASE_URL"
        )
        securonix_token = _require_env(
            "SECURONIX_TOKEN"
        )

        securonix_incidents = fetch_securonix_incidents(
            securonix_base_url,
            securonix_token
        )

        logger.info(
            f"Securonix: "
            f"{len(securonix_incidents)} "
            f"incidents retrieved"
        )

        securonix_jira_tickets = (
            fetch_securonix_jira_tickets(
                jira_email,
                jira_token
            )
        )

        logger.info(
            f"Securonix Jira: "
            f"{len(securonix_jira_tickets)} "
            f"tickets retrieved"
        )

        securonix_result = compare_list_data(
            securonix_incidents,
            securonix_jira_tickets,
            source="securonix",
            managed_clients=MANAGED_CLIENTS.get(
                "securonix",
                {}
            )
        )

        finished_at = _utc_now()
        securonix_result.update(
            {
                "tool": tool_name,
                "tool_key": tool_key,
                "collection": _tool_collection(
                    "success",
                    started_at,
                    finished_at,
                    _iso(finished_at)
                )
            }
        )

        return securonix_result

    except Exception as exception:
        finished_at = _utc_now()
        error = _safe_error(
            tool_name,
            exception
        )
        logger.exception(
            f"{tool_name} collection failed"
        )

        return _failed_tool(
            tool_name,
            tool_key,
            started_at,
            finished_at,
            error,
            previous_dashboard
        )


def _collection_status(tools):
    successes = sum(
        1
        for tool in tools
        if tool.get(
            "collection",
            {}
        ).get("status") == "success"
    )

    if successes == len(tools):
        return "success"

    if successes:
        return "partial_success"

    return "failed"


def main():
    collection_started_at = _utc_now()

    logger.info(
        "Collection cycle started"
    )

    previous_dashboard = _load_previous_dashboard()

    tools = [
        _collect_sentinelone(
            previous_dashboard
        ),
        _collect_wazuh(
            previous_dashboard
        ),
        _collect_securonix(
            previous_dashboard
        )
    ]

    collection_finished_at = _utc_now()
    status = _collection_status(
        tools
    )
    previous_collection = previous_dashboard.get(
        "collection",
        {}
    )
    previous_last_success_at = previous_collection.get(
        "last_success_at"
    ) or previous_dashboard.get(
        "timestamp"
    )
    last_success_at = (
        _iso(collection_finished_at)
        if status == "success"
        else previous_last_success_at
    )

    dashboard_data = {
        "timestamp": _iso(collection_finished_at),
        "collection": {
            "status": status,
            "started_at": _iso(collection_started_at),
            "finished_at": _iso(collection_finished_at),
            "duration_seconds": _duration_seconds(
                collection_started_at,
                collection_finished_at
            ),
            "refresh_interval_minutes":
                REFRESH_INTERVAL_MINUTES,
            "stale_after_minutes":
                STALE_AFTER_MINUTES,
            "is_stale": False,
            "last_success_at": last_success_at
        },
        "tools": tools
    }

    _atomic_write_json(
        DATA_FILE,
        dashboard_data
    )

    logger.info(
        "latest.json updated successfully"
    )

    print(
        "latest.json updated"
    )


if __name__ == "__main__":
    main()
