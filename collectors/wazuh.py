import requests

from config import (
    WAZUH_ALLOWED_CLIENTS,
    WAZUH_CLIENT_MAPPING,
    WAZUH_HOURS,
    WAZUH_LIMIT,
    WAZUH_MIN_RULE_LEVEL,
    WAZUH_URL,
    WAZUH_VERIFY_SSL
)


def _clean_string(value):
    if value is None:
        return ""

    return str(value).strip()


def _safe_wazuh_alert(row):
    if not isinstance(row, dict):
        return None

    client_data = row.get("client", {})
    agent_data = row.get("agent", {})

    if not isinstance(client_data, dict):
        client_data = {}

    if not isinstance(agent_data, dict):
        agent_data = {}

    raw_client = _clean_string(
        client_data.get("name")
    )

    if raw_client not in WAZUH_ALLOWED_CLIENTS:
        return None

    client = _clean_string(
        WAZUH_CLIENT_MAPPING.get(
            raw_client,
            raw_client
        )
    )

    alert_id = _clean_string(
        row.get("alert_id")
    )

    if not alert_id:
        return None

    timestamp = _clean_string(
        row.get("timestamp")
    )

    level = row.get("level", "")

    return {
        "tool": "Wazuh",
        "id": alert_id,
        "wazuh_alert_id": alert_id,
        "alert_id": alert_id,
        "source_id": alert_id,
        "client": client,
        "client_id": _clean_string(
            client_data.get("id")
        ),
        "client_code": _clean_string(
            client_data.get("code")
        ),
        "timestamp": timestamp,
        "created_at": timestamp,
        "rule_id": _clean_string(
            row.get("rule_id")
        ),
        "level": level,
        "rule_level": level,
        "description": _clean_string(
            row.get("description")
        ),
        "location": _clean_string(
            row.get("location")
        ),
        "agent_id": _clean_string(
            agent_data.get("id")
        ),
        "agent_name": _clean_string(
            agent_data.get("name")
        ),
        "source": "wazuh"
    }


def fetch_wazuh_alerts(api_key):

    if not isinstance(api_key, str):
        raise ValueError(
            "WHB_API_KEY not set"
        )

    api_key = api_key.strip()

    if not api_key:
        raise ValueError(
            "WHB_API_KEY not set"
        )

    headers = {
        "X-WHB-API-Key": api_key
    }

    params = {
        "hours": WAZUH_HOURS,
        "limit": WAZUH_LIMIT
    }

    response = requests.get(
        WAZUH_URL,
        headers=headers,
        params=params,
        timeout=60,
        verify=WAZUH_VERIFY_SSL
    )

    response.raise_for_status()

    data = response.json()

    if data.get("aggregation") != "per_alert":
        raise ValueError(
            "Unexpected Wazuh aggregation"
        )

    filters = data.get(
        "filters",
        {}
    )

    min_rule_level = filters.get(
        "min_rule_level"
    )

    if min_rule_level != WAZUH_MIN_RULE_LEVEL:
        raise ValueError(
            "Unexpected Wazuh minimum rule level"
        )

    rows = data.get(
        "rows",
        []
    )

    if not isinstance(rows, list):
        raise ValueError(
            "Invalid Wazuh rows response"
        )

    alerts = []

    for row in rows:
        alert = _safe_wazuh_alert(row)

        if alert is not None:
            alerts.append(alert)

    alerts.sort(
        key=lambda alert: (
            alert.get("client", "").casefold(),
            alert.get("timestamp", ""),
            alert.get("wazuh_alert_id", "")
        )
    )

    return alerts
