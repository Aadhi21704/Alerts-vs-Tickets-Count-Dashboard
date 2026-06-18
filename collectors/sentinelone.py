from datetime import datetime, timedelta, UTC

import requests

from config import (
    MSSP_ALLOWED_CLIENTS,
    RESSELLER_EXCLUDED_CLIENTS,
    SENTINELONE_ALERT_WINDOW_HOURS
)


def _safe_string(value):
    if value is None:
        return ""

    return str(value)


def _extract_sentinelone_safe_fields(alert):
    threat_info = alert.get(
        "threatInfo",
        {}
    )

    if not isinstance(threat_info, dict):
        threat_info = {}

    source_id = _safe_string(
        alert.get("id")
    )

    threat_id = _safe_string(
        threat_info.get("threatId")
    )

    console_url = _safe_string(
        threat_info.get("consoleUrl")
    )

    safe_fields = {
        "sentinelone_source_id":
            source_id,
        "sentinelone_threat_id":
            threat_id or source_id,
        "sentinelone_threat_name":
            _safe_string(
                threat_info.get("threatName")
            ),
        "sentinelone_created_at":
            _safe_string(
                threat_info.get("createdAt")
            ),
        "sentinelone_updated_at":
            _safe_string(
                threat_info.get("updatedAt")
            ),
        "sentinelone_incident_status":
            _safe_string(
                threat_info.get("incidentStatus")
            ),
        "sentinelone_detection_type":
            _safe_string(
                threat_info.get("detectionType")
            )
    }

    if console_url:
        safe_fields[
            "sentinelone_console_url"
        ] = console_url
        safe_fields[
            "sentinelone_threat_url"
        ] = console_url

    return safe_fields


def fetch_sentinelone_alerts(
    source_name,
    url,
    api_token,
    filter_clients
):

    created_after = (
        datetime.now(UTC)
        - timedelta(
            hours=SENTINELONE_ALERT_WINDOW_HOURS
        )
    ).isoformat()

    headers = {
        "Authorization": f"ApiToken {api_token}"
    }

    params = {
        "createdAt__gte": created_after,
        "limit": 1000
    }

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=60
    )

    response.raise_for_status()

    data = response.json()

    alerts = data.get(
        "data",
        []
    )

    filtered_alerts = []

    for alert in alerts:

        site_name = (
            alert
            .get(
                "agentDetectionInfo",
                {}
            )
            .get(
                "siteName",
                "Unknown"
            )
        )

        if (
            source_name == "reseller"
            and
            site_name in RESSELLER_EXCLUDED_CLIENTS
        ):
            continue

        if (
            filter_clients
            and
            site_name not in MSSP_ALLOWED_CLIENTS
        ):
            continue

        filtered_alerts.append(
            {
                "id": alert["id"],
                "client": site_name,
                "source": source_name,
                **_extract_sentinelone_safe_fields(
                    alert
                )
            }
        )

    return filtered_alerts
