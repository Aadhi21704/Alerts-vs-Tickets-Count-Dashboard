from datetime import datetime, timedelta, UTC

import requests

from config import (
    SECURONIX_ALLOWED_CLIENTS,
    SECURONIX_CLIENT_MAPPING,
    SECURONIX_INCIDENT_PAGE_SIZE,
    SECURONIX_INCIDENT_WINDOW_HOURS,
    SECURONIX_VERIFY_SSL
)


def _epoch_milliseconds(timestamp):

    return int(
        timestamp.timestamp()
        * 1000
    )


def fetch_securonix_incidents(
    base_url,
    token
):

    if not isinstance(base_url, str):
        raise ValueError(
            "SECURONIX_BASE_URL not set"
        )

    if not isinstance(token, str):
        raise ValueError(
            "SECURONIX_TOKEN not set"
        )

    base_url = base_url.strip()
    token = token.strip()

    if not base_url:
        raise ValueError(
            "SECURONIX_BASE_URL not set"
        )

    if not token:
        raise ValueError(
            "SECURONIX_TOKEN not set"
        )

    now = datetime.now(UTC)
    opened_after = now - timedelta(
        hours=SECURONIX_INCIDENT_WINDOW_HOURS
    )

    url = (
        f"{base_url.rstrip('/')}"
        "/ws/incident/get"
    )

    headers = {
        "token": token,
        "Accept":
            "application/vnd.snypr.app-v6.0+json"
    }

    allowed_clients = set(
        SECURONIX_ALLOWED_CLIENTS
    )

    incidents = []
    offset = 0
    page_size = SECURONIX_INCIDENT_PAGE_SIZE
    total_incidents = None

    while True:

        params = {
            "type": "list",
            "from": _epoch_milliseconds(
                opened_after
            ),
            "to": _epoch_milliseconds(
                now
            ),
            "rangeType": "opened",
            "offset": offset,
            "max": page_size,
            "order": "desc"
        }

        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=60,
            verify=SECURONIX_VERIFY_SSL
        )

        response.raise_for_status()

        data = response.json()

        if data.get("status") != "OK":
            raise ValueError(
                "Unexpected Securonix status"
            )

        result_data = (
            data
            .get("result", {})
            .get("data", {})
        )

        if total_incidents is None:
            total_incidents = result_data.get(
                "totalIncidents",
                0
            )

            if (
                isinstance(total_incidents, str)
                and
                total_incidents.isdigit()
            ):
                total_incidents = int(
                    total_incidents
                )

            if (
                isinstance(total_incidents, float)
                and
                total_incidents.is_integer()
            ):
                total_incidents = int(
                    total_incidents
                )

            if type(total_incidents) is not int:
                raise ValueError(
                    "Invalid Securonix totalIncidents"
                )

        items = result_data.get(
            "incidentItems",
            []
        )

        if not isinstance(items, list):
            raise ValueError(
                "Invalid Securonix incidentItems"
            )

        if not items:
            break

        for item in items:

            if not isinstance(item, dict):
                raise ValueError(
                    "Invalid Securonix incident"
                )

            tenant_info = item.get(
                "tenantInfo",
                {}
            )

            if not isinstance(tenant_info, dict):
                continue

            raw_client = tenant_info.get(
                "tenantname"
            )

            if not isinstance(raw_client, str):
                continue

            raw_client = raw_client.strip()
            client = SECURONIX_CLIENT_MAPPING.get(
                raw_client,
                raw_client
            )

            if client not in allowed_clients:
                continue

            incidents.append(
                {
                    "id": item.get("incidentId"),
                    "client": client,
                    "created":
                        item.get("casecreatetime"),
                    "updated":
                        item.get("lastUpdateDate"),
                    "status":
                        item.get("incidentStatus"),
                    "priority":
                        item.get("priority"),
                    "assigned_user":
                        item.get("assignedUser"),
                    "incident_type":
                        item.get("incidentType"),
                    "risk_score":
                        item.get("riskscore"),
                    "mitre_tactic":
                        item.get("mitre_tactic"),
                    "mitre_technique":
                        item.get("mitre_technique"),
                    "url": item.get("url")
                }
            )

        returned_count = len(items)
        offset += returned_count

        if offset >= total_incidents:
            break

        if returned_count < page_size:
            break

    return incidents
