from datetime import datetime, timedelta, UTC

import requests

from config import (
    MSSP_ALLOWED_CLIENTS,
    RESSELLER_EXCLUDED_CLIENTS,
    DAYS_BACK
)


def fetch_sentinelone_alerts(
    source_name,
    url,
    api_token,
    filter_clients
):

    created_after = (
        datetime.now(UTC)
        - timedelta(days=DAYS_BACK)
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
                "source": source_name
            }
        )

    return filtered_alerts