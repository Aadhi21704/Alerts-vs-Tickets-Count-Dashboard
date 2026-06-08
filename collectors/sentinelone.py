from datetime import datetime, timedelta, UTC

import requests


ALLOWED_CLIENTS = [
    "QuisLex",
    "CapLaw",
    "LegalOps",
    "LCRA",
    "Consint.ai",
    "NopalCyber"
]


def fetch_sentinelone_alerts(api_token):

    url = (
        "https://usea1-002-mssp.sentinelone.net/"
        "web/api/v2.1/threats"
    )

    created_after = (
        datetime.now(UTC)
        - timedelta(days=14)
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

    alerts = (
        data.get("data", [])
    )

    alerts = [
        {
            "id": alert["id"],
            "client":
                alert
                .get(
                    "agentDetectionInfo",
                    {}
                )
                .get(
                    "siteName",
                    "Unknown"
                )
        }
        for alert in alerts
        if (
            alert
            .get(
                "agentDetectionInfo",
                {}
            )
            .get(
                "siteName"
            )
            in ALLOWED_CLIENTS
        )
    ]

    return alerts