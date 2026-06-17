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


def _safe_wazuh_by_rule_evidence(rule_row):

    if not isinstance(rule_row, dict):
        return None

    return {
        # WHB by_rule is grouped; this is a representative alert id sample.
        "sample_alert_id": str(
            rule_row.get(
                "id",
                ""
            )
        ),
        "rule_id": str(
            rule_row.get(
                "rule_id",
                ""
            )
        ),
        "count": rule_row.get(
            "count",
            0
        ),
        "level": rule_row.get(
            "level",
            ""
        ),
        "location": rule_row.get(
            "location",
            ""
        ),
        "description": rule_row.get(
            "description",
            ""
        )
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

    if data.get("aggregation") != "latest_per_client":
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

    allowed_clients = set(
        WAZUH_ALLOWED_CLIENTS
    )

    client_records = {}

    for row in rows:

        if not isinstance(row, dict):
            raise ValueError(
                "Invalid Wazuh row"
            )

        client_data = row.get(
            "client",
            {}
        )

        if not isinstance(client_data, dict):
            raise ValueError(
                "Invalid Wazuh client"
            )

        raw_client = client_data.get(
            "name",
            ""
        )

        if not isinstance(raw_client, str):
            raise ValueError(
                "Invalid Wazuh client name"
            )

        raw_client = raw_client.strip()

        if raw_client not in allowed_clients:
            continue

        total_count = row.get(
            "total_count"
        )

        if (
            type(total_count) is not int
            or
            total_count < 0
        ):
            raise ValueError(
                "Invalid Wazuh total_count for "
                f"{raw_client}"
            )

        client = WAZUH_CLIENT_MAPPING.get(
            raw_client,
            raw_client
        ).strip()

        if client not in client_records:
            client_records[client] = {
                "count": 0,
                "wazuh_source_evidence": []
            }

        client_records[client]["count"] += (
            total_count
        )

        by_rule = row.get(
            "by_rule",
            []
        )

        if not isinstance(by_rule, list):
            raise ValueError(
                "Invalid Wazuh by_rule response for "
                f"{raw_client}"
            )

        for rule_row in by_rule:

            evidence = _safe_wazuh_by_rule_evidence(
                rule_row
            )

            if evidence is None:
                raise ValueError(
                    "Invalid Wazuh by_rule row for "
                    f"{raw_client}"
                )

            client_records[client][
                "wazuh_source_evidence"
            ].append(
                evidence
            )

    return [
        {
            "tool": "Wazuh",
            "client": client,
            "count": record["count"],
            "alerts": record[
                "wazuh_source_evidence"
            ],
            "wazuh_source_evidence":
                record["wazuh_source_evidence"],
            "source": "wazuh"
        }
        for client, record
        in sorted(client_records.items())
    ]
