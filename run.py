import json
import os
import urllib3

from dotenv import load_dotenv

from logger import logger

from config import (
    MANAGED_CLIENTS,
    SENTINELONE_CLIENT_MAPPING,
    SENTINELONE_SOURCES
)

from collectors.sentinelone import (
    fetch_sentinelone_alerts
)

from collectors.wazuh import (
    fetch_wazuh_alerts
)

from collectors.jira import (
    fetch_jira_tickets,
    fetch_wazuh_jira_tickets
)

from comparison.comparator import (
    compare_count_data,
    compare_data
)

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

load_dotenv()


def main():

    try:

        logger.info(
            "Collection cycle started"
        )

        jira_email = os.getenv(
            "JIRA_EMAIL"
        )

        jira_token = os.getenv(
            "JIRA_API_TOKEN"
        )

        if not jira_email:
            raise ValueError(
                "JIRA_EMAIL not set"
            )

        if not jira_token:
            raise ValueError(
                "JIRA_API_TOKEN not set"
            )

        sentinel_alerts = []

        for source in SENTINELONE_SOURCES:

            source_name = source["name"]

            source_url = source["url"]

            token_env = source["token_env"]

            api_token = os.getenv(
                token_env
            )

            if not api_token:
                raise ValueError(
                    f"{token_env} not set"
                )

            source_alerts = (
                fetch_sentinelone_alerts(
                    source_name,
                    source_url,
                    api_token,
                    source["filter_clients"]
                )
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

        jira_tickets = (
            fetch_jira_tickets(
                jira_email,
                jira_token
            )
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
            client_mapping=
                SENTINELONE_CLIENT_MAPPING
        )

        timestamp = sentinelone_result[
            "timestamp"
        ]

        sentinelone_tool_result = {
            key: value
            for key, value
            in sentinelone_result.items()
            if key != "timestamp"
        }

        whb_api_key = os.getenv(
            "WHB_API_KEY"
        )

        if not whb_api_key:
            raise ValueError(
                "WHB_API_KEY not set"
            )

        wazuh_alert_counts = (
            fetch_wazuh_alerts(
                whb_api_key
            )
        )

        logger.info(
            f"Wazuh: "
            f"{sum(
                record['count']
                for record in wazuh_alert_counts
            )} alerts retrieved"
        )

        wazuh_jira_tickets = (
            fetch_wazuh_jira_tickets(
                jira_email,
                jira_token
            )
        )

        logger.info(
            f"Wazuh Jira: "
            f"{len(wazuh_jira_tickets)} "
            f"tickets retrieved"
        )

        wazuh_result = compare_count_data(
            wazuh_alert_counts,
            wazuh_jira_tickets,
            source="wazuh"
        )

        dashboard_data = {
            "timestamp": timestamp,
            "tools": [
                {
                    "tool": "SentinelOne",
                    "tool_key": "sentinelone",
                    **sentinelone_tool_result
                },
                {
                    "tool": "Wazuh",
                    "tool_key": "wazuh",
                    **wazuh_result
                }
            ]
        }

        with open(
            "latest.json",
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                dashboard_data,
                f,
                indent=2
            )

        logger.info(
            "latest.json updated successfully"
        )

        print(
            "latest.json updated"
        )

    except Exception as e:

        logger.exception(
            f"Collection cycle failed: {e}"
        )

        raise


if __name__ == "__main__":
    main()
