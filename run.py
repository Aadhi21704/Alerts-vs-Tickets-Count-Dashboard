import json
import os
import urllib3

from dotenv import load_dotenv

from logger import logger

from config import SENTINELONE_SOURCES

from collectors.sentinelone import (
    fetch_sentinelone_alerts
)

from collectors.jira import (
    fetch_jira_tickets
)

from comparison.comparator import (
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

        result = compare_data(
            sentinel_alerts,
            jira_tickets
        )

        with open(
            "latest.json",
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                [result],
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