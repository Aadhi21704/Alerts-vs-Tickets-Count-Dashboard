import json
import os
import urllib3
from dotenv import load_dotenv
from collectors.sentinelone import (
    fetch_sentinelone_alerts
)

from collectors.jira import (
    fetch_jira_tickets
)

from comparison.comparator import (
    compare_data
)


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

def main():

    s1_token = os.getenv(
        "S1_API_TOKEN"
    )

    jira_email = os.getenv(
        "JIRA_EMAIL"
    )

    jira_token = os.getenv(
        "JIRA_API_TOKEN"
    )

    if not s1_token:
        raise ValueError(
            "S1_API_TOKEN not set"
        )

    if not jira_email:
        raise ValueError(
            "JIRA_EMAIL not set"
        )

    if not jira_token:
        raise ValueError(
            "JIRA_API_TOKEN not set"
        )

    sentinel_alerts = (
        fetch_sentinelone_alerts(
            s1_token
        )
    )

    jira_tickets = (
        fetch_jira_tickets(
            jira_email,
            jira_token
        )
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

    print("latest.json updated")


if __name__ == "__main__":
    main()