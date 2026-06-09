import requests

from config import (
    DAYS_BACK,
    JIRA_URL
)

def extract_site_name(description):

    try:

        content = (
            description.get("content", [])
        )

        for section in content:

            if (
                section.get("type")
                != "table"
            ):
                continue

            rows = (
                section.get(
                    "content",
                    []
                )
            )

            for row in rows:

                cells = (
                    row.get(
                        "content",
                        []
                    )
                )

                if len(cells) < 2:
                    continue

                key_text = (
                    cells[0]
                    .get("content", [{}])[0]
                    .get("content", [{}])[0]
                    .get("text", "")
                )

                value_text = (
                    cells[1]
                    .get("content", [{}])[0]
                    .get("content", [{}])[0]
                    .get("text", "")
                )

                if key_text == "Site Name":
                    return value_text

    except Exception:
        pass

    return "Unknown"


def fetch_jira_tickets(
    email,
    api_token
):

    url = JIRA_URL

    jql = f'''
        "tenant name[labels]" IN (QuisLex, CapLaw, LegalOps, LCRA, Consint.ai, NopalCyber)
        AND issuetype = SentinelOne
        AND created >= -{DAYS_BACK}d
        AND project = NSIR
        ORDER BY created DESC
        '''.strip()

    response = requests.get(
        url,
        auth=(email, api_token),
        params={
            "jql": jql,
            "maxResults": 1000,
            "fields":
                "summary,"
                "created,"
                "description"
        },
        timeout=60,
        verify=False
    )

    response.raise_for_status()

    data = response.json()

    issues = (
        data.get("issues", [])
    )

    return [
        {
            "key":
                issue["key"],

            "client":
                extract_site_name(
                    issue["fields"]
                    .get(
                        "description",
                        {}
                    )
                ),

            "summary":
                issue["fields"]
                .get(
                    "summary",
                    ""
                ),

            "created":
                issue["fields"]
                .get(
                    "created",
                    ""
                )
        }

        for issue in issues
    ]