import requests

from config import (
    DAYS_BACK,
    JIRA_URL
)

def get_cell_text(cell):

    text_parts = []

    for paragraph in cell.get("content", []):

        for item in paragraph.get(
            "content",
            []
        ):

            if item.get("type") == "text":

                text_parts.append(
                    item.get("text", "")
                )

    return "".join(text_parts)


def extract_site_name(description):

    try:

        for section in description.get(
            "content",
            []
        ):

            if section.get("type") != "table":
                continue

            rows = section.get(
                "content",
                []
            )

            for row in rows:

                cells = row.get(
                    "content",
                    []
                )

                if len(cells) < 2:
                    continue

                key_text = get_cell_text(
                    cells[0]
                )

                value_text = get_cell_text(
                    cells[1]
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
        issuetype = SentinelOne
        AND created >= -{DAYS_BACK}d
        AND project = NSIR
        ORDER BY created DESC
    '''.strip()

    all_issues = []

    next_page_token = None

    while True:

        params = {
            "jql": jql,
            "maxResults": 1000,
            "fields":
                "summary,"
                "created,"
                "description"
        }

        if next_page_token:

            params[
                "nextPageToken"
            ] = next_page_token

        response = requests.get(
            url,
            auth=(email, api_token),
            params=params,
            timeout=60,
            verify=False
        )

        response.raise_for_status()

        data = response.json()

        issues = data.get(
            "issues",
            []
        )

        print(
            f"PAGE: {len(all_issues)} "
            f"+ {len(issues)} "
            f"isLast={data.get('isLast')} "
            f"token={bool(data.get('nextPageToken'))}"
        )

        all_issues.extend(
            issues
        )

        if data.get(
            "isLast",
            True
        ):
            print("REACHED LAST PAGE")
            break

        next_page_token = data.get(
            "nextPageToken"
        )

        if not next_page_token:
            break

    tickets = []

    for issue in all_issues:

        client = extract_site_name(
            issue["fields"].get(
                "description",
                {}
            )
        )

        if client == "Unknown":
            continue
        
        if "Greenko" in client:
            print(
                issue["key"],
                "=>",
                client
            )

        tickets.append(
            {
                "key": issue["key"],
                "client": client,
                "summary":
                    issue["fields"].get(
                        "summary",
                        ""
                    ),
                "created":
                    issue["fields"].get(
                        "created",
                        ""
                    )
            }
        )

    return tickets