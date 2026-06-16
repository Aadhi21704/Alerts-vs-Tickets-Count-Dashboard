import requests

from config import (
    JIRA_URL,
    SECURONIX_ALLOWED_CLIENTS,
    SECURONIX_JIRA_TENANT_FIELD,
    SECURONIX_JIRA_WINDOW_HOURS,
    SENTINELONE_JIRA_WINDOW_HOURS,
    WAZUH_CLIENT_MAPPING,
    WAZUH_JIRA_WINDOW_HOURS,
    WAZUH_JIRA_TENANT_FIELD
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


def _fetch_jira_issues(
    email,
    api_token,
    jql,
    fields
):

    url = JIRA_URL

    all_issues = []

    next_page_token = None

    while True:

        params = {
            "jql": jql,
            "maxResults": 1000,
            "fields": ",".join(fields)
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

    return all_issues


def fetch_jira_tickets(
    email,
    api_token
):

    jql = f'''
        issuetype = SentinelOne
        AND created >= -{SENTINELONE_JIRA_WINDOW_HOURS}h
        AND project = NSIR
        ORDER BY created DESC
    '''.strip()

    all_issues = _fetch_jira_issues(
        email,
        api_token,
        jql,
        [
            "summary",
            "created",
            "description"
        ]
    )

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


def fetch_wazuh_jira_tickets(
    email,
    api_token
):

    allowed_clients = sorted(
        set(
            WAZUH_CLIENT_MAPPING.values()
        )
    )

    quoted_clients = ", ".join(
        f'"{client}"'
        for client in allowed_clients
    )

    jql = f'''
        "Tenant Name[Labels]" IN ({quoted_clients})
        AND created >= -{WAZUH_JIRA_WINDOW_HOURS}h
        AND project = NSIR
        AND type = "Wazuh Alert"
        ORDER BY created DESC
    '''.strip()

    all_issues = _fetch_jira_issues(
        email,
        api_token,
        jql,
        [
            "summary",
            "created",
            WAZUH_JIRA_TENANT_FIELD
        ]
    )

    allowed_client_set = set(
        allowed_clients
    )

    tickets = []

    for issue in all_issues:

        fields = issue.get(
            "fields",
            {}
        )

        tenant_values = fields.get(
            WAZUH_JIRA_TENANT_FIELD
        )

        if not isinstance(
            tenant_values,
            list
        ):
            continue

        matched_clients = {
            value.strip()
            for value in tenant_values
            if (
                isinstance(value, str)
                and
                value.strip()
                in allowed_client_set
            )
        }

        if len(matched_clients) != 1:
            continue

        client = matched_clients.pop()

        tickets.append(
            {
                "key": issue["key"],
                "client": client,
                "summary":
                    fields.get(
                        "summary",
                        ""
                    ),
                "created":
                    fields.get(
                        "created",
                        ""
                    )
            }
        )

    return tickets


def fetch_securonix_jira_tickets(
    email,
    api_token
):

    allowed_clients = sorted(
        SECURONIX_ALLOWED_CLIENTS
    )

    jql_clients = ", ".join(
        f'"{client}"'
        for client in allowed_clients
    )

    jql = f'''
        "tenant name[labels]" IN ({jql_clients})
        AND created >= -{SECURONIX_JIRA_WINDOW_HOURS}h
        AND issuetype = "Security Incident"
        AND project = NSIR
        ORDER BY created DESC
    '''.strip()

    all_issues = _fetch_jira_issues(
        email,
        api_token,
        jql,
        [
            "summary",
            "created",
            SECURONIX_JIRA_TENANT_FIELD
        ]
    )

    allowed_client_set = set(
        allowed_clients
    )

    tickets = []

    for issue in all_issues:

        fields = issue.get(
            "fields",
            {}
        )

        tenant_values = fields.get(
            SECURONIX_JIRA_TENANT_FIELD
        )

        if not isinstance(
            tenant_values,
            list
        ):
            continue

        matched_clients = {
            value.strip()
            for value in tenant_values
            if (
                isinstance(value, str)
                and
                value.strip()
                in allowed_client_set
            )
        }

        if len(matched_clients) != 1:
            continue

        client = matched_clients.pop()

        tickets.append(
            {
                "key": issue["key"],
                "client": client,
                "summary":
                    fields.get(
                        "summary",
                        ""
                    ),
                "created":
                    fields.get(
                        "created",
                        ""
                    )
            }
        )

    return tickets
