from datetime import datetime, UTC


def compare_data(
    sentinel_alerts,
    jira_tickets,
    managed_clients=None
):

    clients = {}

    for client, sources in (
        managed_clients or {}
    ).items():

        client = client.strip()

        if not client:
            continue

        clients[client] = {
            "client": client,
            "sources": set(sources),
            "sentinel_alerts": [],
            "jira_tickets": []
        }

    for alert in sentinel_alerts:

        client = alert.get(
            "client",
            "Unknown"
        ).strip()

        if client not in clients:
            clients[client] = {
                "client": client,
                "sources": set(),
                "sentinel_alerts": [],
                "jira_tickets": []
            }

        clients[client]["sources"].add(
            alert.get("source", "unknown")
        )

        clients[client]["sentinel_alerts"].append({
            **alert,
            "client": client
        })

    for ticket in jira_tickets:

        client = ticket.get(
            "client",
            "Unknown"
        ).strip()

        if client not in clients:
            clients[client] = {
                "client": client,
                "sources": set(),
                "sentinel_alerts": [],
                "jira_tickets": []
            }

        clients[client]["jira_tickets"].append({
            **ticket,
            "client": client
        })

    result = []

    for client in clients.values():

        result.append({
            "client": client["client"],
            "sources": sorted(
                list(client["sources"])
            ),
            "sentinel_count": len(
                client["sentinel_alerts"]
            ),
            "jira_count": len(
                client["jira_tickets"]
            ),
            "status":
                "Equal"
                if len(client["sentinel_alerts"])
                ==
                len(client["jira_tickets"])
                else
                "Mismatch",
            "sentinel_alerts":
                client["sentinel_alerts"],
            "jira_tickets":
                client["jira_tickets"]
        })

    return {
        "timestamp":
            datetime.now(UTC).isoformat(),

        "total_sentinel_count":
            len(sentinel_alerts),

        "total_jira_count":
            len(jira_tickets),

        "clients":
            result
    }
