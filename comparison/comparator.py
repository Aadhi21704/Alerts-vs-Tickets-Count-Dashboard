from datetime import datetime, UTC


def compare_data(
    sentinel_alerts,
    jira_tickets,
    managed_clients=None,
    client_mapping=None
):

    clients = {}
    client_mapping = client_mapping or {}

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

        raw_client = alert.get(
            "client",
            "Unknown"
        ).strip()
        client = client_mapping.get(
            raw_client,
            raw_client
        )

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

        raw_client = ticket.get(
            "client",
            "Unknown"
        ).strip()
        client = client_mapping.get(
            raw_client,
            raw_client
        )

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


def compare_count_data(
    alert_counts,
    jira_tickets,
    source
):

    clients = {}

    for record in alert_counts:

        client = record.get(
            "client",
            "Unknown"
        ).strip()

        if client not in clients:
            clients[client] = {
                "client": client,
                "sources": set(),
                "alert_count": 0,
                "alerts": [],
                "tickets": []
            }

        clients[client]["sources"].add(
            record.get(
                "source",
                source
            )
        )

        clients[client]["alert_count"] += (
            record["count"]
        )

        clients[client]["alerts"].extend(
            record.get(
                "alerts",
                []
            )
        )

    for ticket in jira_tickets:

        client = ticket.get(
            "client",
            "Unknown"
        ).strip()

        if client not in clients:
            clients[client] = {
                "client": client,
                "sources": {source},
                "alert_count": 0,
                "alerts": [],
                "tickets": []
            }

        clients[client]["tickets"].append({
            **ticket,
            "client": client
        })

    result = []

    for client in clients.values():

        ticket_count = len(
            client["tickets"]
        )

        result.append({
            "client": client["client"],
            "sources": sorted(
                list(client["sources"])
            ),
            "alert_count":
                client["alert_count"],
            "ticket_count":
                ticket_count,
            "status":
                "Equal"
                if client["alert_count"]
                == ticket_count
                else
                "Mismatch",
            "alerts":
                client["alerts"],
            "tickets":
                client["tickets"]
        })

    result.sort(
        key=lambda client: (
            client["status"] == "Equal",
            client["client"].casefold()
        )
    )

    return {
        "total_alerts":
            sum(
                record["count"]
                for record in alert_counts
            ),

        "total_tickets":
            len(jira_tickets),

        "clients":
            result
    }
