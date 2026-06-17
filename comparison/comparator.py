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


def _safe_wazuh_ticket(ticket):

    jira_key = ticket.get(
        "jira_key",
        ticket.get(
            "key",
            ""
        )
    )

    return {
        "key": jira_key,
        "jira_key": jira_key,
        "created": ticket.get(
            "created",
            ""
        ),
        "summary": ticket.get(
            "summary",
            ""
        ),
        "status": ticket.get(
            "status",
            ""
        ),
        "wazuh_alert_id": ticket.get(
            "wazuh_alert_id",
            ""
        ),
        "rule_id": ticket.get(
            "rule_id",
            ""
        ),
        "resolved_client": ticket.get(
            "resolved_client"
        ),
        "client_resolution_source": ticket.get(
            "client_resolution_source",
            ""
        ),
        "confidence": ticket.get(
            "confidence",
            ""
        ),
        "metadata_issues": ticket.get(
            "metadata_issues",
            []
        )
    }


def _wazuh_status(
    alert_count,
    correlated_ticket_count
):

    if correlated_ticket_count < alert_count:
        return "Missing Tickets"

    if correlated_ticket_count > alert_count:
        return "Extra Tickets - Review"

    return "Covered"


def compare_wazuh_correlation_data(
    alert_counts,
    jira_tickets,
    source="wazuh",
    managed_clients=None
):

    clients = {}
    unmapped_tickets = []
    managed_client_set = {
        client.strip()
        for client in (
            managed_clients or []
        )
        if client and client.strip()
    }

    for record in alert_counts:

        client = record.get(
            "client",
            "Unknown"
        ).strip()

        if managed_client_set and client not in managed_client_set:
            continue

        if client not in clients:
            clients[client] = {
                "client": client,
                "sources": set(),
                "alert_count": 0,
                "alerts": [],
                "wazuh_source_evidence": [],
                "strict_tickets": [],
                "correlated_tickets": []
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

        clients[client]["wazuh_source_evidence"].extend(
            record.get(
                "wazuh_source_evidence",
                record.get(
                    "source_evidence",
                    []
                )
            )
        )

    for client in managed_client_set:

        if client not in clients:
            clients[client] = {
                "client": client,
                "sources": {source},
                "alert_count": 0,
                "alerts": [],
                "wazuh_source_evidence": [],
                "strict_tickets": [],
                "correlated_tickets": []
            }

    for ticket in jira_tickets:

        safe_ticket = _safe_wazuh_ticket(
            ticket
        )

        resolved_client = ticket.get(
            "resolved_client"
        )

        tenant_clients = [
            tenant_client.strip()
            for tenant_client in ticket.get(
                "tenant_field",
                []
            )
            if tenant_client and tenant_client.strip()
        ]

        managed_tenant_clients = [
            tenant_client
            for tenant_client in tenant_clients
            if (
                not managed_client_set
                or tenant_client in managed_client_set
            )
        ]

        is_high_confidence = (
            ticket.get("confidence") == "high"
        )

        if (
            resolved_client
            and
            is_high_confidence
            and (
                not managed_client_set
                or resolved_client in managed_client_set
            )
        ):

            if resolved_client not in clients:
                clients[resolved_client] = {
                    "client": resolved_client,
                    "sources": {source},
                    "alert_count": 0,
                    "alerts": [],
                    "wazuh_source_evidence": [],
                    "strict_tickets": [],
                    "correlated_tickets": []
                }

            clients[resolved_client][
                "correlated_tickets"
            ].append(
                safe_ticket
            )

        elif managed_tenant_clients:

            unmapped_tickets.append(
                safe_ticket
            )

        for tenant_client in managed_tenant_clients:
            if tenant_client not in clients:
                clients[tenant_client] = {
                    "client": tenant_client,
                    "sources": {source},
                    "alert_count": 0,
                    "alerts": [],
                    "wazuh_source_evidence": [],
                    "strict_tickets": [],
                    "correlated_tickets": []
                }

            clients[tenant_client][
                "strict_tickets"
            ].append(
                safe_ticket
            )

    result = []

    for client in clients.values():

        strict_ticket_count = len(
            client["strict_tickets"]
        )

        correlated_ticket_count = len(
            client["correlated_tickets"]
        )

        metadata_drift_count = sum(
            1
            for ticket in client["correlated_tickets"]
            if ticket.get("metadata_issues")
        )

        coverage_delta = (
            correlated_ticket_count
            - client["alert_count"]
        )

        missing_ticket_count = max(
            client["alert_count"]
            - correlated_ticket_count,
            0
        )

        extra_ticket_count = max(
            correlated_ticket_count
            - client["alert_count"],
            0
        )

        coverage_status = _wazuh_status(
            client["alert_count"],
            correlated_ticket_count
        )

        result.append({
            "client": client["client"],
            "sources": sorted(
                list(client["sources"])
            ),
            "alert_count":
                client["alert_count"],
            "strict_ticket_count":
                strict_ticket_count,
            "correlated_ticket_count":
                correlated_ticket_count,
            "metadata_drift_count":
                metadata_drift_count,
            "coverage_status":
                coverage_status,
            "coverage_delta":
                coverage_delta,
            "missing_ticket_count":
                missing_ticket_count,
            "extra_ticket_count":
                extra_ticket_count,
            "ticket_count":
                correlated_ticket_count,
            "status":
                coverage_status,
            "alerts":
                client["alerts"],
            "source_evidence":
                client["wazuh_source_evidence"],
            "wazuh_source_evidence":
                client["wazuh_source_evidence"],
            "tickets":
                client["correlated_tickets"],
            "strict_tickets":
                client["strict_tickets"]
        })

    result.sort(
        key=lambda client: (
            client["status"] == "Equal",
            client["client"].casefold()
        )
    )

    correlated_total_tickets = sum(
        len(client["correlated_tickets"])
        for client in clients.values()
    )

    strict_total_tickets = sum(
        len(client["strict_tickets"])
        for client in clients.values()
    )

    metadata_drift_total = sum(
        client["metadata_drift_count"]
        for client in result
    )

    total_alert_count = sum(
        client["alert_count"]
        for client in result
    )

    coverage_delta_total = (
        correlated_total_tickets
        - total_alert_count
    )

    missing_ticket_total = sum(
        client["missing_ticket_count"]
        for client in result
    )

    extra_ticket_total = sum(
        client["extra_ticket_count"]
        for client in result
    )

    return {
        "total_alerts":
            total_alert_count,

        "total_tickets":
            correlated_total_tickets,

        "strict_total_tickets":
            strict_total_tickets,

        "correlated_total_tickets":
            correlated_total_tickets,

        "metadata_drift_total":
            metadata_drift_total,

        "coverage_delta_total":
            coverage_delta_total,

        "missing_ticket_total":
            missing_ticket_total,

        "extra_ticket_total":
            extra_ticket_total,

        "unmapped_ticket_count":
            len(unmapped_tickets),

        "unmapped_tickets":
            unmapped_tickets,

        "clients":
            result
    }


def compare_list_data(
    records,
    jira_tickets,
    source,
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
            "alerts": [],
            "tickets": []
        }

    for record in records:

        client = record.get(
            "client",
            "Unknown"
        ).strip()

        if client not in clients:
            clients[client] = {
                "client": client,
                "sources": set(),
                "alerts": [],
                "tickets": []
            }

        clients[client]["sources"].add(
            record.get(
                "source",
                source
            )
        )

        clients[client]["alerts"].append({
            **record,
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
                "sources": {source},
                "alerts": [],
                "tickets": []
            }

        clients[client]["tickets"].append({
            **ticket,
            "client": client
        })

    result = []

    for client in clients.values():

        alert_count = len(
            client["alerts"]
        )
        ticket_count = len(
            client["tickets"]
        )

        result.append({
            "client": client["client"],
            "sources": sorted(
                list(client["sources"])
            ),
            "alert_count": alert_count,
            "ticket_count": ticket_count,
            "status":
                "Equal"
                if alert_count == ticket_count
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
        "total_alerts": len(records),
        "total_tickets": len(jira_tickets),
        "clients": result
    }
