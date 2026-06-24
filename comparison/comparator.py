from datetime import datetime, UTC


def _coverage_status(
    alert_count,
    ticket_count
):

    if ticket_count < alert_count:
        return "Missing Tickets"

    if ticket_count > alert_count:
        return "Review"

    return "Covered"


def _coverage_fields(
    alert_count,
    ticket_count,
    strict_ticket_count=None,
    correlated_ticket_count=None,
    metadata_drift_count=0
):

    strict_ticket_count = (
        ticket_count
        if strict_ticket_count is None
        else strict_ticket_count
    )

    correlated_ticket_count = (
        ticket_count
        if correlated_ticket_count is None
        else correlated_ticket_count
    )

    coverage_delta = (
        correlated_ticket_count
        - alert_count
    )

    return {
        "strict_ticket_count": strict_ticket_count,
        "correlated_ticket_count": correlated_ticket_count,
        "metadata_drift_count": metadata_drift_count,
        "coverage_status":
            _coverage_status(
                alert_count,
                correlated_ticket_count
            ),
        "coverage_delta": coverage_delta,
        "missing_ticket_count":
            max(
                alert_count - correlated_ticket_count,
                0
            ),
        "extra_ticket_count":
            max(
                correlated_ticket_count - alert_count,
                0
            )
    }


def _coverage_totals(
    clients
):

    return {
        "strict_total_tickets":
            sum(
                client.get("strict_ticket_count", 0)
                for client in clients
            ),
        "correlated_total_tickets":
            sum(
                client.get("correlated_ticket_count", 0)
                for client in clients
            ),
        "metadata_drift_total":
            sum(
                client.get("metadata_drift_count", 0)
                for client in clients
            ),
        "coverage_delta_total":
            sum(
                client.get("coverage_delta", 0)
                for client in clients
            ),
        "missing_ticket_total":
            sum(
                client.get("missing_ticket_count", 0)
                for client in clients
            ),
        "extra_ticket_total":
            sum(
                client.get("extra_ticket_count", 0)
                for client in clients
            )
    }


def _exact_client_bucket(
    client,
    sources=None,
    alert_key="alerts"
):
    return {
        "client": client,
        "sources": set(sources or []),
        alert_key: [],
        "strict_tickets": [],
        "correlated_tickets": [],
        "matched_source_indexes": set()
    }


def _ensure_exact_client(
    clients,
    client,
    sources=None,
    alert_key="alerts"
):
    if client not in clients:
        clients[client] = _exact_client_bucket(
            client,
            sources=sources,
            alert_key=alert_key
        )

    return clients[client]


def _metadata_issues_for_match(
    ticket,
    strict_client,
    matched_client
):
    metadata_issues = list(
        ticket.get(
            "metadata_issues",
            []
        )
        or []
    )

    if strict_client != matched_client:
        metadata_issues.append(
            "client_metadata_drift"
        )

    return sorted(
        set(metadata_issues)
    )


def _exact_count_fields(
    client,
    alert_key="alerts",
    status_fn=None
):
    alert_count = len(
        client[alert_key]
    )
    strict_ticket_count = len(
        client["strict_tickets"]
    )
    correlated_ticket_count = len(
        client["correlated_tickets"]
    )
    unique_matched_source_count = len(
        client["matched_source_indexes"]
    )
    missing_ticket_count = max(
        alert_count
        - unique_matched_source_count,
        0
    )
    extra_ticket_count = max(
        correlated_ticket_count
        - alert_count,
        0
    )
    coverage_delta = (
        correlated_ticket_count
        - alert_count
    )
    metadata_drift_count = sum(
        1
        for ticket in client["correlated_tickets"]
        if ticket.get("metadata_issues")
    )

    if status_fn is None:
        coverage_status = (
            "Missing Tickets"
            if missing_ticket_count > 0
            else (
                "Review"
                if extra_ticket_count > 0
                else "Covered"
            )
        )
    else:
        coverage_status = status_fn(
            missing_ticket_count,
            extra_ticket_count
        )

    return {
        "alert_count": alert_count,
        "strict_ticket_count": strict_ticket_count,
        "correlated_ticket_count": correlated_ticket_count,
        "unique_matched_source_count":
            unique_matched_source_count,
        "metadata_drift_count": metadata_drift_count,
        "coverage_status": coverage_status,
        "coverage_delta": coverage_delta,
        "missing_ticket_count": missing_ticket_count,
        "extra_ticket_count": extra_ticket_count
    }


def _exact_result_totals(
    result,
    total_alerts,
    unmapped_tickets
):
    correlated_total_tickets = sum(
        client["correlated_ticket_count"]
        for client in result
    )

    return {
        "total_alerts": total_alerts,
        "total_tickets": correlated_total_tickets,
        "strict_total_tickets":
            sum(
                client["strict_ticket_count"]
                for client in result
            ),
        "correlated_total_tickets":
            correlated_total_tickets,
        "metadata_drift_total":
            sum(
                client["metadata_drift_count"]
                for client in result
            ),
        "coverage_delta_total":
            correlated_total_tickets - total_alerts,
        "missing_ticket_total":
            sum(
                client["missing_ticket_count"]
                for client in result
            ),
        "extra_ticket_total":
            sum(
                client["extra_ticket_count"]
                for client in result
            ),
        "unmapped_ticket_count":
            len(unmapped_tickets),
        "unmapped_tickets":
            unmapped_tickets
    }


def _default_record_client(record):
    return record.get(
        "client",
        "Unknown"
    ).strip()


def _default_ticket_client(ticket):
    return ticket.get(
        "client",
        "Unknown"
    ).strip()


def _build_exact_client_result(
    client,
    counts,
    alert_key="alerts",
    extra_fields=None
):
    result = {
        "client": client["client"],
        "sources": sorted(
            list(client["sources"])
        ),
        "alert_count": counts["alert_count"],
        "ticket_count": counts[
            "correlated_ticket_count"
        ],
        "strict_ticket_count":
            counts["strict_ticket_count"],
        "correlated_ticket_count":
            counts["correlated_ticket_count"],
        "unique_matched_source_count":
            counts["unique_matched_source_count"],
        "metadata_drift_count":
            counts["metadata_drift_count"],
        "coverage_status":
            counts["coverage_status"],
        "coverage_delta":
            counts["coverage_delta"],
        "missing_ticket_count":
            counts["missing_ticket_count"],
        "extra_ticket_count":
            counts["extra_ticket_count"],
        "status":
            counts["coverage_status"],
        alert_key:
            client[alert_key],
        "tickets":
            client["correlated_tickets"],
        "strict_tickets":
            client["strict_tickets"]
    }

    if extra_fields:
        result.update(
            extra_fields(
                client,
                counts
            )
        )

    return result


def _compare_exact_id_correlation_data(
    records,
    jira_tickets,
    source,
    source_identifier_fn,
    ticket_identifier_fn,
    managed_clients=None,
    alert_key="alerts",
    source_default=None,
    source_client_fn=None,
    ticket_client_fn=None,
    source_record_hook=None,
    strict_client_value_fn=None,
    matched_status="exact_id_match",
    unmatched_status="evidence_unmatched",
    status_fn=None,
    sort_result=True,
    result_extra_fields=None
):
    clients = {}
    source_default = (
        source
        if source_default is None
        else source_default
    )
    source_client_fn = (
        source_client_fn
        or _default_record_client
    )
    ticket_client_fn = (
        ticket_client_fn
        or _default_ticket_client
    )

    for client, sources in (
        managed_clients or {}
    ).items():

        client = client.strip()

        if not client:
            continue

        _ensure_exact_client(
            clients,
            client,
            sources=sources,
            alert_key=alert_key
        )

    source_index = {}

    for record_index, record in enumerate(records):

        client = source_client_fn(
            record
        )

        _ensure_exact_client(
            clients,
            client,
            alert_key=alert_key
        )

        clients[client]["sources"].add(
            record.get(
                "source",
                source_default
            )
        )

        clients[client][alert_key].append({
            **record,
            "client": client
        })

        if source_record_hook:
            source_record_hook(
                record,
                client
            )

        for identifier in source_identifier_fn(
            record
        ):
            source_index[identifier] = {
                "index": record_index,
                "client": client,
                "record": record
            }

    unmapped_tickets = []

    for ticket in jira_tickets:

        strict_client = ticket_client_fn(
            ticket
        )

        _ensure_exact_client(
            clients,
            strict_client,
            sources={source},
            alert_key=alert_key
        )

        strict_ticket_client = (
            strict_client_value_fn(
                ticket,
                strict_client
            )
            if strict_client_value_fn
            else strict_client
        )

        strict_ticket = {
            **ticket,
            "client": strict_client,
            "strict_client": strict_ticket_client
        }

        clients[strict_client][
            "strict_tickets"
        ].append(
            strict_ticket
        )

        matched_source = None
        ticket_identifiers = ticket_identifier_fn(
            ticket
        )

        for identifier in ticket_identifiers:
            if identifier in source_index:
                matched_source = source_index[
                    identifier
                ]
                break

        if not matched_source:
            if ticket_identifiers:
                unmapped_tickets.append(
                    {
                        **strict_ticket,
                        "match_status":
                            unmatched_status
                    }
                )

            continue

        matched_client = matched_source[
            "client"
        ]

        _ensure_exact_client(
            clients,
            matched_client,
            sources={source},
            alert_key=alert_key
        )

        correlated_ticket = {
            **ticket,
            "client": matched_client,
            "strict_client": strict_client,
            "matched_source_client": matched_client,
            "match_status": matched_status,
            "metadata_issues":
                _metadata_issues_for_match(
                    ticket,
                    strict_client,
                    matched_client
                )
        }

        clients[matched_client][
            "correlated_tickets"
        ].append(
            correlated_ticket
        )

        clients[matched_client][
            "matched_source_indexes"
        ].add(
            matched_source["index"]
        )

    result = []

    for client in clients.values():
        counts = _exact_count_fields(
            client,
            alert_key=alert_key,
            status_fn=status_fn
        )

        result.append(
            _build_exact_client_result(
                client,
                counts,
                alert_key=alert_key,
                extra_fields=result_extra_fields
            )
        )

    if sort_result:
        result.sort(
            key=lambda client: (
                client["status"] == "Covered",
                client["client"].casefold()
            )
        )

    totals = _exact_result_totals(
        result,
        len(records),
        unmapped_tickets
    )

    return {
        **totals,
        "clients": result
    }


def _normalized_identifier(value):
    if value is None:
        return ""

    return str(value).strip().casefold()


def _sentinelone_alert_identifiers(alert):
    identifiers = []

    for field_name in (
        "id",
        "sentinelone_source_id",
        "sentinelone_threat_id",
        "sentinelone_threat_url_id"
    ):
        identifier = _normalized_identifier(
            alert.get(field_name)
        )

        if identifier:
            identifiers.append(identifier)

    return sorted(
        set(identifiers)
    )


def _sentinelone_ticket_identifiers(ticket):
    identifiers = []

    for field_name in (
        "sentinelone_threat_id",
        "sentinelone_threat_url_id"
    ):
        identifier = _normalized_identifier(
            ticket.get(field_name)
        )

        if identifier:
            identifiers.append(identifier)

    return sorted(
        set(identifiers)
    )


def _sentinelone_status(
    missing_ticket_count,
    extra_ticket_count
):
    if missing_ticket_count > 0:
        return "Missing Tickets"

    if extra_ticket_count > 0:
        return "Review"

    return "Covered"


def _extract_query_id(value):
    if not isinstance(value, str):
        return ""

    for separator in ("?", "&"):
        parts = value.split(separator)
        value = "&".join(parts)

    for part in value.split("&"):
        key, separator, field_value = part.partition("=")

        if (
            separator
            and key.strip().casefold() == "id"
            and field_value.strip()
        ):
            return field_value.strip()

    return ""


def _securonix_source_identifiers(record):
    identifiers = []

    for field_name in (
        "id",
        "securonix_incident_id"
    ):
        identifier = _normalized_identifier(
            record.get(field_name)
        )

        if identifier:
            identifiers.append(identifier)

    url_identifier = _normalized_identifier(
        _extract_query_id(
            record.get("securonix_incident_url")
            or record.get("url")
        )
    )

    if url_identifier:
        identifiers.append(url_identifier)

    return sorted(set(identifiers))


def _securonix_ticket_identifiers(ticket):
    identifiers = []

    for field_name in (
        "securonix_incident_id",
        "securonix_incident_url_id"
    ):
        identifier = _normalized_identifier(
            ticket.get(field_name)
        )

        if identifier:
            identifiers.append(identifier)

    return sorted(set(identifiers))


def _microsoft_sentinel_source_identifiers(record):
    identifiers = []

    for field_name in (
        "microsoft_sentinel_incident_arm_id",
        "microsoft_sentinel_incident_name",
        "microsoft_sentinel_incident_guid",
        "id"
    ):
        identifier = _normalized_identifier(
            record.get(field_name)
        )

        if identifier:
            identifiers.append(identifier)

    client = _normalized_identifier(
        record.get("client")
    )
    workspace = _normalized_identifier(
        record.get("microsoft_sentinel_workspace_name")
    )
    incident_number = _normalized_identifier(
        record.get("microsoft_sentinel_incident_id")
        or record.get("incident_number")
    )

    if client and workspace and incident_number:
        identifiers.append(
            f"{client}|{workspace}|{incident_number}"
        )

    return sorted(set(identifiers))


def _microsoft_sentinel_ticket_identifiers(ticket, workspace_by_client):
    identifiers = []

    for field_name in (
        "microsoft_sentinel_incident_arm_id",
        "microsoft_sentinel_incident_arm_guid",
        "microsoft_sentinel_incident_url_guid"
    ):
        identifier = _normalized_identifier(
            ticket.get(field_name)
        )

        if identifier:
            identifiers.append(identifier)

    client = _normalized_identifier(
        ticket.get("client")
        or ticket.get("strict_client")
    )
    workspace = workspace_by_client.get(
        client,
        ""
    )
    incident_number = _normalized_identifier(
        ticket.get("microsoft_sentinel_incident_id")
    )

    if client and workspace and incident_number:
        identifiers.append(
            f"{client}|{workspace}|{incident_number}"
        )

    return sorted(set(identifiers))


def _compare_microsoft_sentinel_correlation_data(
    records,
    jira_tickets,
    source,
    managed_clients=None
):

    workspace_by_client = {}

    def record_hook(record, client):
        workspace = _normalized_identifier(
            record.get("microsoft_sentinel_workspace_name")
        )

        if workspace:
            workspace_by_client[
                _normalized_identifier(client)
            ] = workspace

    return _compare_exact_id_correlation_data(
        records,
        jira_tickets,
        source,
        _microsoft_sentinel_source_identifiers,
        lambda ticket: _microsoft_sentinel_ticket_identifiers(
            ticket,
            workspace_by_client
        ),
        managed_clients=managed_clients,
        source_record_hook=record_hook,
        strict_client_value_fn=lambda ticket, strict_client:
            ticket.get(
                "strict_client",
                strict_client
            ),
        matched_status="microsoft_sentinel_exact_id_match",
        unmatched_status="microsoft_sentinel_evidence_unmatched"
    )


def compare_data(
    sentinel_alerts,
    jira_tickets,
    managed_clients=None,
    client_mapping=None
):

    client_mapping = client_mapping or {}

    def source_client(alert):
        raw_client = alert.get(
            "client",
            "Unknown"
        ).strip()
        return client_mapping.get(
            raw_client,
            raw_client
        )

    def ticket_client(ticket):
        raw_client = ticket.get(
            "client",
            "Unknown"
        ).strip()
        return client_mapping.get(
            raw_client,
            raw_client
        )

    comparison = _compare_exact_id_correlation_data(
        sentinel_alerts,
        jira_tickets,
        "sentinelone",
        _sentinelone_alert_identifiers,
        _sentinelone_ticket_identifiers,
        managed_clients=managed_clients,
        alert_key="sentinel_alerts",
        source_default="unknown",
        source_client_fn=source_client,
        ticket_client_fn=ticket_client,
        matched_status="sentinelone_exact_id_match",
        unmatched_status="sentinelone_evidence_unmatched",
        status_fn=_sentinelone_status,
        sort_result=False,
        result_extra_fields=lambda client, counts: {
            "sentinel_count": counts["alert_count"],
            "jira_count": counts["strict_ticket_count"],
            "jira_tickets":
                client["correlated_tickets"]
        }
    )

    return {
        "timestamp":
            datetime.now(UTC).isoformat(),

        "total_sentinel_count":
            len(sentinel_alerts),

        "total_jira_count":
            comparison["strict_total_tickets"],

        **comparison
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
            **_coverage_fields(
                client["alert_count"],
                ticket_count
            ),
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

    coverage_totals = _coverage_totals(
        result
    )

    return {
        "total_alerts":
            sum(
                record["count"]
                for record in alert_counts
            ),

        "total_tickets":
            len(jira_tickets),

        **coverage_totals,

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

    return _coverage_status(
        alert_count,
        correlated_ticket_count
    )


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

    if source == "microsoft_sentinel":
        return _compare_microsoft_sentinel_correlation_data(
            records,
            jira_tickets,
            source,
            managed_clients
        )

    if source == "securonix":
        return _compare_securonix_correlation_data(
            records,
            jira_tickets,
            source,
            managed_clients
        )

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
            **_coverage_fields(
                alert_count,
                ticket_count
            ),
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

    coverage_totals = _coverage_totals(
        result
    )

    return {
        "total_alerts": len(records),
        "total_tickets": len(jira_tickets),
        **coverage_totals,
        "clients": result
    }


def _compare_securonix_correlation_data(
    records,
    jira_tickets,
    source,
    managed_clients=None
):

    return _compare_exact_id_correlation_data(
        records,
        jira_tickets,
        source,
        _securonix_source_identifiers,
        _securonix_ticket_identifiers,
        managed_clients=managed_clients,
        matched_status="securonix_exact_id_match",
        unmatched_status="securonix_evidence_unmatched"
    )
