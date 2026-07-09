import os
import ssl
import tempfile
from pathlib import Path

import requests

from config import (
    DASHBOARD_PUBLIC_URL,
    TEAMS_CA_BUNDLE,
    TEAMS_NOTIFICATIONS_ENABLED,
    TEAMS_USE_PROXY,
    TEAMS_VERIFY_SSL,
    TEAMS_WEBHOOK_URL
)
from logger import logger


_TRUE_VALUES = {
    "1",
    "true",
    "yes",
    "on"
}
_FALSE_VALUES = {
    "0",
    "false",
    "no",
    "off"
}
_MAX_MISSING_RECORDS = 10


_SOURCE_ID_FIELDS = {
    "sentinelone": (
        "sentinelone_threat_id",
        "sentinelone_source_id",
        "threat_id",
        "id"
    ),
    "wazuh": (
        "wazuh_alert_id",
        "alert_id",
        "id"
    ),
    "securonix": (
        "securonix_incident_id",
        "incident_id",
        "id"
    ),
    "microsoft_sentinel": (
        "microsoft_sentinel_incident_id",
        "incident_number",
        "incident_id",
        "id"
    )
}

_MATCH_SOURCE_ID_FIELDS = {
    "sentinelone": (
        "id",
        "sentinelone_source_id",
        "sentinelone_threat_id",
        "sentinelone_threat_url_id"
    ),
    "wazuh": (
        "wazuh_alert_id",
        "alert_id",
        "id"
    ),
    "securonix": (
        "id",
        "securonix_incident_id",
        "incident_id",
        "securonix_incident_url"
    ),
    "microsoft_sentinel": (
        "microsoft_sentinel_incident_arm_id",
        "microsoft_sentinel_incident_name",
        "microsoft_sentinel_incident_guid",
        "microsoft_sentinel_incident_id",
        "incident_number",
        "incident_id",
        "id"
    )
}

_MATCH_TICKET_ID_FIELDS = {
    "sentinelone": (
        "sentinelone_threat_id",
        "sentinelone_threat_url_id"
    ),
    "wazuh": (
        "wazuh_alert_id",
        "alert_id"
    ),
    "securonix": (
        "securonix_incident_id",
        "securonix_incident_url_id",
        "securonix_incident_url"
    ),
    "microsoft_sentinel": (
        "microsoft_sentinel_incident_arm_id",
        "microsoft_sentinel_incident_arm_guid",
        "microsoft_sentinel_incident_url_guid",
        "microsoft_sentinel_incident_id",
        "incident_number",
        "incident_id"
    )
}


def _env_value(name, default=""):
    value = os.getenv(
        name
    )

    if value is None:
        return default

    return value.strip()


def teams_notifications_enabled():
    configured_default = (
        "true"
        if TEAMS_NOTIFICATIONS_ENABLED
        else "false"
    )

    return _env_value(
        "TEAMS_NOTIFICATIONS_ENABLED",
        configured_default
    ).casefold() in _TRUE_VALUES


def teams_webhook_configured():
    return bool(
        _teams_webhook_url()
    )


def _teams_use_proxy():
    configured_default = (
        "true"
        if TEAMS_USE_PROXY
        else "false"
    )

    return _env_value(
        "TEAMS_USE_PROXY",
        configured_default
    ).casefold() in _TRUE_VALUES


def _windows_root_ca_bundle():
    if os.name != "nt":
        return ""

    enum_certificates = getattr(
        ssl,
        "enum_certificates",
        None
    )

    if enum_certificates is None:
        return ""

    bundle_path = Path(
        tempfile.gettempdir()
    ) / "dashboard_teams_windows_roots.pem"

    try:
        certificates = enum_certificates(
            "ROOT"
        )

        with bundle_path.open(
            "w",
            encoding="ascii"
        ) as handle:
            for certificate, encoding, trust in certificates:
                if encoding != "x509_asn":
                    continue

                if trust is not True and "1.3.6.1.5.5.7.3.1" not in trust:
                    continue

                handle.write(
                    ssl.DER_cert_to_PEM_cert(certificate)
                )

        return str(bundle_path)
    except Exception as exception:
        logger.warning(
            "Unable to build Windows CA bundle for Teams: %s",
            type(exception).__name__
        )
        return ""


def _teams_verify_setting():
    ca_bundle = _env_value(
        "TEAMS_CA_BUNDLE",
        TEAMS_CA_BUNDLE
    )

    if ca_bundle:
        return ca_bundle

    configured_default = (
        "true"
        if TEAMS_VERIFY_SSL
        else "false"
    )
    verify_value = _env_value(
        "TEAMS_VERIFY_SSL",
        configured_default
    ).casefold()

    if verify_value in _FALSE_VALUES:
        return False

    windows_bundle = _windows_root_ca_bundle()

    if windows_bundle:
        return windows_bundle

    return True


def _safe_text(value, limit=300):
    if value is None:
        return "-"

    text = str(value).strip()

    if not text:
        return "-"

    return text[:limit]


def _dashboard_url():
    return _env_value(
        "DASHBOARD_PUBLIC_URL",
        DASHBOARD_PUBLIC_URL
    )


def _teams_webhook_url():
    return _env_value(
        "TEAMS_WEBHOOK_URL",
        TEAMS_WEBHOOK_URL
    )


def _fact(name, value):
    return {
        "name": name,
        "value": _safe_text(value)
    }


def _normalized(value):
    if value is None:
        return ""

    return str(value).strip().casefold()


def _record_identifiers(record, fields):
    identifiers = []

    if not isinstance(record, dict):
        return identifiers

    for field_name in fields:
        value = _normalized(
            record.get(field_name)
        )

        if value:
            identifiers.append(value)

    return sorted(set(identifiers))


def _first_present(record, fields):
    if not isinstance(record, dict):
        return ""

    for field_name in fields:
        value = record.get(field_name)

        if value not in (None, ""):
            return value

    return ""


def _source_records(client_data, tool_key):
    if not isinstance(client_data, dict):
        return []

    candidate_fields = (
        "alerts",
        "sentinel_alerts",
        "source_evidence",
        "wazuh_source_evidence",
        "incidents"
    )

    for field_name in candidate_fields:
        records = client_data.get(field_name)

        if isinstance(records, list):
            return [
                record
                for record in records
                if isinstance(record, dict)
            ]

    return []


def _ticket_records(client_data):
    if not isinstance(client_data, dict):
        return []

    records = client_data.get(
        "tickets",
        client_data.get(
            "jira_tickets",
            []
        )
    )

    if not isinstance(records, list):
        return []

    return [
        record
        for record in records
        if isinstance(record, dict)
    ]


def _missing_source_records(payload):
    tool_key = payload.get(
        "tool_key",
        ""
    )
    client_data = payload.get(
        "client_data",
        {}
    )
    source_fields = _MATCH_SOURCE_ID_FIELDS.get(
        tool_key,
        ("id",)
    )
    ticket_fields = _MATCH_TICKET_ID_FIELDS.get(
        tool_key,
        ("id",)
    )

    matched_ticket_ids = set()

    for ticket in _ticket_records(client_data):
        matched_ticket_ids.update(
            _record_identifiers(
                ticket,
                ticket_fields
            )
        )

    missing_records = []

    for record in _source_records(
        client_data,
        tool_key
    ):
        source_ids = set(
            _record_identifiers(
                record,
                source_fields
            )
        )

        if not source_ids:
            continue

        if source_ids.isdisjoint(matched_ticket_ids):
            missing_records.append(record)

    return missing_records


def _safe_missing_record_detail(record, payload):
    tool_key = payload.get(
        "tool_key",
        ""
    )

    return {
        "id": _first_present(
            record,
            _SOURCE_ID_FIELDS.get(
                tool_key,
                ("id",)
            )
        ),
        "time": _first_present(
            record,
            (
                "display_time",
                "created",
                "created_at",
                "createdAt",
                "timestamp",
                "sentinelone_created_at",
                "updated",
                "updated_at",
                "updatedAt"
            )
        ),
        "name": _first_present(
            record,
            (
                "name",
                "title",
                "sentinelone_threat_name",
                "threat_name",
                "microsoft_sentinel_incident_name",
                "incident_name",
                "description"
            )
        ),
        "rule_id": _first_present(
            record,
            (
                "rule_id",
                "ruleId"
            )
        ),
        "level_or_severity": _first_present(
            record,
            (
                "level",
                "rule_level",
                "severity",
                "priority"
            )
        ),
        "agent_or_host": _first_present(
            record,
            (
                "agent_name",
                "endpoint_name",
                "hostname",
                "host_name",
                "computerName",
                "computer_name",
                "agent_id"
            )
        ),
        "status": _first_present(
            record,
            (
                "status",
                "sentinelone_incident_status"
            )
        ),
        "tool": payload.get("tool_name", "-"),
        "client": payload.get("client", "-")
    }


def _format_missing_record(detail, index):
    parts = [
        f"ID: {_safe_text(detail.get('id'))}",
        f"Time: {_safe_text(detail.get('time'))}",
        f"Name: {_safe_text(detail.get('name'))}"
    ]

    if detail.get("rule_id"):
        parts.append(
            f"Rule ID: {_safe_text(detail.get('rule_id'))}"
        )

    if detail.get("level_or_severity"):
        parts.append(
            "Level/Severity: "
            f"{_safe_text(detail.get('level_or_severity'))}"
        )

    if detail.get("agent_or_host"):
        parts.append(
            "Agent/Endpoint/Host: "
            f"{_safe_text(detail.get('agent_or_host'))}"
        )

    if detail.get("status"):
        parts.append(
            f"Status: {_safe_text(detail.get('status'))}"
        )

    parts.append(
        f"Tool: {_safe_text(detail.get('tool'))}"
    )
    parts.append(
        f"Client: {_safe_text(detail.get('client'))}"
    )

    return f"**{index}.** " + "  \n".join(parts)


def _missing_record_section(payload):
    missing_records = _missing_source_records(
        payload
    )
    total_missing = len(missing_records)
    limited_records = missing_records[:_MAX_MISSING_RECORDS]
    details = [
        _safe_missing_record_detail(
            record,
            payload
        )
        for record in limited_records
    ]
    lines = [
        _format_missing_record(
            detail,
            index
        )
        for index, detail in enumerate(
            details,
            start=1
        )
    ]

    if total_missing > _MAX_MISSING_RECORDS:
        lines.insert(
            0,
            "Showing first "
            f"{_MAX_MISSING_RECORDS} of {total_missing} "
            "missing records."
        )

    logger.info(
        "Teams card missing_detail_count=%s missing_total=%s",
        len(details),
        total_missing
    )

    if not lines:
        return None

    return {
        "activityTitle": "Missing alert/incident details",
        "text": "\n\n".join(lines),
        "markdown": True
    }


def _build_message(payload):
    dashboard_url = _dashboard_url()
    title = _safe_text(
        payload.get(
            "title",
            "Dashboard mismatch detected"
        )
    )

    facts = [
        _fact("Tool", payload.get("tool_name")),
        _fact("Tool key", payload.get("tool_key")),
        _fact("Client", payload.get("client")),
        _fact("Source count", payload.get("alert_count")),
        _fact("Jira ticket count", payload.get("ticket_count")),
        _fact("Missing count", payload.get("missing_ticket_count")),
        _fact("Extra count", payload.get("extra_ticket_count")),
        _fact("Timestamp", payload.get("timestamp"))
    ]

    sections = [
        {
            "activityTitle": "Mismatch requires review",
            "facts": facts,
            "markdown": True
        }
    ]
    missing_section = _missing_record_section(
        payload
    )

    if missing_section:
        sections.append(
            missing_section
        )

    card = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": "D13438",
        "title": title,
        "sections": sections
    }

    if dashboard_url:
        card["potentialAction"] = [
            {
                "@type": "OpenUri",
                "name": "Open dashboard",
                "targets": [
                    {
                        "os": "default",
                        "uri": dashboard_url
                    }
                ]
            }
        ]

    return card


def send_teams_mismatch_notification(payload):
    if not teams_notifications_enabled():
        logger.info(
            "Teams notification not sent: notifications disabled"
        )
        return False

    webhook_url = _teams_webhook_url()

    if not webhook_url:
        logger.warning(
            "Teams notification not sent: webhook URL missing"
        )
        return False

    verify_setting = _teams_verify_setting()
    use_proxy = _teams_use_proxy()

    logger.info(
        "Teams post attempted: verify_ssl=%s ca_bundle=%s proxy_env=%s",
        verify_setting is not False,
        isinstance(verify_setting, str),
        use_proxy
    )

    try:
        session = requests.Session()
        session.trust_env = use_proxy
        response = session.post(
            webhook_url,
            json=_build_message(payload),
            timeout=10,
            verify=verify_setting
        )

        if response.ok:
            logger.info(
                "Teams post succeeded: status_code=%s",
                response.status_code
            )
            return True

        logger.warning(
            "Teams post failed: status_code=%s",
            response.status_code
        )
        return False
    except requests.exceptions.SSLError:
        logger.warning(
            "Teams post failed due to SSL verification error"
        )
        return False
    except requests.RequestException as exception:
        response = getattr(
            exception,
            "response",
            None
        )

        if response is not None:
            logger.warning(
                "Teams post failed: status_code=%s",
                response.status_code
            )
        else:
            logger.warning(
                "Teams post failed before HTTP response: %s",
                type(exception).__name__
            )
        return False
