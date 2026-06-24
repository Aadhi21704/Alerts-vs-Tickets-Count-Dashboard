import json
import re

import requests

from config import (
    JIRA_URL,
    MS_SENTINEL_CLIENTS,
    MS_SENTINEL_INCIDENT_WINDOW_HOURS,
    SECURONIX_ALLOWED_CLIENTS,
    SECURONIX_JIRA_TENANT_FIELD,
    SECURONIX_JIRA_WINDOW_HOURS,
    SENTINELONE_JIRA_WINDOW_HOURS,
    WAZUH_CLIENT_MAPPING,
    WAZUH_JIRA_CLIENT_HINTS,
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


def _get_adf_text_with_links(node):
    if isinstance(node, str):
        return node

    if isinstance(node, list):
        return " ".join(
            _get_adf_text_with_links(child)
            for child in node
        )

    if not isinstance(node, dict):
        return ""

    text_parts = []

    if node.get("type") == "text":
        text_parts.append(
            node.get("text", "")
        )

    attrs = node.get("attrs", {})

    if isinstance(attrs, dict):
        href = attrs.get("href")

        if isinstance(href, str):
            text_parts.append(href)

    for mark in node.get("marks", []) or []:
        if not isinstance(mark, dict):
            continue

        mark_attrs = mark.get("attrs", {})

        if not isinstance(mark_attrs, dict):
            continue

        href = mark_attrs.get("href")

        if isinstance(href, str):
            text_parts.append(href)

    for child in node.get("content", []) or []:
        child_text = _get_adf_text_with_links(
            child
        )

        if child_text:
            text_parts.append(child_text)

    return " ".join(
        part
        for part in text_parts
        if part
    )


_SENTINELONE_THREAT_ID_PATTERNS = [
    re.compile(
        r"(?i)\bSentinelOne\s+Threat\s+ID\b\s*[:=]?\s*"
        r"([A-Za-z0-9._:-]{6,})"
    ),
    re.compile(
        r"(?i)\bThreat\s+ID\b\s*[:=]?\s*"
        r"([A-Za-z0-9._:-]{6,})"
    ),
    re.compile(
        r"(?i)\bthreatId\b\s*[:=]?\s*"
        r"([A-Za-z0-9._:-]{6,})"
    ),
    re.compile(
        r"(?i)\bSource\s+(?:Alert|Threat)\s+ID\b\s*[:=]?\s*"
        r"([A-Za-z0-9._:-]{6,})"
    )
]

_SENTINELONE_THREAT_URL_PATTERN = re.compile(
    r"(?i)https?://[^\s\])}]+sentinelone\.net"
    r"/[^\s\])}]*?/threats/([A-Za-z0-9._:-]+)"
)

_SENTINELONE_CONSOLE_URL_PATTERN = re.compile(
    r"(?i)https?://[^\s\])}]+sentinelone\.net/[^\s\])}]+"
)

_AZURE_OR_MICROSOFT_SENTINEL_PATTERN = re.compile(
    r"(?i)(portal\.azure\.com|Microsoft_Azure_Security_Insights|"
    r"Microsoft Sentinel|Azure Sentinel|Sentinel Incident|Incident URL)"
)

_SECURONIX_INCIDENT_ID_PATTERNS = [
    re.compile(
        r"(?i)\bSCNX\s*-\s*Incident\s*-\s*ID\b\s*[:=]?\s*"
        r"([0-9A-Za-z._:-]{3,})"
    ),
    re.compile(
        r"(?i)\bSecuronix\s+Incident\s+ID\b\s*[:=]?\s*"
        r"([0-9A-Za-z._:-]{3,})"
    ),
    re.compile(
        r"(?i)\bincidentId\b\s*[:=]?\s*"
        r"([0-9A-Za-z._:-]{3,})"
    )
]

_SECURONIX_INCIDENT_URL_PATTERN = re.compile(
    r"(?i)https?://[^\s\])}]+(?:securonix|snypr)[^\s\])}]*"
)

_SECURONIX_INCIDENT_URL_FIELD = "customfield_10120"

_SECURONIX_INCIDENT_ID_FIELD = "customfield_10116"

_MS_SENTINEL_INCIDENT_GUID_PATTERN = re.compile(
    r"(?i)/incidents/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12})(?:$|[/?#])"
)

_MS_SENTINEL_GUID_PATTERN = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}\b"
)

_MS_SENTINEL_URL_PATTERN = re.compile(
    r"(?i)https?://[^\s\])}<>\"|]+"
)


def _clean_sentinelone_identifier(value):
    if not isinstance(value, str):
        return ""

    return re.sub(
        r"(?i)(Threat|Incident|URL|Details|ID)$",
        "",
        value.strip().strip(":;,.)]")
    ).strip()


def _extract_sentinelone_jira_evidence(summary, description):
    safe_text = " ".join(
        value
        for value in [
            summary or "",
            _get_adf_text_with_links(description)
        ]
        if value
    )

    threat_ids = []

    for pattern in _SENTINELONE_THREAT_ID_PATTERNS:
        for match in pattern.finditer(safe_text):
            threat_id = _clean_sentinelone_identifier(
                match.group(1)
            )

            if threat_id:
                threat_ids.append(threat_id)

    threat_url_ids = []

    for match in _SENTINELONE_THREAT_URL_PATTERN.finditer(safe_text):
        threat_url_id = _clean_sentinelone_identifier(
            match.group(1)
        )

        if threat_url_id:
            threat_url_ids.append(threat_url_id)

    console_url = ""
    console_url_match = _SENTINELONE_CONSOLE_URL_PATTERN.search(
        safe_text
    )

    if console_url_match:
        console_url = console_url_match.group(0)

    unique_threat_ids = sorted(
        set(threat_ids)
    )
    unique_threat_url_ids = sorted(
        set(threat_url_ids)
    )

    evidence = {
        "sentinelone_threat_id":
            unique_threat_ids[0]
            if unique_threat_ids
            else "",
        "sentinelone_threat_url_id":
            unique_threat_url_ids[0]
            if unique_threat_url_ids
            else "",
        "sentinelone_identifier_source": ""
    }

    if console_url:
        evidence[
            "sentinelone_console_url"
        ] = console_url

    if unique_threat_ids:
        evidence[
            "sentinelone_identifier_source"
        ] = "description"
    elif unique_threat_url_ids:
        evidence[
            "sentinelone_identifier_source"
        ] = "url"

    if _AZURE_OR_MICROSOFT_SENTINEL_PATTERN.search(safe_text):
        evidence[
            "non_sentinelone_evidence_type"
        ] = "azure_or_microsoft_sentinel"

    return evidence


def _clean_securonix_identifier(value):
    if not isinstance(value, str):
        return ""

    return re.sub(
        r"(?i)(Incident|URL|ID|Details)$",
        "",
        value.strip().strip(":;,.)]'\"[")
    ).strip()


def _extract_query_parameter(url, parameter_name):
    if not isinstance(url, str):
        return ""

    match = re.search(
        rf"(?i)(?:[?&]){re.escape(parameter_name)}=([^&#\s]+)",
        url
    )

    if not match:
        return ""

    return _clean_securonix_identifier(
        match.group(1)
    )


def _extract_securonix_jira_evidence(
    summary,
    description,
    incident_id_field=None,
    incident_url_field=None
):
    safe_text = " ".join(
        value
        for value in [
            summary or "",
            _get_adf_text_with_links(description),
            _get_adf_text_with_links(incident_id_field),
            _get_adf_text_with_links(incident_url_field)
        ]
        if value
    )

    incident_ids = []

    direct_incident_id = _clean_securonix_identifier(
        _get_adf_text_with_links(incident_id_field)
    )

    if direct_incident_id:
        incident_ids.append(
            direct_incident_id
        )

    for pattern in _SECURONIX_INCIDENT_ID_PATTERNS:
        for match in pattern.finditer(safe_text):
            incident_id = _clean_securonix_identifier(
                match.group(1)
            )

            if incident_id:
                incident_ids.append(incident_id)

    incident_urls = []

    for match in _SECURONIX_INCIDENT_URL_PATTERN.finditer(safe_text):
        incident_url = match.group(0)

        if "solr" in incident_url.casefold():
            continue

        incident_urls.append(incident_url)

    unique_incident_ids = sorted(
        set(incident_ids)
    )
    unique_incident_urls = sorted(
        set(incident_urls)
    )

    incident_url_id = ""

    for incident_url in unique_incident_urls:
        incident_url_id = _extract_query_parameter(
            incident_url,
            "id"
        )

        if incident_url_id:
            break

    evidence = {
        "securonix_incident_id":
            unique_incident_ids[0]
            if unique_incident_ids
            else "",
        "securonix_incident_url":
            unique_incident_urls[0]
            if unique_incident_urls
            else "",
        "securonix_incident_url_id":
            incident_url_id,
        "securonix_identifier_source": ""
    }

    if incident_id_field:
        evidence[
            "securonix_identifier_source"
        ] = "custom_field"
    elif unique_incident_ids:
        evidence[
            "securonix_identifier_source"
        ] = "description"
    elif incident_url_id:
        evidence[
            "securonix_identifier_source"
        ] = (
            "custom_field"
            if incident_url_field
            else "url"
        )

    return evidence


def _clean_microsoft_sentinel_identifier(value):
    if value is None:
        return ""

    if not isinstance(value, str):
        value = str(value)

    return value.strip().strip(":;,.)]'\"[")


def _microsoft_sentinel_incident_guid_from_value(value):
    if not isinstance(value, str):
        return ""

    decoded_value = value.replace(
        "%2F",
        "/"
    ).replace(
        "%2f",
        "/"
    )

    match = _MS_SENTINEL_INCIDENT_GUID_PATTERN.search(
        decoded_value
    )

    if match:
        return match.group(1).lower()

    matches = _MS_SENTINEL_GUID_PATTERN.findall(
        decoded_value
    )

    if not matches:
        return ""

    return matches[-1].lower()


def _microsoft_sentinel_table_value(parsed_fields, field_name):
    value = _get_wazuh_table_value(
        parsed_fields,
        field_name
    )

    return _clean_microsoft_sentinel_identifier(
        value
    )


def _extract_microsoft_sentinel_labeled_value(safe_text, label):
    pattern = re.compile(
        rf"(?i)\b{re.escape(label)}\b\s*[:=]?\s*"
        r"(.+?)(?=\s+(?:Incident\s+ID|Incident\s+ARM\s+ID|"
        r"Incident\s+URL|Created\s+Time\s*\(UTC\)|"
        r"Last\s+Modified\s+Time\s*\(UTC\))\b|$)"
    )

    match = pattern.search(
        safe_text
    )

    if not match:
        return ""

    return _clean_microsoft_sentinel_identifier(
        match.group(1)
    )


def _extract_microsoft_sentinel_jira_evidence(description):
    parsed_fields = _parse_adf_table_fields(
        description
    )

    safe_text = _get_adf_text_with_links(
        description
    )

    incident_id = (
        _microsoft_sentinel_table_value(
            parsed_fields,
            "Incident ID"
        )
        or
        _extract_microsoft_sentinel_labeled_value(
            safe_text,
            "Incident ID"
        )
    )

    incident_arm_id = (
        _microsoft_sentinel_table_value(
            parsed_fields,
            "Incident ARM ID"
        )
        or
        _extract_microsoft_sentinel_labeled_value(
            safe_text,
            "Incident ARM ID"
        )
    )

    incident_url = (
        _microsoft_sentinel_table_value(
            parsed_fields,
            "Incident URL"
        )
        or
        _extract_microsoft_sentinel_labeled_value(
            safe_text,
            "Incident URL"
        )
    )

    if not incident_url:
        for match in _MS_SENTINEL_URL_PATTERN.finditer(
            safe_text
        ):
            candidate_url = match.group(0)

            if (
                "incident" in candidate_url.casefold()
                or
                "securityinsights" in candidate_url.casefold()
                or
                "portal.azure" in candidate_url.casefold()
            ):
                incident_url = candidate_url
                break

    created_time_utc = (
        _microsoft_sentinel_table_value(
            parsed_fields,
            "Created Time(UTC)"
        )
        or
        _extract_microsoft_sentinel_labeled_value(
            safe_text,
            "Created Time(UTC)"
        )
    )

    last_modified_time_utc = (
        _microsoft_sentinel_table_value(
            parsed_fields,
            "Last Modified Time(UTC)"
        )
        or
        _extract_microsoft_sentinel_labeled_value(
            safe_text,
            "Last Modified Time(UTC)"
        )
    )

    identifier_source = ""

    if any(
        [
            incident_id,
            incident_arm_id,
            incident_url,
            created_time_utc,
            last_modified_time_utc
        ]
    ):
        identifier_source = "description_adf"

    return {
        "microsoft_sentinel_incident_id": incident_id,
        "microsoft_sentinel_incident_arm_id": incident_arm_id,
        "microsoft_sentinel_incident_arm_guid":
            _microsoft_sentinel_incident_guid_from_value(
                incident_arm_id
            ),
        "microsoft_sentinel_incident_url": incident_url,
        "microsoft_sentinel_incident_url_guid":
            _microsoft_sentinel_incident_guid_from_value(
                incident_url
            ),
        "microsoft_sentinel_created_time_utc": created_time_utc,
        "microsoft_sentinel_last_modified_time_utc":
            last_modified_time_utc,
        "microsoft_sentinel_identifier_source":
            identifier_source
    }


def _get_adf_text(node):
    if isinstance(node, str):
        return node

    if not isinstance(node, dict):
        return ""

    if node.get("type") == "text":
        return node.get("text", "")

    return "".join(
        _get_adf_text(child)
        for child in node.get("content", [])
    )


def _normalize_wazuh_description_key(key):
    return key.replace("`", "").strip().lower()


def _parse_adf_table_fields(description):
    parsed_fields = {}

    if not isinstance(description, dict):
        return parsed_fields

    try:
        for section in description.get("content", []):
            if section.get("type") != "table":
                continue

            for row in section.get("content", []):
                cells = row.get("content", [])

                if len(cells) < 2:
                    continue

                key_text = _normalize_wazuh_description_key(
                    _get_adf_text(cells[0])
                )

                if not key_text:
                    continue

                parsed_fields[key_text] = _get_adf_text(cells[1]).strip()
    except Exception:
        return parsed_fields

    return parsed_fields


def _get_wazuh_table_value(parsed_fields, field_name):
    return parsed_fields.get(
        _normalize_wazuh_description_key(field_name),
        ""
    )


def _parse_json_object(value):
    if not isinstance(value, str) or not value.strip():
        return {}

    try:
        parsed_value = json.loads(value)
    except (TypeError, ValueError):
        return {}

    if not isinstance(parsed_value, dict):
        return {}

    return parsed_value


def _get_nested_wazuh_value(parsed_fields, object_name, child_name):
    direct_value = _get_wazuh_table_value(
        parsed_fields,
        f"{object_name}.{child_name}"
    )

    if direct_value:
        return str(direct_value)

    parent_value = _parse_json_object(
        _get_wazuh_table_value(
            parsed_fields,
            object_name
        )
    )

    nested_value = parent_value.get(child_name, "")

    if nested_value is None:
        return ""

    return str(nested_value)


def _normalize_tenant_values(tenant_values):
    if isinstance(tenant_values, list):
        return [
            value.strip()
            for value in tenant_values
            if isinstance(value, str) and value.strip()
        ]

    if isinstance(tenant_values, str) and tenant_values.strip():
        return [tenant_values.strip()]

    return []


def _hint_matches_text(hint, text):
    if not hint or not text:
        return False

    hint_text = hint.casefold()
    source_text = text.casefold()

    if hint_text == source_text:
        return True

    if len(hint_text) >= 4 and hint_text in source_text:
        return True

    for separator in (
        " ", "\t", "\r", "\n", ",", ";", ":", "/", "\\",
        "|", "(", ")", "[", "]", "{", "}", "_"
    ):
        source_text = source_text.replace(separator, "-")

    return hint_text in [
        part
        for part in source_text.split("-")
        if part
    ] or hint_text in source_text.split(".")


def _resolve_wazuh_jira_client(
    tenant_field,
    agent_name,
    manager_name,
    parsed_fields
):
    allowed_clients = set(WAZUH_CLIENT_MAPPING.values())

    tenant_matches = [
        value
        for value in tenant_field
        if value in allowed_clients
    ]

    safe_source_text = [agent_name, manager_name]
    excluded_source_keys = {"full_log", "data"}

    for key, value in parsed_fields.items():
        if key in excluded_source_keys or key.startswith("data."):
            continue

        safe_source_text.append(value)

    hint_matches = []

    for client, hints in WAZUH_JIRA_CLIENT_HINTS.items():
        if client not in allowed_clients:
            continue

        for hint in hints:
            if any(
                _hint_matches_text(hint, source)
                for source in safe_source_text
            ):
                hint_matches.append(client)
                break

    unique_tenant_matches = sorted(set(tenant_matches))
    unique_hint_matches = sorted(set(hint_matches))

    if len(unique_tenant_matches) == 1:
        resolved_client = unique_tenant_matches[0]
        client_resolution_source = "tenant_field"
        confidence = "high"
    elif len(unique_hint_matches) == 1:
        resolved_client = unique_hint_matches[0]
        client_resolution_source = "client_hint"
        confidence = "high"
    else:
        resolved_client = None
        client_resolution_source = "unmapped"
        confidence = "low"

    metadata_issues = []

    if not tenant_field and client_resolution_source == "client_hint":
        metadata_issues.append("missing_tenant_field")

    if (
        tenant_field
        and
        unique_hint_matches
        and
        resolved_client
        and (
            resolved_client not in unique_hint_matches
            or (
                client_resolution_source == "client_hint"
                and
                resolved_client not in tenant_field
            )
        )
    ):
        metadata_issues.append("tenant_field_mismatch")

    if not resolved_client:
        metadata_issues.append("unmapped_client")

    return {
        "resolved_client": resolved_client,
        "client_resolution_source": client_resolution_source,
        "confidence": confidence,
        "metadata_issues": metadata_issues
    }


def _issue_fields(issue):
    fields = issue.get(
        "fields",
        {}
    )

    if isinstance(fields, dict):
        return fields

    return {}


def _issue_key(issue):
    return issue.get(
        "key",
        ""
    )


def _jira_status_name(fields):
    status = fields.get(
        "status",
        {}
    )

    if isinstance(status, dict):
        return status.get(
            "name",
            ""
        )

    return status or ""


def _fetch_jira_issues(
    email,
    api_token,
    jql,
    fields,
    max_pages=None
):

    url = JIRA_URL

    all_issues = []

    next_page_token = None

    page_count = 0

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

        all_issues.extend(
            issues
        )

        page_count += 1

        if max_pages is not None and page_count >= max_pages:
            break

        if data.get(
            "isLast",
            True
        ):
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

        fields = _issue_fields(issue)

        description = fields.get(
            "description",
            {}
        )

        summary = fields.get(
            "summary",
            ""
        )

        client = extract_site_name(
            description
        )

        if client == "Unknown":
            continue
        
        tickets.append(
            {
                "key": _issue_key(issue),
                "client": client,
                "summary":
                    summary,
                "created":
                    fields.get(
                        "created",
                        ""
                    ),
                **_extract_sentinelone_jira_evidence(
                    summary,
                    description
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

        fields = _issue_fields(issue)

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
                "key": _issue_key(issue),
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


def fetch_wazuh_jira_tickets_for_correlation(
    email,
    api_token,
    max_pages=None
):
    jql = f'''
        project = NSIR
        AND type = "Wazuh Alert"
        AND created >= -{WAZUH_JIRA_WINDOW_HOURS}h
        ORDER BY created DESC
    '''.strip()

    all_issues = _fetch_jira_issues(
        email,
        api_token,
        jql,
        [
            "summary",
            "created",
            "issuetype",
            "status",
            "description",
            WAZUH_JIRA_TENANT_FIELD
        ],
        max_pages=max_pages,
    )

    tickets = []

    for issue in all_issues:
        fields = _issue_fields(issue)

        parsed_fields = _parse_adf_table_fields(
            fields.get("description", {})
        )

        tenant_field = _normalize_tenant_values(
            fields.get(WAZUH_JIRA_TENANT_FIELD)
        )

        agent_name = _get_wazuh_table_value(
            parsed_fields,
            "agent.name"
        )

        if not agent_name:
            agent_name = _get_nested_wazuh_value(
                parsed_fields,
                "agent",
                "name"
            )

        manager_name = _get_wazuh_table_value(
            parsed_fields,
            "manager.name"
        )

        if not manager_name:
            manager_name = _get_nested_wazuh_value(
                parsed_fields,
                "manager",
                "name"
            )

        client_resolution = _resolve_wazuh_jira_client(
            tenant_field,
            agent_name,
            manager_name,
            parsed_fields
        )

        tickets.append(
            {
                "jira_key": _issue_key(issue),
                "created": fields.get("created", ""),
                "summary": fields.get("summary", ""),
                "status": _jira_status_name(fields),
                "tenant_field": tenant_field,
                "wazuh_alert_id": _get_wazuh_table_value(
                    parsed_fields,
                    "id"
                ),
                "rule_id": _get_nested_wazuh_value(
                    parsed_fields,
                    "rule",
                    "id"
                ),
                "rule_level": _get_nested_wazuh_value(
                    parsed_fields,
                    "rule",
                    "level"
                ),
                "rule_description": _get_nested_wazuh_value(
                    parsed_fields,
                    "rule",
                    "description"
                ),
                "agent_name": agent_name,
                "manager_name": manager_name,
                "location": _get_wazuh_table_value(
                    parsed_fields,
                    "location"
                ),
                **client_resolution
            }
        )

    return tickets


def fetch_microsoft_sentinel_jira_tickets(
    email,
    api_token,
    client_name="ContractPodAi",
    max_pages=None
):
    client_config = MS_SENTINEL_CLIENTS.get(
        client_name,
        {}
    )

    jira_tenant = client_config.get(
        "jira_tenant"
    )

    summary_aliases = client_config.get(
        "summary_aliases",
        []
    )

    if not jira_tenant:
        raise ValueError(
            f"Microsoft Sentinel Jira tenant not configured: {client_name}"
        )

    if not summary_aliases:
        raise ValueError(
            f"Microsoft Sentinel summary aliases not configured: {client_name}"
        )

    summary_alias = summary_aliases[0]

    jql = f'''
        project = NSIR
        AND "Tenant Name" = "{jira_tenant}"
        AND summary ~ "{summary_alias}"
        AND created >= -{MS_SENTINEL_INCIDENT_WINDOW_HOURS}h
        ORDER BY created DESC
    '''.strip()

    all_issues = _fetch_jira_issues(
        email,
        api_token,
        jql,
        [
            "summary",
            "created",
            "status",
            "description",
            WAZUH_JIRA_TENANT_FIELD
        ],
        max_pages=max_pages,
    )

    tickets = []

    for issue in all_issues:
        fields = _issue_fields(issue)

        summary = fields.get(
            "summary",
            ""
        )

        if summary_alias.casefold() not in summary.casefold():
            continue

        tenant_values = _normalize_tenant_values(
            fields.get(WAZUH_JIRA_TENANT_FIELD)
        )

        if jira_tenant not in tenant_values:
            continue

        description = fields.get(
            "description",
            {}
        )

        tickets.append(
            {
                "key": _issue_key(issue),
                "jira_key": _issue_key(issue),
                "client": client_name,
                "strict_client": client_name,
                "tenant_field": jira_tenant,
                "summary": summary,
                "created": fields.get(
                    "created",
                    ""
                ),
                "status": _jira_status_name(fields),
                **_extract_microsoft_sentinel_jira_evidence(
                    description
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
            "description",
            _SECURONIX_INCIDENT_ID_FIELD,
            _SECURONIX_INCIDENT_URL_FIELD,
            SECURONIX_JIRA_TENANT_FIELD
        ]
    )

    allowed_client_set = set(
        allowed_clients
    )

    tickets = []

    for issue in all_issues:

        fields = _issue_fields(issue)

        description = fields.get(
            "description",
            {}
        )

        summary = fields.get(
            "summary",
            ""
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
                "key": _issue_key(issue),
                "client": client,
                "summary":
                    summary,
                "created":
                    fields.get(
                        "created",
                        ""
                    ),
                **_extract_securonix_jira_evidence(
                    summary,
                    description,
                    fields.get(
                        _SECURONIX_INCIDENT_ID_FIELD
                    ),
                    fields.get(
                        _SECURONIX_INCIDENT_URL_FIELD
                    )
                )
            }
        )

    return tickets
