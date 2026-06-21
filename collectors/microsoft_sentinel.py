import os
import re
from datetime import UTC, datetime, timedelta

import requests
import urllib3

from config import (
    MS_SENTINEL_API_VERSION,
    MS_SENTINEL_CLIENTS,
    MS_SENTINEL_INCIDENT_WINDOW_HOURS,
    MS_SENTINEL_PAGE_SIZE
)


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


_TOKEN_CACHE = {}

_INCIDENT_GUID_PATTERN = re.compile(
    r"(?i)/incidents/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12})(?:$|[/?#])"
)


def _get_required_env(name):
    value = os.getenv(name, "").strip()

    if not value:
        raise ValueError(
            f"{name} not set"
        )

    return value


def _incident_guid_from_arm_id(arm_id):
    if not isinstance(arm_id, str):
        return ""

    match = _INCIDENT_GUID_PATTERN.search(
        arm_id
    )

    if not match:
        return ""

    return match.group(1).lower()


def _client_credentials(client_config):
    return {
        "tenant_id": _get_required_env(
            client_config["tenant_id_env"]
        ),
        "client_id": _get_required_env(
            client_config["client_id_env"]
        ),
        "client_secret": _get_required_env(
            client_config["client_secret_env"]
        ),
        "subscription_id": _get_required_env(
            client_config["subscription_id_env"]
        ),
        "resource_group_name": _get_required_env(
            client_config["resource_group_name_env"]
        ),
        "workspace_name": _get_required_env(
            client_config["workspace_name_env"]
        )
    }


def _get_access_token(client_name, client_config):
    credentials = _client_credentials(
        client_config
    )

    cached_token = _TOKEN_CACHE.get(
        client_name
    )

    now = datetime.now(UTC)

    if (
        cached_token
        and cached_token["expires_at"] > now + timedelta(minutes=5)
    ):
        return cached_token["access_token"], credentials

    token_url = (
        "https://login.microsoftonline.com/"
        f"{credentials['tenant_id']}/oauth2/v2.0/token"
    )

    response = requests.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": credentials["client_id"],
            "client_secret": credentials["client_secret"],
            "scope": "https://management.azure.com/.default"
        },
        timeout=60,
        verify=False
    )

    response.raise_for_status()

    token_data = response.json()
    access_token = token_data.get(
        "access_token"
    )

    if not access_token:
        raise ValueError(
            "Microsoft Sentinel token response missing access_token"
        )

    expires_in = token_data.get(
        "expires_in",
        3599
    )

    try:
        expires_in = int(expires_in)
    except (TypeError, ValueError):
        expires_in = 3599

    _TOKEN_CACHE[client_name] = {
        "access_token": access_token,
        "expires_at": now + timedelta(seconds=expires_in)
    }

    return access_token, credentials


def _incidents_url(credentials):
    return (
        "https://management.azure.com/subscriptions/"
        f"{credentials['subscription_id']}/resourceGroups/"
        f"{credentials['resource_group_name']}/providers/"
        "Microsoft.OperationalInsights/workspaces/"
        f"{credentials['workspace_name']}/providers/"
        "Microsoft.SecurityInsights/incidents"
    )


def _normalize_incident(client_name, workspace_name, incident):
    properties = incident.get(
        "properties",
        {}
    )

    if not isinstance(properties, dict):
        properties = {}

    arm_id = incident.get(
        "id",
        ""
    )

    incident_name = incident.get(
        "name",
        ""
    )

    incident_guid = (
        _incident_guid_from_arm_id(arm_id)
        or (
            incident_name.lower()
            if isinstance(incident_name, str)
            else ""
        )
    )

    incident_number = properties.get(
        "incidentNumber"
    )

    return {
        "id": incident_name or incident_guid or incident_number,
        "client": client_name,
        "source": "microsoft_sentinel",
        "microsoft_sentinel_incident_name": incident_name,
        "microsoft_sentinel_incident_guid": incident_guid,
        "microsoft_sentinel_incident_id": incident_number,
        "incident_number": incident_number,
        "microsoft_sentinel_incident_arm_id": arm_id,
        "microsoft_sentinel_workspace_name": workspace_name,
        "title": properties.get("title"),
        "severity": properties.get("severity"),
        "status": properties.get("status"),
        "created": properties.get("createdTimeUtc"),
        "updated": properties.get("lastModifiedTimeUtc"),
        "first_activity_time": properties.get("firstActivityTimeUtc"),
        "last_activity_time": properties.get("lastActivityTimeUtc"),
        "alert_count": properties.get("additionalData", {}).get(
            "alertsCount"
        )
        if isinstance(properties.get("additionalData"), dict)
        else None
    }


def fetch_microsoft_sentinel_incidents(client_name="ContractPodAi"):
    client_config = MS_SENTINEL_CLIENTS.get(
        client_name
    )

    if not client_config:
        raise ValueError(
            f"Unknown Microsoft Sentinel client: {client_name}"
        )

    if not client_config.get("enabled", False):
        return []

    access_token, credentials = _get_access_token(
        client_name,
        client_config
    )

    created_after = datetime.now(UTC) - timedelta(
        hours=MS_SENTINEL_INCIDENT_WINDOW_HOURS
    )

    params = {
        "api-version": MS_SENTINEL_API_VERSION,
        "$filter": (
            "properties/createdTimeUtc ge "
            f"{created_after.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        ),
        "$orderby": "properties/createdTimeUtc desc",
        "$top": str(MS_SENTINEL_PAGE_SIZE)
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    url = _incidents_url(
        credentials
    )

    incidents = []

    while url:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=90,
            verify=False
        )

        response.raise_for_status()

        data = response.json()

        for incident in data.get("value", []):
            if not isinstance(incident, dict):
                continue

            incidents.append(
                _normalize_incident(
                    client_name,
                    credentials["workspace_name"],
                    incident
                )
            )

        url = data.get("nextLink")
        params = None

    return incidents
