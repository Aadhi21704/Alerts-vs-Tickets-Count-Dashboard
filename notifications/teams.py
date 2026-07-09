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

def _safe_text(value):
    if value is None:
        return "-"

    text = str(value).strip()

    if not text:
        return "-"

    return text[:300]


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

    card = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": "D13438",
        "title": title,
        "sections": [
            {
                "activityTitle": "Mismatch requires review",
                "facts": facts,
                "markdown": True
            }
        ]
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
