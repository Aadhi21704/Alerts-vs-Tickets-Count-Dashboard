import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

from notifications.teams import (
    send_teams_mismatch_notification,
    teams_notifications_enabled,
    teams_webhook_configured
)


def main():
    load_dotenv()

    print("Teams notification test")
    print(
        "  notifications: "
        + (
            "enabled"
            if teams_notifications_enabled()
            else "disabled"
        )
    )
    print(
        "  webhook: "
        + (
            "configured"
            if teams_webhook_configured()
            else "missing"
        )
    )

    payload = {
        "title": "Dashboard Teams test notification",
        "tool_name": "Smoke Test",
        "tool_key": "manual_test",
        "client": "Manual Safe Test",
        "alert_count": 0,
        "ticket_count": 0,
        "missing_ticket_count": 0,
        "extra_ticket_count": 0,
        "timestamp": datetime.now(UTC).isoformat()
    }

    sent = send_teams_mismatch_notification(
        payload
    )

    print(
        "  result: "
        + (
            "sent"
            if sent
            else "not sent"
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
