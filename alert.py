import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional, List, Dict


# Discord embed color for security alerts.
ALERT_COLOR = 0xE74C3C


def send_alert(
    webhook_url: str,
    message: str = "",
    title: str = "Security Alert",
    fields: Optional[List[Dict]] = None,
) -> bool:
    """Send a security alert to Discord using an embed."""

    if not webhook_url:
        print("Discord webhook URL is not configured.")
        return False

    embed = {
        "title": title,
        "color": ALERT_COLOR,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {
            "text": "Audit"
        },
    }

    # Add event information as embed fields.
    if fields:
        embed["fields"] = []

        for field in fields:
            name = str(field.get("name", "Unknown"))
            value = str(field.get("value", "Unknown"))

            embed["fields"].append(
                {
                    "name": name,
                    "value": value,
                    "inline": False,
                }
            )

    # Add the detected command after the fields.
    if message:
        embed["fields"].append(
            {
                "name": "Command",
                "value": f"```text\n{message}\n```",
                "inline": False,
            }
        )

    payload = {
        "embeds": [embed]
    }

    try:
        data = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            webhook_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Audit/1.0",
            },
            method="POST",
        )

        with urllib.request.urlopen(request) as response:
            if response.status == 204:
                return True

            print(
                f"Discord transmission response status error: "
                f"{response.status}"
            )
            return False

    except urllib.error.HTTPError as e:
        try:
            error_body = e.read().decode("utf-8")
        except Exception:
            error_body = ""

        print(
            f"Failed to send Discord notification: "
            f"{e.code}: {error_body}"
        )
        return False

    except urllib.error.URLError as e:
        print(f"Failed to connect to Discord: {e}")
        return False

    except Exception as e:
        print(f"Unexpected Discord notification error: {e}")
        return False
