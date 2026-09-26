import json, time, urllib.request, urllib.error
from typing import Optional, List, Dict
import config


def send_alert(
    webhook_url: str,
    message: str = "",
    title: str = "Notification",
    fields: Optional[List[Dict]] = None,
) -> bool:
    '''Send a plain Discord message: title, then fields, then message in a code block, split into Discord-safe chunks.'''
    limit = getattr(config, "DISCORD_LIMIT", 1900)
    field_lines = "\n".join(f"**{f['name']}:** {f['value']}" for f in fields) if fields else ""

    chunks = [message[i:i + limit] for i in range(0, len(message), limit)] or [""]
    total = len(chunks)
    success = True

    for idx, chunk in enumerate(chunks, start=1):
        header = f"**{title}**" if total == 1 else f"**{title} ({idx}/{total})**"
        content = header
        if field_lines and idx == 1:
            content += f"\n{field_lines}"
        if chunk:
            content += f"\n```\n{chunk}\n```"

        try:
            data = json.dumps({"content": content}).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=data,
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req) as response:
                if response.status != 204:
                    print(f"Discord transmission response status error: {response.status}")
                    success = False
        except urllib.error.HTTPError as e:
            print(f"Failed to send Discord notification: {e.code}: {e.read().decode()}")
            success = False
        # Small delay between chunks to avoid hitting Discord's rate limit.
        if total > 1:
            time.sleep(1)

    return success
