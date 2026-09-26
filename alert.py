import json, time, urllib.request, urllib.error
from typing import Optional, List, Dict
import config

_RESET = "\u001b[0m"
_LEVEL_COLOR = {"error": "\u001b[1;31m", "warning": "\u001b[1;33m", "success": "\u001b[1;32m", "info": "\u001b[0;37m"}
_RISK_COLOR = {"high": "\u001b[1;31m", "medium": "\u001b[1;33m", "low": "\u001b[1;32m", None: "\u001b[0;37m"}


def _colorize_line(line: str) -> str:
    '''Wrap one report line in an ANSI color based on its highest matched risk keyword.'''
    color = _RISK_COLOR.get(config.get_risk_level(line))
    return f"{color}{line}{_RESET}"


def send_alert(
    webhook_url: str,
    message: str = "",
    title: str = "Notification",
    level: str = "info",
    fields: Optional[List[Dict]] = None,
    colorize_lines: bool = False,
) -> bool:
    '''Send a plain (non-embed) Discord message, colored via an ansi code block, split into Discord-safe chunks.'''
    limit = getattr(config, "DISCORD_LIMIT", 1900)

    if colorize_lines and message:
        body = "\n".join(_colorize_line(line) for line in message.split("\n"))
    elif message:
        body = f"{_LEVEL_COLOR.get(level, _LEVEL_COLOR['info'])}{message}{_RESET}"
    else:
        body = ""

    # Fields render as plain markdown lines above the code block (only on the first chunk).
    field_lines = "\n".join(f"**{f['name']}:** {f['value']}" for f in fields) if fields else ""

    chunks = [body[i:i + limit] for i in range(0, len(body), limit)] or [""]
    total = len(chunks)
    success = True

    for idx, chunk in enumerate(chunks, start=1):
        header = f"**{title}**" if total == 1 else f"**{title} ({idx}/{total})**"
        content = header
        if field_lines and idx == 1:
            content += f"\n{field_lines}"
        if chunk:
            content += f"\n```ansi\n{chunk}\n```"

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
