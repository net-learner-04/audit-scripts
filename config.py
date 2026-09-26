import re

# sec
INTERVAL = 10

# Discord's hard limit is 2000 chars per plain message; keep some margin.
DISCORD_LIMIT = 1900

# All keywords are treated as high-risk; matched with word boundaries to avoid false positives like "sync"/"disk".
KEYWORDS = ["dd", "/etc/shadow", "/etc/sudoers", "authorized_keys",]

_KEYWORD_PATTERN = re.compile(
    r"\b(?:" + "|".join(re.escape(k) for k in KEYWORDS) + r")\b",
    re.IGNORECASE
)
