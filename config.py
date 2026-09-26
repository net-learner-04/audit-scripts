import re

# Monitoring interval (seconds)
INTERVAL = 10

# Malicious commands and sensitive files.
KEYWORDS = [
    "dd",
    "/etc/shadow",
    "/etc/sudoers",
    "authorized_keys",
]


# Match keywords without requiring word boundaries around
# non-word characters such as "/" in file paths.
_KEYWORD_PATTERN = re.compile(
    r"(?<!\w)(?:"
    + "|".join(re.escape(k) for k in KEYWORDS)
    + r")(?!\w)",
    re.IGNORECASE,
)
