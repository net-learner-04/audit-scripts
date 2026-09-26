import re

# sec
INTERVAL = 10

# Discord's hard limit is 2000 chars per plain message; keep some margin.
DISCORD_LIMIT = 1900

# Keywords worth reporting, tiered by risk so alerts can be color-coded; matched with word boundaries to avoid false positives like "sync"/"disk".
RISK_KEYWORDS = {
    "high": [
        "wget", "curl", "nc", "ncat", "netcat", "chmod", "base64",
        "/etc/shadow", "/etc/sudoers", "rm", "dd",
        "ssh-keygen", "authorized_keys",
    ],
    "medium": [
        "sudo", "su", "iptables", "nft", "crontab", "nohup", "disown",
    ],
    "low": [
        "python", "python3", "perl", "ruby",
        "bash", "sh", "zsh", "dash", "history",
    ],
}

# Flattened list, kept for backwards-compat with anything matching on "any suspicious keyword".
KEYWORDS = [kw for group in RISK_KEYWORDS.values() for kw in group]

# Pre-compiled patterns: one overall, plus one per risk tier for color-coding.
_KEYWORD_PATTERN = re.compile(
    r"\b(?:" + "|".join(re.escape(k) for k in KEYWORDS) + r")\b",
    re.IGNORECASE
)
_RISK_PATTERNS = {
    risk: re.compile(r"\b(?:" + "|".join(re.escape(k) for k in kws) + r")\b", re.IGNORECASE)
    for risk, kws in RISK_KEYWORDS.items()
}


def get_risk_level(cmd_line: str):
    '''Return the highest matching risk tier ("high" > "medium" > "low") for a command line, or None.'''
    for risk in ("high", "medium", "low"):
        if _RISK_PATTERNS[risk].search(cmd_line):
            return risk
    return None
