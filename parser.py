import re, config

# auditd hex-encodes EXECVE args containing spaces/quotes/non-printables.
_HEX_PATTERN = re.compile(r'^[0-9A-Fa-f]+$')

# Matches only EXECVE arg keys (a0, a1, ...); other numeric fields (uid, pid, ...) must never be hex-decoded.
_EXECVE_ARG_KEY_PATTERN = re.compile(r'^a[0-9]+$')

# Detects an ENRICHED-format field (e.g. UID=) glued onto the previous field with no space.
_ENRICHED_GLUE_PATTERN = re.compile(r'(?<=[^\sA-Z])([A-Z][A-Z0-9_]*=)')


def is_suspicious(cmd_line: str) -> bool:
    '''Check whether a command line contains any keyword worth reporting.'''
    return bool(config._KEYWORD_PATTERN.search(cmd_line))


def decode_execve_arg(arg: str) -> str:
    '''Decode a single EXECVE argument, converting hex-encoded strings back to plain text.'''
    # Only pure, even-length hex strings are treated as hex-encoded.
    if len(arg) % 2 == 0 and len(arg) > 0 and _HEX_PATTERN.match(arg):
        try:
            return bytes.fromhex(arg).decode("utf-8", errors="replace")
        except ValueError:
            return arg
    return arg


def parse_audit_log(line: str) -> dict:
    '''Parse a raw audit log line into a dictionary of key-value pairs.'''
    # Insert a space before glued-on ENRICHED fields so the regex below doesn't swallow them.
    line = _ENRICHED_GLUE_PATTERN.sub(r' \1', line)

    p = r'([a-zA-Z0-9_]+)=(?:"([^"]*)"|([^"\s]+))'
    m = re.findall(p, line)

    data = dict()

    for item in m:
        key, quoted_val, bare_val = item[0], item[1], item[2]

        # Quoted values are already text; only bare (unquoted) values may be hex-encoded.
        if quoted_val:
            value = quoted_val
        else:
            # Only EXECVE arg fields get hex-decoded; other bare fields stay as-is.
            if _EXECVE_ARG_KEY_PATTERN.match(key):
                value = decode_execve_arg(bare_val)
            else:
                value = bare_val

        data[key] = value

    return data
