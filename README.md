# Audit Log Watcher → Discord Alerts

A lightweight Linux security monitoring tool that uses `auditd` to watch for
sensitive file access and suspicious command execution, then reports findings
to a Discord channel via webhook.

## What it does

- **Sets up audit rules** (`audit.py`) to monitor:
  - Writes/reads to `/etc/passwd`
  - All process executions (`execve` syscalls)
- **Tails the audit log** (`tailer.py`) in real time, handling log rotation
  transparently (e.g. when `auditd` rotates `audit.log`).
- **Parses raw audit log lines** (`parser.py`) into structured key/value data,
  including decoding auditd's hex-encoded `EXECVE` arguments and handling the
  "ENRICHED" log format.
- **Filters for suspicious commands** using a keyword list (`config.py`) —
  things like `wget`, `curl`, `chmod`, `base64`, `sudo`, `ssh-keygen`, shell
  interpreters, etc. — matched with word boundaries to avoid false positives.
- **Sends alerts to Discord** (`discord.py`) as rich embeds:
  - Immediate alert when `/etc/passwd` is accessed.
  - Periodic batched report (every 5 minutes) of suspicious commands executed,
    queued and rate-limited before sending.
- **Cleans up** all audit rules on exit (including `Ctrl+C`).

## Files

| File | Purpose |
|---|---|
| `main.py` | Entry point; main event loop tying everything together |
| `audit.py` | Sets up / tears down `auditctl` rules (requires root) |
| `tailer.py` | Follows the audit log file, handles rotation |
| `parser.py` | Parses and decodes raw audit log lines |
| `config.py` | Tunables: polling interval, Discord limits, keyword list |
| `discord.py` | Sends formatted messages/embeds to a Discord webhook |

## Requirements

- Linux with `auditd` and `auditctl` installed, and **root privileges**
  (needed to configure audit rules).
- Python 3
- `python-dotenv` (`pip install python-dotenv`)

## Setup

1. Create a `.env` file in the project root:

   ```env
   WEBHOOK=https://discord.com/api/webhooks/xxxxx/yyyyy
   FILE_KEY=my_secret_key
   EXEC_KEY=my_exec_key
   AUDIT_LOG_PATH=/var/log/audit/audit.log
   ```

   - `WEBHOOK` — your Discord webhook URL (required).
   - `FILE_KEY` / `EXEC_KEY` — audit rule tags used internally to correlate
     log entries (optional, sensible defaults provided).
   - `AUDIT_LOG_PATH` — path to the audit log (defaults to the standard
     location).

2. Run as root (needed for `auditctl`):

   ```bash
   sudo python3 main.py
   ```

   It's recommended to run this inside `tmux` or as a `systemd` service so it
   keeps running in the background.

## How alerts work

- **File access alert**: sent immediately, with fields for the target file,
  the program used, the UID, and the audit event ID.
- **Suspicious exec report**: suspicious command lines are buffered and sent
  as a single batched report every 5 minutes, respecting Discord's rate
  limits and message-length caps (long reports are automatically split
  across multiple embeds).

## Notes

- All audit rules are cleared on startup and on exit (`auditctl -D`), so this
  tool takes exclusive ownership of audit rules while running.
- This is intended as a simple host intrusion-detection / alerting tool for a
  single server, not a full SIEM replacement.
