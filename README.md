# Audit Log Watcher

A lightweight Linux security monitor that uses `auditd` to detect sensitive
file access and malicious command execution, then sends alerts to Discord.

## Features

* Monitors sensitive files such as `/etc/passwd`.
* Monitors process execution through `execve`.
* Parses and decodes auditd logs in real time.
* Detects high-risk commands using keywords defined in `config.py`.
* Sends security alerts to Discord using embeds.
* Handles audit log rotation.
* Removes its audit rules when stopped.

## Files

| File        | Purpose                                        |
| ----------- | ---------------------------------------------- |
| `main.py`   | Main monitoring loop                           |
| `audit.py`  | Configures and removes audit rules             |
| `tailer.py` | Follows the audit log and handles log rotation |
| `parser.py` | Parses auditd log entries                      |
| `config.py` | Monitoring settings and high-risk keywords     |
| `alert.py`  | Sends Discord embed alerts                     |

## Requirements

* Linux
* `auditd` and `auditctl`
* Python 3
* Root privileges
* `python-dotenv`

Install the Python dependency:

```bash
pip install python-dotenv
```

## Setup

Create a `.env` file in the project directory:

```env
WEBHOOK=https://discord.com/api/webhooks/xxxxx/yyyyy
FILE_KEY=my_secret_key
EXEC_KEY=my_exec_key
AUDIT_LOG_PATH=/var/log/audit/audit.log
```

* `WEBHOOK` — Discord webhook URL.
* `FILE_KEY` — audit rule key for sensitive file access.
* `EXEC_KEY` — audit rule key for process execution.
* `AUDIT_LOG_PATH` — audit log path.

Run the monitor as root:

```bash
sudo python3 main.py
```

## Detection

The monitor currently detects:

### Sensitive file access

Audit rules are used to monitor configured sensitive files.

When access is detected, an alert is sent immediately.

### High-risk commands

Commands are checked against the keyword list in `config.py`.

Current high-risk keywords:

```text
dd
/etc/shadow
/etc/sudoers
authorized_keys
```

When a match is found, the Discord alert contains:

* User
* Command
* Detection time

## Discord Alerts

Alerts are sent as Discord embeds.

Example:

```text
Malicious Command Detected

User
root (uid=0)

Command
dd if=/dev/zero of=/tmp/testfile bs=1K count=1

Audit
```

## Notes

* The monitor requires root privileges to configure audit rules.
* Audit rules are removed when the program exits.
* This is a lightweight host monitoring tool, not a full SIEM.
