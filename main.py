import os, pwd
from datetime import datetime
from dotenv import load_dotenv
import config
from audit import setup_audit_rules, cleanup_audit_rules
from tailer import file_tailing
from parser import parse_audit_log, is_suspicious
from alert import send_alert


# Load environment variables.
load_dotenv()

WEBHOOK = os.getenv("WEBHOOK")
FILE_KEY = os.getenv("FILE_KEY", "my_secret_key")
EXEC_KEY = os.getenv("EXEC_KEY", "my_exec_key")
AUDIT_LOG_PATH = os.getenv(
    "AUDIT_LOG_PATH",
    "/var/log/audit/audit.log",
)


def resolve_username(uid) -> str:
    """Resolve a UID to its username, falling back to the raw UID."""
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (ValueError, KeyError, TypeError):
        return str(uid)


def start():
    """Continuously monitor audit logs and send security alerts."""
    buffer = {}

    setup_audit_rules(FILE_KEY, EXEC_KEY)

    print(
        f"Start time: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M')}"
    )
    print(f"Monitoring the {AUDIT_LOG_PATH} file...")

    try:
        for line in file_tailing(AUDIT_LOG_PATH):
            parsed_data = parse_audit_log(line)

            if "type" not in parsed_data:
                continue

            log_type = parsed_data.get("type")
            log_key = parsed_data.get("key")
            msg_id = parsed_data.get("msg_id")

            # Sensitive file access.
            if log_type == "SYSCALL":
                if log_key == FILE_KEY:
                    exe_path = parsed_data.get("exe", "Unknown")
                    uid_val = parsed_data.get("uid", "Unknown")
                    username = resolve_username(uid_val)

                    target = parsed_data.get("name", "Unknown")

                    send_alert(
                        WEBHOOK,
                        title="Sensitive File Access Detected",
                        fields=[
                            {
                                "name": "User",
                                "value": f"{username} (uid={uid_val})",
                            },
                            {
                                "name": "Target",
                                "value": target,
                            },
                            {
                                "name": "Program",
                                "value": exe_path,
                            },
                            {
                                "name": "Event ID",
                                "value": str(msg_id),
                            },
                        ],
                    )

                # Process execution.
                elif log_key == EXEC_KEY:
                    buffer[msg_id] = {
                        "exe": parsed_data.get("exe", "Unknown"),
                        "uid": parsed_data.get("uid", "Unknown"),
                        "args": [],
                    }

            # EXECVE contains the actual command arguments.
            elif log_type == "EXECVE":
                if msg_id not in buffer:
                    continue

                for key in sorted(parsed_data.keys()):
                    if key.startswith("a") and key[1:].isdigit():
                        buffer[msg_id]["args"].append(
                            parsed_data[key]
                        )

                cmd_line = " ".join(
                    buffer[msg_id]["args"]
                )

                if is_suspicious(cmd_line):
                    exe = buffer[msg_id]["exe"]
                    uid = buffer[msg_id]["uid"]
                    username = resolve_username(uid)

                    send_alert(
                        WEBHOOK,
                        cmd_line,
                        title="Malicious Command Detected",
                        fields=[
                            {
                                "name": "User",
                                "value": f"{username} (uid={uid})",
                            },
                        ],
                    )

                buffer.pop(msg_id, None)

                # Prevent unbounded memory usage.
                if len(buffer) > 10000:
                    buffer.clear()

    except KeyboardInterrupt:
        print("The script is terminated by the user.")

    finally:
        cleanup_audit_rules()


if __name__ == "__main__":
    start()
```
