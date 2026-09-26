import os, pwd
from datetime import datetime
from dotenv import load_dotenv
# Import modular components
import config
from audit import setup_audit_rules, cleanup_audit_rules
from tailer import file_tailing
from parser import parse_audit_log, is_suspicious
from alert import send_alert

# Load environment variables
load_dotenv()

WEBHOOK = os.getenv("WEBHOOK")
FILE_KEY = os.getenv("FILE_KEY", "my_secret_key")
EXEC_KEY = os.getenv("EXEC_KEY", "my_exec_key")
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "/var/log/audit/audit.log")


def resolve_username(uid) -> str:
    '''Resolve a UID to its username (requires root), falling back to the raw UID if unknown.'''
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (ValueError, KeyError, TypeError):
        return str(uid)


def start():
    '''Main loop: continuously monitors audit logs and sends an alert immediately on any high-risk event.'''
    buffer = dict()
    setup_audit_rules(FILE_KEY, EXEC_KEY)

    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"Monitoring the {AUDIT_LOG_PATH} file...")

    try:
        for line in file_tailing(AUDIT_LOG_PATH):
            parsed_data = parse_audit_log(line)

            if "type" not in parsed_data:
                continue

            log_type = parsed_data.get("type")
            log_key = parsed_data.get("key")
            msg_id = parsed_data.get("msg_id")

            if log_type == "SYSCALL":
                if parsed_data.get("key") == FILE_KEY:
                    exe_path = parsed_data.get("exe", "Unknown")
                    uid_val = parsed_data.get("uid", "Unknown")
                    username = resolve_username(uid_val)

                    send_alert(
                        WEBHOOK,
                        title="Sensitive File Access Detected",
                        fields=[
                            {"name": "Target", "value": "/etc/passwd"},
                            {"name": "Program", "value": exe_path},
                            {"name": "User", "value": f"{username} (uid={uid_val})"},
                            {"name": "Event ID", "value": str(msg_id)},
                        ],
                    )

                elif log_key == EXEC_KEY:
                    buffer[msg_id] = {
                        "exe": parsed_data.get("exe", "Unknown"),
                        "uid": parsed_data.get("uid", "Unknown"),
                        # A list to store the commands used when the type is EXECVE.
                        "args": []
                    }
            elif log_type == "EXECVE":
                if msg_id in buffer:
                    for key in sorted(parsed_data.keys()):
                        if key.startswith("a") and key[1:].isdigit():
                            # parsed_data[key] is already decoded (see parse_audit_log).
                            buffer[msg_id]["args"].append(parsed_data[key])

                    if len(buffer) > 10000:
                        buffer.clear()

                    cmd_line = " ".join(buffer[msg_id]["args"])

                    if is_suspicious(cmd_line):
                        exe = buffer[msg_id]["exe"]
                        uid = buffer[msg_id]["uid"]
                        username = resolve_username(uid)

                        send_alert(
                            WEBHOOK,
                            cmd_line,
                            title="Malicious Command Detected",
                            fields=[
                                {"name": "User", "value": f"{username} (uid={uid})"},
                            ],
                        )

                    buffer.pop(msg_id)
    except KeyboardInterrupt as e:
        print(f"The script is terminated by the user: {e}")
    finally:
        cleanup_audit_rules()


if __name__ == "__main__":
    start()
