import sys, os
import subprocess as sub


# Sensitive files to monitor.
SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh/authorized_keys",
]


def setup_audit_rules(file_key: str, exec_key: str):
    """Set up audit rules for sensitive files and execve calls."""

    # Delete all existing audit rules.
    sub.run(
        ["auditctl", "-D"],
        stdout=sub.DEVNULL,
        stderr=sub.DEVNULL,
    )

    try:
        # Monitor sensitive file access.
        for path in SENSITIVE_FILES:
            sub.run(
                [
                    "auditctl",
                    "-w",
                    path,
                    "-p",
                    "rwxa",
                    "-k",
                    file_key,
                ],
                check=True,
            )

        # Monitor command execution.
        sub.run(
            [
                "auditctl",
                "-a",
                "always,exit",
                "-F",
                "arch=b64",
                "-S",
                "execve",
                "-k",
                exec_key,
            ],
            check=True,
        )

    except sub.CalledProcessError as e:
        print(
            f"Failed to register the audit rule. "
            f"Check if you have root privileges: {e}"
        )
        sys.exit(os.EX_NOPERM)


def cleanup_audit_rules():
    """Remove all audit rules and reset the audit configuration."""

    print("Delete All Existing Audit Rules.")

    sub.run(
        ["auditctl", "-D"],
        stdout=sub.DEVNULL,
        stderr=sub.DEVNULL,
    )

    print("Rule removal complete. Script terminated.")
```
