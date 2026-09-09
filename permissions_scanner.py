import os
import stat


# Terminal colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


# Virtual/system directories to skip during recursive scanning
SKIP_DIRECTORIES = {
    "proc",
    "sys",
    "dev",
    "run"
}


def get_file_mode(path):
    """Return the file mode, or None if it cannot be accessed."""
    try:
        return os.stat(path).st_mode
    except (PermissionError, FileNotFoundError, OSError):
        return None


def get_permissions(path):
    """Return the Linux permission string."""
    mode = get_file_mode(path)

    if mode is None:
        return "UNKNOWN"

    return stat.filemode(mode)


def is_regular_file(path):
    """Check whether the path is a regular file."""
    mode = get_file_mode(path)

    if mode is None:
        return False

    return stat.S_ISREG(mode)


def is_directory(path):
    """Check whether the path is a directory."""
    mode = get_file_mode(path)

    if mode is None:
        return False

    return stat.S_ISDIR(mode)


def is_world_writable(path):
    """Check whether a file or directory is world-writable."""
    mode = get_file_mode(path)

    if mode is None:
        return False

    return bool(mode & stat.S_IWOTH)


def is_group_writable(path):
    """Check whether a file or directory is group-writable."""
    mode = get_file_mode(path)

    if mode is None:
        return False

    return bool(mode & stat.S_IWGRP)


def check_sensitive_files():
    """
    Check permissions on sensitive files such as
    /etc/passwd and /etc/shadow.
    """

    findings = []

    sensitive_files = [
        "/etc/passwd",
        "/etc/shadow"
    ]

    for path in sensitive_files:

        if not os.path.exists(path):
            continue

        permissions = get_permissions(path)

        if is_world_writable(path):

            findings.append({
                "type": "Sensitive File Permission",
                "path": path,
                "permissions": permissions,
                "severity": "HIGH",
                "finding": "Sensitive system file is world-writable",
                "recommendation":
                    "Remove unnecessary world-write permission."
            })

        elif is_group_writable(path):

            findings.append({
                "type": "Sensitive File Permission",
                "path": path,
                "permissions": permissions,
                "severity": "HIGH",
                "finding": "Sensitive system file is group-writable",
                "recommendation":
                    "Review group ownership and remove unnecessary "
                    "write permission."
            })

    return findings


def scan_world_writable_files(root="/"):
    """
    Find regular files that are writable by any local user.
    """

    findings = []

    for current_root, directories, files in os.walk(
        root,
        topdown=True,
        onerror=lambda error: None
    ):

        # Skip virtual/system filesystems
        directories[:] = [
            directory
            for directory in directories
            if directory not in SKIP_DIRECTORIES
        ]

        for filename in files:

            path = os.path.join(current_root, filename)

            # Only analyze actual regular files.
            # This prevents devices, sockets and FIFOs
            # from being incorrectly classified as files.
            if not is_regular_file(path):
                continue

            if is_world_writable(path):

                findings.append({
                    "type": "World-Writable File",
                    "path": path,
                    "permissions": get_permissions(path),
                    "severity": "HIGH",
                    "finding":
                        "Regular file is writable by any local user",
                    "recommendation":
                        "Review whether world-write permission is "
                        "required and remove it if unnecessary."
                })

    return findings


def scan_privileged_writable_files(root="/"):
    """
    Find regular files with SUID or SGID bits that are also
    writable by a user or group.
    """

    findings = []

    for current_root, directories, files in os.walk(
        root,
        topdown=True,
        onerror=lambda error: None
    ):

        directories[:] = [
            directory
            for directory in directories
            if directory not in SKIP_DIRECTORIES
        ]

        for filename in files:

            path = os.path.join(current_root, filename)

            # Only analyze regular files
            if not is_regular_file(path):
                continue

            mode = get_file_mode(path)

            if mode is None:
                continue

            has_suid = bool(mode & stat.S_ISUID)
            has_sgid = bool(mode & stat.S_ISGID)

            is_writable = (
                bool(mode & stat.S_IWOTH) or
                bool(mode & stat.S_IWGRP)
            )

            if (has_suid or has_sgid) and is_writable:

                privilege_type = []

                if has_suid:
                    privilege_type.append("SUID")

                if has_sgid:
                    privilege_type.append("SGID")

                privilege_name = "/".join(privilege_type)

                findings.append({
                    "type": "Writable Privileged File",
                    "path": path,
                    "permissions": stat.filemode(mode),
                    "severity": "HIGH",
                    "finding":
                        f"{privilege_name} file is writable by a "
                        "user or group",
                    "recommendation":
                        "Review ownership and remove unnecessary "
                        "write permissions from privileged files."
                })

    return findings


def scan_home_directories():
    """
    Check user home directories for world-writable permissions.
    """

    findings = []

    home_directory = "/home"

    if not is_directory(home_directory):
        return findings

    try:
        users = os.listdir(home_directory)
    except PermissionError:
        return findings

    for username in users:

        path = os.path.join(home_directory, username)

        if not is_directory(path):
            continue

        if is_world_writable(path):

            findings.append({
                "type": "Home Directory Permission",
                "path": path,
                "permissions": get_permissions(path),
                "severity": "HIGH",
                "finding":
                    "Home directory is world-writable",
                "recommendation":
                    "Restrict write permissions on the home directory."
            })

    return findings


def run_permission_scan():
    """Run all permission checks."""

    findings = []

    findings.extend(check_sensitive_files())
    findings.extend(scan_world_writable_files())
    findings.extend(scan_privileged_writable_files())
    findings.extend(scan_home_directories())

    return findings


def print_finding(finding):
    """Print a finding with severity-based highlighting."""

    print("-" * 60)

    print("Type:", finding["type"])
    print("Path:", finding["path"])
    print("Permissions:", finding["permissions"])

    severity = finding["severity"]

    if severity == "HIGH":

        print(f"{RED}Severity: {severity}{RESET}")
        print(
            f"{RED}Finding: "
            f"{finding['finding']}{RESET}"
        )

    elif severity == "MEDIUM":

        print(f"{YELLOW}Severity: {severity}{RESET}")
        print("Finding:", finding["finding"])

    else:

        print(f"{GREEN}Severity: {severity}{RESET}")
        print("Finding:", finding["finding"])

    print("Recommendation:", finding["recommendation"])


def main():

    print("=" * 60)
    print("WEAK FILE & DIRECTORY PERMISSIONS SCANNER")
    print("=" * 60)

    findings = run_permission_scan()

    if not findings:

        print(
            f"\n{GREEN}"
            "No obvious weak permission conditions detected."
            f"{RESET}"
        )

        print("\nScan completed successfully.")
        return

    print(f"\nFindings detected: {len(findings)}")

    high_count = 0
    medium_count = 0
    low_count = 0

    for finding in findings:

        severity = finding["severity"]

        if severity == "HIGH":
            high_count += 1

        elif severity == "MEDIUM":
            medium_count += 1

        else:
            low_count += 1

        print_finding(finding)

    print("\n" + "=" * 60)
    print("PERMISSION SCAN SUMMARY")
    print("=" * 60)

    print("Total Findings:", len(findings))

    print(
        f"{RED}HIGH Risk Findings: "
        f"{high_count}{RESET}"
    )

    print(
        f"{YELLOW}MEDIUM Risk Findings: "
        f"{medium_count}{RESET}"
    )

    print(
        f"{GREEN}LOW Risk Findings: "
        f"{low_count}{RESET}"
    )

    if high_count > 0:

        print(
            f"{RED}"
            "Overall Status: HIGH RISK FINDING DETECTED"
            f"{RESET}"
        )

    elif medium_count > 0:

        print(
            f"{YELLOW}"
            "Overall Status: MEDIUM RISK FINDING DETECTED"
            f"{RESET}"
        )

    else:

        print(
            f"{GREEN}"
            "Overall Status: NO HIGH-RISK FINDINGS"
            f"{RESET}"
        )

    print("=" * 60)


if __name__ == "__main__":
    main()
