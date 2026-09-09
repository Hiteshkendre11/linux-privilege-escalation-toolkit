import os
import re
import stat
import subprocess


# Terminal colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


CRON_LOCATIONS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly"
]


def get_permissions(path):
    """Return Linux permission string."""
    try:
        return stat.filemode(os.stat(path).st_mode)
    except (PermissionError, FileNotFoundError, OSError):
        return "UNKNOWN"


def is_world_writable(path):
    """Check whether a path is world-writable."""
    try:
        return bool(os.stat(path).st_mode & stat.S_IWOTH)
    except (PermissionError, FileNotFoundError, OSError):
        return False


def is_group_writable(path):
    """Check whether a path is group-writable."""
    try:
        return bool(os.stat(path).st_mode & stat.S_IWGRP)
    except (PermissionError, FileNotFoundError, OSError):
        return False


def is_regular_file(path):
    """Check whether a path is a regular file."""
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (PermissionError, FileNotFoundError, OSError):
        return False


def get_crontab_output():
    """Retrieve the current user's crontab."""
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
            timeout=10
        )

        return result.stdout

    except FileNotFoundError:
        return ""

    except subprocess.TimeoutExpired:
        return ""


def scan_cron_locations():
    """
    Scan standard system cron locations.
    """

    findings = []

    for location in CRON_LOCATIONS:

        if not os.path.exists(location):
            continue

        if os.path.isfile(location):

            if is_world_writable(location):

                findings.append({
                    "type": "World-Writable Cron Configuration",
                    "path": location,
                    "permissions": get_permissions(location),
                    "severity": "HIGH",
                    "finding":
                        "Cron configuration file is world-writable.",
                    "recommendation":
                        "Remove unnecessary write permissions and "
                        "restrict ownership to trusted administrators."
                })

            elif is_group_writable(location):

                findings.append({
                    "type": "Group-Writable Cron Configuration",
                    "path": location,
                    "permissions": get_permissions(location),
                    "severity": "MEDIUM",
                    "finding":
                        "Cron configuration file is group-writable.",
                    "recommendation":
                        "Review the owning group and remove unnecessary "
                        "write permissions."
                })

        elif os.path.isdir(location):

            try:
                entries = os.listdir(location)
            except PermissionError:
                continue

            for entry in entries:

                path = os.path.join(location, entry)

                if not is_regular_file(path):
                    continue

                if is_world_writable(path):

                    findings.append({
                        "type": "World-Writable Cron Script",
                        "path": path,
                        "permissions": get_permissions(path),
                        "severity": "HIGH",
                        "finding":
                            "Cron script is writable by any local user.",
                        "recommendation":
                            "Restrict write permissions and ensure the "
                            "script is owned by a trusted administrator."
                    })

                elif is_group_writable(path):

                    findings.append({
                        "type": "Group-Writable Cron Script",
                        "path": path,
                        "permissions": get_permissions(path),
                        "severity": "MEDIUM",
                        "finding":
                            "Cron script is writable by its group.",
                        "recommendation":
                            "Review group membership and restrict write "
                            "permissions where unnecessary."
                    })

    return findings


def extract_script_paths(cron_content):
    """
    Extract likely executable/script paths from cron entries.

    This is an enumeration aid only. It does not execute commands.
    """

    paths = []

    for line in cron_content.splitlines():

        line = line.strip()

        if not line or line.startswith("#"):
            continue

        # Remove common environment variable declarations.
        if "=" in line and not line.startswith("@"):
            first_part = line.split()[0]

            if "=" in first_part:
                continue

        # Look for absolute paths in the cron command.
        matches = re.findall(
            r"(\/[A-Za-z0-9_./+-]+)",
            line
        )

        for match in matches:

            # Remove trailing punctuation.
            path = match.rstrip(";,|")

            if os.path.exists(path):
                paths.append(path)

    return list(dict.fromkeys(paths))


def scan_referenced_cron_files():
    """
    Analyze files referenced by the current user's crontab.
    """

    findings = []

    cron_content = get_crontab_output()

    if not cron_content:
        return findings

    script_paths = extract_script_paths(cron_content)

    for path in script_paths:

        if not is_regular_file(path):
            continue

        if is_world_writable(path):

            findings.append({
                "type": "Writable Cron-Referenced File",
                "path": path,
                "permissions": get_permissions(path),
                "severity": "HIGH",
                "finding":
                    "A file referenced by a cron entry is "
                    "world-writable.",
                "recommendation":
                    "Restrict write permissions and verify that "
                    "only trusted users can modify the file."
            })

        elif is_group_writable(path):

            findings.append({
                "type": "Group-Writable Cron-Referenced File",
                "path": path,
                "permissions": get_permissions(path),
                "severity": "MEDIUM",
                "finding":
                    "A file referenced by a cron entry is "
                    "group-writable.",
                "recommendation":
                    "Review the owning group and restrict write "
                    "permissions where appropriate."
            })

    return findings


def enumerate_system_cron():
    """
    Collect system cron configuration for reporting.
    """

    cron_entries = []

    for location in CRON_LOCATIONS:

        if not os.path.exists(location):
            continue

        if os.path.isfile(location):

            try:
                with open(
                    location,
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as file:

                    content = file.read()

                cron_entries.append({
                    "path": location,
                    "content": content
                })

            except (PermissionError, OSError):
                continue

        elif os.path.isdir(location):

            try:
                entries = os.listdir(location)
            except PermissionError:
                continue

            for entry in entries:

                path = os.path.join(location, entry)

                if not is_regular_file(path):
                    continue

                try:
                    with open(
                        path,
                        "r",
                        encoding="utf-8",
                        errors="ignore"
                    ) as file:

                        content = file.read()

                    cron_entries.append({
                        "path": path,
                        "content": content
                    })

                except (PermissionError, OSError):
                    continue

    return cron_entries


def run_cron_scan():
    """Run all cron security checks."""

    findings = []

    findings.extend(scan_cron_locations())
    findings.extend(scan_referenced_cron_files())

    return findings


def print_finding(finding):
    """Print a finding using severity-based colors."""

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
    print("CRON JOB VULNERABILITY SCANNER")
    print("=" * 60)

    findings = run_cron_scan()

    # Display current user's crontab status.
    user_crontab = get_crontab_output()

    print("\nCurrent User Cron Status:")

    if user_crontab:
        print("User crontab entries detected.")
    else:
        print("No user crontab entries detected.")

    # Enumerate system cron locations.
    system_cron = enumerate_system_cron()

    print(
        f"\nSystem Cron Configuration Files Found: "
        f"{len(system_cron)}"
    )

    if not findings:

        print(
            f"\n{GREEN}"
            "No obvious writable cron vulnerability detected."
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
    print("CRON SCAN SUMMARY")
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
