import os
import subprocess
import stat


HIGH_RISK_BINARIES = {
    "find",
    "vim",
    "nmap",
    "perl",
    "python",
    "awk",
    "bash",
    "env",
    "less",
    "more"
}


RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def scan_files(permission):
    """
    Scan the filesystem for files with the specified
    SUID or SGID permission bit.
    """

    try:

        result = subprocess.run(
            [
                "find",
                "/",
                "-perm",
                f"-{permission}",
                "-type",
                "f"
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        return result.stdout.splitlines()

    except subprocess.TimeoutExpired:

        return []

    except Exception:

        return []


def get_file_information(path):
    """
    Safely retrieve file permission and ownership information.
    """

    try:

        file_stat = os.stat(path)

        permissions = stat.filemode(
            file_stat.st_mode
        )

        owner_id = file_stat.st_uid
        group_id = file_stat.st_gid

        try:

            import pwd
            owner = pwd.getpwuid(
                owner_id
            ).pw_name

        except Exception:

            owner = str(owner_id)

        try:

            import grp
            group = grp.getgrgid(
                group_id
            ).gr_name

        except Exception:

            group = str(group_id)

        return (
            permissions,
            owner,
            group,
            file_stat.st_mode
        )

    except (
        PermissionError,
        FileNotFoundError,
        OSError
    ):

        return (
            "UNKNOWN",
            "UNKNOWN",
            "UNKNOWN",
            0
        )


def analyze_file(path, permission_type):
    """
    Analyze a single SUID or SGID file.

    Returns a structured finding dictionary so that
    analyzer.py and main.py can process the result.
    """

    permissions, owner, group, mode = (
        get_file_information(path)
    )

    binary_name = os.path.basename(path)

    is_world_writable = bool(
        mode & stat.S_IWOTH
    )

    is_group_writable = bool(
        mode & stat.S_IWGRP
    )

    is_high_risk_binary = (
        binary_name.lower()
        in HIGH_RISK_BINARIES
    )

    # ---------------------------------------------------------
    # Severity determination
    # ---------------------------------------------------------

    if is_world_writable:

        severity = "HIGH"

        finding = (
            "Privileged file is world-writable"
        )

        recommendation = (
            "Remove unnecessary world-write permission "
            "from the privileged file and review its "
            "SUID/SGID configuration."
        )

    elif is_group_writable:

        severity = "HIGH"

        finding = (
            "Privileged file is group-writable"
        )

        recommendation = (
            "Review group ownership and remove unnecessary "
            "group-write permission from the privileged file."
        )

    elif is_high_risk_binary:

        severity = "HIGH"

        finding = (
            "Binary matches a known privilege-escalation "
            "pattern"
        )

        recommendation = (
            "Review the binary against approved security "
            "references and remove unnecessary SUID/SGID "
            "permissions."
        )

    else:

        severity = "LOW"

        finding = (
            "No obvious high-risk condition detected"
        )

        recommendation = (
            "No immediate action required; continue "
            "monitoring privileged binaries and review "
            "whether the SUID/SGID permission is required."
        )

    # ---------------------------------------------------------
    # Display finding
    # ---------------------------------------------------------

    print(
        "------------------------------------------------"
    )

    print(
        "Type:",
        permission_type
    )

    print(
        "Permissions:",
        permissions
    )

    print(
        "Owner:",
        owner
    )

    print(
        "Group:",
        group
    )

    print(
        "Binary:",
        binary_name
    )

    print(
        "Path:",
        path
    )

    print(
        "World-Writable:",
        is_world_writable
    )

    print(
        "Group-Writable:",
        is_group_writable
    )

    if severity == "HIGH":

        print(
            f"{RED}Severity: "
            f"{severity}{RESET}"
        )

        print(
            f"{RED}Finding: "
            f"{finding}{RESET}"
        )

    elif severity == "MEDIUM":

        print(
            f"{YELLOW}Severity: "
            f"{severity}{RESET}"
        )

        print(
            "Finding:",
            finding
        )

    else:

        print(
            f"{GREEN}Severity: "
            f"{severity}{RESET}"
        )

        print(
            "Finding:",
            finding
        )

    print(
        "Recommendation:",
        recommendation
    )

    # ---------------------------------------------------------
    # Structured result
    # ---------------------------------------------------------

    return {
        "type": permission_type,
        "permissions": permissions,
        "owner": owner,
        "group": group,
        "binary": binary_name,
        "path": path,
        "world_writable": is_world_writable,
        "group_writable": is_group_writable,
        "severity": severity,
        "finding": finding,
        "recommendation": recommendation
    }


def run_suid_scan():
    """
    Run both SUID and SGID scans.

    Returns a structured list of findings.
    """

    findings = []

    # ---------------------------------------------------------
    # SUID
    # ---------------------------------------------------------

    suid_files = scan_files(
        4000
    )

    print(
        "SUID Files:"
    )

    for file in suid_files:

        finding = analyze_file(
            file,
            "SUID"
        )

        findings.append(
            finding
        )

    # ---------------------------------------------------------
    # SGID
    # ---------------------------------------------------------

    print(
        "\n--------------------------------------------"
    )

    sgid_files = scan_files(
        2000
    )

    print(
        "SGID Files:"
    )

    for file in sgid_files:

        finding = analyze_file(
            file,
            "SGID"
        )

        findings.append(
            finding
        )

    return (
        findings,
        suid_files,
        sgid_files
    )


def main():

    print(
        "=" * 60
    )

    print(
        "SUID / SGID SECURITY SCANNER"
    )

    print(
        "=" * 60
    )

    findings, suid_files, sgid_files = (
        run_suid_scan()
    )

    high_count = 0
    medium_count = 0
    low_count = 0

    for finding in findings:

        severity = finding[
            "severity"
        ]

        if severity == "HIGH":

            high_count += 1

        elif severity == "MEDIUM":

            medium_count += 1

        else:

            low_count += 1

    print(
        "\n============================================"
    )

    print(
        "SCAN SUMMARY"
    )

    print(
        "============================================"
    )

    print(
        "SUID Files Found:",
        len(suid_files)
    )

    print(
        "SGID Files Found:",
        len(sgid_files)
    )

    print(
        "HIGH Risk Findings:",
        high_count
    )

    print(
        "MEDIUM Risk Findings:",
        medium_count
    )

    print(
        "LOW Risk Findings:",
        low_count
    )

    if high_count > 0:

        print(
            f"{RED}"
            "Overall Status: "
            "HIGH RISK FINDING DETECTED"
            f"{RESET}"
        )

    elif medium_count > 0:

        print(
            f"{YELLOW}"
            "Overall Status: "
            "MEDIUM RISK FINDING DETECTED"
            f"{RESET}"
        )

    else:

        print(
            f"{GREEN}"
            "Overall Status: "
            "NO HIGH RISK FINDINGS DETECTED"
            f"{RESET}"
        )

    print(
        "============================================"
    )


if __name__ == "__main__":
    main()
