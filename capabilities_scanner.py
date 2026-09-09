import os
import re
import stat
import subprocess


# Terminal colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


# Capabilities that can be particularly security-sensitive
HIGH_RISK_CAPABILITIES = {
    "cap_setuid",
    "cap_setgid",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_sys_admin",
    "cap_sys_ptrace",
    "cap_sys_module",
    "cap_chown",
}


def run_getcap():
    """
    Run getcap against the filesystem.

    Detection only: the command reads capability metadata and
    does not modify or execute the discovered files.
    """

    try:
        result = subprocess.run(
            ["getcap", "-r", "/", "-n"],
            capture_output=True,
            text=True,
            timeout=60
        )

        return result.stdout

    except subprocess.TimeoutExpired:
        return "ERROR: getcap scan timed out."

    except FileNotFoundError:
        return "ERROR: getcap command not found."

    except Exception as error:
        return f"ERROR: {error}"


def parse_capability_line(line):
    """
    Parse a getcap output line.

    Example:
        /usr/bin/example cap_setuid=ep

    Returns:
        (path, capability_string)
    """

    line = line.strip()

    if not line:
        return None, None

    parts = line.split(None, 1)

    if len(parts) != 2:
        return None, None

    return parts[0], parts[1]


def extract_capability_names(capability_string):
    """
    Extract capability names from a getcap capability string.
    """

    capabilities = []

    matches = re.findall(
        r"(cap_[a-z0-9_]+)",
        capability_string.lower()
    )

    for capability in matches:

        if capability not in capabilities:
            capabilities.append(capability)

    return capabilities


def get_permissions(path):
    """Return Linux permission string."""

    try:
        return stat.filemode(os.stat(path).st_mode)

    except (PermissionError, FileNotFoundError, OSError):
        return "UNKNOWN"


def is_regular_file(path):
    """Check whether path is a regular file."""

    try:
        return stat.S_ISREG(os.stat(path).st_mode)

    except (PermissionError, FileNotFoundError, OSError):
        return False


def analyze_capability(path, capability_string):
    """
    Analyze a single file capability configuration.
    """

    findings = []

    capabilities = extract_capability_names(
        capability_string
    )

    if not capabilities:
        return findings

    high_risk = [
        capability
        for capability in capabilities
        if capability in HIGH_RISK_CAPABILITIES
    ]

    # A high-risk capability assigned to a regular executable
    # should be reviewed.
    if high_risk:

        findings.append({
            "type": "High-Risk Linux Capability",
            "path": path,
            "permissions": get_permissions(path),
            "capabilities": capability_string,
            "severity": "HIGH",
            "finding":
                "File has security-sensitive Linux capabilities: "
                + ", ".join(high_risk),
            "recommendation":
                "Review whether these capabilities are required. "
                "Remove unnecessary capabilities and restrict "
                "access to the file."
        })

    else:

        findings.append({
            "type": "Linux File Capability",
            "path": path,
            "permissions": get_permissions(path),
            "capabilities": capability_string,
            "severity": "LOW",
            "finding":
                "File has Linux capabilities assigned.",
            "recommendation":
                "Verify that the capabilities are required and "
                "follow the principle of least privilege."
        })

    return findings


def run_capability_scan():
    """
    Execute getcap and analyze discovered capabilities.
    """

    output = run_getcap()

    if output.startswith("ERROR:"):
        return [], output

    findings = []

    for line in output.splitlines():

        path, capability_string = parse_capability_line(line)

        if not path or not capability_string:
            continue

        # Ignore entries that are not regular files.
        if not is_regular_file(path):
            continue

        findings.extend(
            analyze_capability(
                path,
                capability_string
            )
        )

    return findings, output


def print_finding(finding):
    """Print capability finding with severity highlighting."""

    print("-" * 60)

    print("Type:", finding["type"])
    print("Path:", finding["path"])
    print("Permissions:", finding["permissions"])
    print("Capabilities:", finding["capabilities"])

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

    print(
        "Recommendation:",
        finding["recommendation"]
    )


def main():

    print("=" * 60)
    print("LINUX CAPABILITIES SCANNER")
    print("=" * 60)

    findings, output = run_capability_scan()

    if output.startswith("ERROR:"):

        print(f"\n{RED}{output}{RESET}")
        return

    if not findings:

        print(
            f"\n{GREEN}"
            "No Linux file capabilities detected."
            f"{RESET}"
        )

        print("\nScan completed successfully.")
        return

    print(
        f"\nCapability Findings Detected: "
        f"{len(findings)}"
    )

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
    print("CAPABILITIES SCAN SUMMARY")
    print("=" * 60)

    print(
        "Total Findings:",
        len(findings)
    )

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
