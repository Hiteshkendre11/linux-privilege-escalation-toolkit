import os
import re
import stat
import subprocess


# Terminal colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


def run_command(command):
    """Run a system command and return its output."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15
        )

        return result.stdout + result.stderr

    except subprocess.TimeoutExpired:
        return "ERROR: Command timed out."

    except FileNotFoundError:
        return f"ERROR: Command not found: {command[0]}"

    except Exception as error:
        return f"ERROR: {error}"


def get_service_names():
    """Return all systemd service names."""

    output = run_command([
        "systemctl",
        "list-units",
        "--type=service",
        "--all",
        "--no-pager",
        "--no-legend"
    ])

    if output.startswith("ERROR:"):
        return [], output

    services = []

    for line in output.splitlines():

        parts = line.split()

        if not parts:
            continue

        service = parts[0]

        if service.endswith(".service"):
            services.append(service)

    return list(dict.fromkeys(services)), output


def get_service_details(service):
    """Retrieve important properties of a systemd service."""

    return run_command([
        "systemctl",
        "show",
        service,
        "--no-pager",
        "--property=User,Group,ExecStart,FragmentPath,Environment"
    ])


def parse_property(output, property_name):
    """Extract a systemd property."""

    for line in output.splitlines():

        if line.startswith(property_name + "="):
            return line.split("=", 1)[1].strip()

    return ""


def parse_execstart(exec_start):
    """
    Extract the actual executable path from systemd ExecStart output.

    Example:
    { path=/usr/bin/foo ; argv[]=/usr/bin/foo --option ; ... }

    Returns:
        /usr/bin/foo
    """

    if not exec_start:
        return ""

    # Systemd structured format
    path_match = re.search(
        r"path=([^ ;}]+)",
        exec_start
    )

    if path_match:
        return path_match.group(1)

    # Fallback for simpler ExecStart representations
    if exec_start.startswith("/"):
        return exec_start.split()[0]

    return ""


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


def is_world_writable(path):
    """Check whether path is world-writable."""

    try:
        return bool(os.stat(path).st_mode & stat.S_IWOTH)

    except (PermissionError, FileNotFoundError, OSError):
        return False


def is_group_writable(path):
    """Check whether path is group-writable."""

    try:
        return bool(os.stat(path).st_mode & stat.S_IWGRP)

    except (PermissionError, FileNotFoundError, OSError):
        return False


def is_root_service(user):
    """
    Determine whether a service runs as root.

    An empty User property means systemd's default user,
    which is normally root for system services.
    """

    return user == "" or user == "root"


def check_service_file(
    service,
    fragment_path
):
    """Check permissions on the systemd service unit file."""

    findings = []

    if not fragment_path:
        return findings

    if not os.path.isfile(fragment_path):
        return findings

    permissions = get_permissions(fragment_path)

    if is_world_writable(fragment_path):

        findings.append({
            "type": "World-Writable Root Service File",
            "service": service,
            "path": fragment_path,
            "permissions": permissions,
            "severity": "HIGH",
            "finding":
                "A root-level systemd service file is "
                "world-writable.",
            "recommendation":
                "Restrict write permissions on the service "
                "unit file to trusted administrators."
        })

    elif is_group_writable(fragment_path):

        findings.append({
            "type": "Group-Writable Root Service File",
            "service": service,
            "path": fragment_path,
            "permissions": permissions,
            "severity": "MEDIUM",
            "finding":
                "A root-level systemd service file is "
                "group-writable.",
            "recommendation":
                "Review group ownership and restrict unnecessary "
                "write permissions."
        })

    return findings


def check_service_executable(
    service,
    executable
):
    """Check permissions on a service executable."""

    findings = []

    if not executable:
        return findings

    if not os.path.exists(executable):
        return findings

    if not is_regular_file(executable):
        return findings

    permissions = get_permissions(executable)

    if is_world_writable(executable):

        findings.append({
            "type": "World-Writable Root Service Executable",
            "service": service,
            "path": executable,
            "permissions": permissions,
            "severity": "HIGH",
            "finding":
                "A root-level service references a "
                "world-writable executable.",
            "recommendation":
                "Restrict write permissions on the executable "
                "and ensure it is owned by a trusted account."
        })

    elif is_group_writable(executable):

        findings.append({
            "type": "Group-Writable Root Service Executable",
            "service": service,
            "path": executable,
            "permissions": permissions,
            "severity": "MEDIUM",
            "finding":
                "A root-level service references a "
                "group-writable executable.",
            "recommendation":
                "Review group ownership and restrict unnecessary "
                "write permissions."
        })

    return findings


def check_service_path(
    service,
    environment
):
    """
    Check the PATH environment configured for a root service.

    Relative or empty PATH components can be risky because
    command resolution may occur from an unintended location.
    """

    findings = []

    if not environment:
        return findings

    path_match = re.search(
        r"(?:^| )PATH=([^ ]+)",
        environment
    )

    if not path_match:
        return findings

    service_path = path_match.group(1)

    path_entries = service_path.split(":")

    insecure_entries = []

    for entry in path_entries:

        if entry == "":
            insecure_entries.append("<empty>")

        elif entry == ".":
            insecure_entries.append(".")

        elif not os.path.isabs(entry):
            insecure_entries.append(entry)

    if insecure_entries:

        findings.append({
            "type": "Potentially Unsafe Service PATH",
            "service": service,
            "path": service_path,
            "permissions": "N/A",
            "severity": "HIGH",
            "finding":
                "Root-level service PATH contains a relative "
                "or empty directory entry.",
            "recommendation":
                "Use trusted absolute directories in the service "
                "PATH environment."
        })

    return findings


def analyze_service(service):
    """Analyze one systemd service."""

    findings = []

    details = get_service_details(service)

    if details.startswith("ERROR:"):
        return findings

    user = parse_property(details, "User")
    exec_start = parse_property(details, "ExecStart")
    fragment_path = parse_property(details, "FragmentPath")
    environment = parse_property(details, "Environment")

    # Only analyze services that run as root.
    if not is_root_service(user):
        return findings

    # Check the service unit file.
    findings.extend(
        check_service_file(
            service,
            fragment_path
        )
    )

    # Extract and check the actual executable.
    executable = parse_execstart(exec_start)

    findings.extend(
        check_service_executable(
            service,
            executable
        )
    )

    # Check service PATH configuration.
    findings.extend(
        check_service_path(
            service,
            environment
        )
    )

    return findings


def run_service_scan():
    """Run the complete systemd service scan."""

    services, output = get_service_names()

    if output.startswith("ERROR:"):
        return [], 0, output

    findings = []

    for service in services:

        service_findings = analyze_service(service)

        findings.extend(service_findings)

    return findings, len(services), output


def print_finding(finding):
    """Display a finding using severity-based colors."""

    print("-" * 60)

    print("Type:", finding["type"])
    print("Service:", finding["service"])
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

    print(
        "Recommendation:",
        finding["recommendation"]
    )


def main():

    print("=" * 60)
    print("SYSTEMD SERVICE MISCONFIGURATION SCANNER")
    print("=" * 60)

    findings, service_count, output = run_service_scan()

    if output.startswith("ERROR:"):

        print(f"\n{RED}{output}{RESET}")
        return

    print(
        f"\nSystemd Services Analyzed: "
        f"{service_count}"
    )

    if not findings:

        print(
            f"\n{GREEN}"
            "No obvious risky systemd service configuration detected."
            f"{RESET}"
        )

        print("\nScan completed successfully.")
        return

    print(
        f"\nFindings detected: "
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
    print("SERVICE SCAN SUMMARY")
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
