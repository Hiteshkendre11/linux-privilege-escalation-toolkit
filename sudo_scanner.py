import subprocess


# Terminal colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def get_sudo_permissions():
    """
    Retrieve the current user's sudo privileges.

    sudo is executed with the normal terminal attached so that
    the user can manually enter their password when required.
    """

    try:
        result = subprocess.run(
            ["sudo", "-l"],
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30
        )

        return result.stdout

    except subprocess.TimeoutExpired:
        return "ERROR: sudo command timed out."

    except FileNotFoundError:
        return "ERROR: sudo command not found."

    except Exception as error:
        return f"ERROR: {error}"


def analyze_sudo_output(output):
    """
    Analyze sudo -l output for potentially risky configurations.
    """

    findings = []

    for line in output.splitlines():

        rule = line.strip()

        if not rule:
            continue

        upper_rule = rule.upper()

        # Passwordless broad sudo access
        if "NOPASSWD:" in upper_rule and "ALL" in upper_rule:

            findings.append({
                "type": "Sudo NOPASSWD Rule",
                "rule": rule,
                "severity": "HIGH",
                "finding":
                    "Sudo rule provides passwordless access to "
                    "broadly permitted commands.",
                "recommendation":
                    "Remove unnecessary NOPASSWD access and restrict "
                    "sudo permissions to required commands only."
            })

        # Passwordless access to a specific command
        elif "NOPASSWD:" in upper_rule:

            findings.append({
                "type": "Sudo NOPASSWD Rule",
                "rule": rule,
                "severity": "MEDIUM",
                "finding":
                    "Sudo rule allows a command to run without "
                    "password authentication.",
                "recommendation":
                    "Review whether passwordless execution is required "
                    "and restrict the permitted command."
            })

        # Broad authenticated sudo access
        elif "(ALL : ALL) ALL" in upper_rule:

            findings.append({
                "type": "Broad Sudo Permission",
                "rule": rule,
                "severity": "MEDIUM",
                "finding":
                    "User has broad sudo privileges requiring "
                    "authentication.",
                "recommendation":
                    "Apply the principle of least privilege and restrict "
                    "sudo access to only required commands."
            })

        # Alternative common sudo format
        elif "(ALL) ALL" in upper_rule:

            findings.append({
                "type": "Broad Sudo Permission",
                "rule": rule,
                "severity": "MEDIUM",
                "finding":
                    "User has broad sudo privileges requiring "
                    "authentication.",
                "recommendation":
                    "Apply the principle of least privilege and restrict "
                    "sudo access to only required commands."
            })

    return findings


def print_finding(finding):
    """
    Display a finding using severity-based terminal colors.
    """

    print("-" * 60)

    print("Type:", finding["type"])
    print("Rule:", finding["rule"])

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


def run_sudo_scan():
    """
    Run sudo enumeration and analyze the result.

    Returns:
        findings, raw_output
    """

    output = get_sudo_permissions()

    if output.startswith("ERROR:"):
        return [], output

    findings = analyze_sudo_output(output)

    return findings, output


def main():

    print("=" * 60)
    print("SUDO MISCONFIGURATION SCANNER")
    print("=" * 60)

    findings, output = run_sudo_scan()

    if output.startswith("ERROR:"):

        print(
            f"\n{RED}"
            f"{output}"
            f"{RESET}"
        )

        return

    if not findings:

        print(
            f"\n{GREEN}"
            "No obvious risky sudo configuration detected."
            f"{RESET}"
        )

        print(
            "\nScan completed successfully."
        )

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

    print(
        "\n" + "=" * 60
    )

    print(
        "SUDO SCAN SUMMARY"
    )

    print(
        "=" * 60
    )

    print(
        "Total Findings:",
        len(findings)
    )

    print(
        f"{RED}"
        f"HIGH Risk Findings: "
        f"{high_count}"
        f"{RESET}"
    )

    print(
        f"{YELLOW}"
        f"MEDIUM Risk Findings: "
        f"{medium_count}"
        f"{RESET}"
    )

    print(
        f"{GREEN}"
        f"LOW Risk Findings: "
        f"{low_count}"
        f"{RESET}"
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

    print(
        "=" * 60
    )


if __name__ == "__main__":
    main()
