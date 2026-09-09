"""
Main controller for the Linux Privilege Escalation Automation Toolkit.

This program:
1. Collects system information.
2. Runs all security scanner modules.
3. Collects structured findings.
4. Analyzes and consolidates findings.
5. Generates a structured security report.

Detection and reporting only.
No exploitation is performed.
"""

import os
import platform
import time

import system_info
import suid_scanner
import permissions_scanner
import sudo_scanner
import cron_scanner
import service_scanner
import capabilities_scanner
import kernel_scanner

import analyzer
import report_generator


# Terminal colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"


def collect_system_information():
    """Collect basic system information."""

    information = {}

    information["Operating System"] = platform.system()
    information["Distribution"] = platform.platform()
    information["Kernel"] = platform.release()
    information["Architecture"] = platform.machine()

    try:
        information["Current User"] = os.getlogin()
    except OSError:
        information["Current User"] = os.environ.get(
            "USER",
            "Unknown"
        )

    return information


def run_suid_scanner():
    """Run the SUID/SGID scanner and return structured findings."""

    try:

        findings, suid_files, sgid_files = (
            suid_scanner.run_suid_scan()
        )

        return findings

    except Exception as error:

        print(
            f"{YELLOW}"
            f"SUID/SGID scanner warning: {error}"
            f"{RESET}"
        )

        return []


def run_permissions_scanner():
    """Run the permissions scanner."""

    try:

        if hasattr(
            permissions_scanner,
            "run_permission_scan"
        ):

            result = (
                permissions_scanner.run_permission_scan()
            )

            if isinstance(result, tuple):
                return result[0]

            if isinstance(result, list):
                return result

        elif hasattr(
            permissions_scanner,
            "run_scan"
        ):

            result = permissions_scanner.run_scan()

            if isinstance(result, list):
                return result

        print(
            f"{YELLOW}"
            "Permissions scanner returned no structured findings."
            f"{RESET}"
        )

    except Exception as error:

        print(
            f"{YELLOW}"
            f"Permissions scanner warning: {error}"
            f"{RESET}"
        )

    return []


def run_sudo_scanner():
    """Run the sudo scanner."""

    try:

        findings, output = (
            sudo_scanner.run_sudo_scan()
        )

        return findings

    except Exception as error:

        print(
            f"{YELLOW}"
            f"Sudo scanner warning: {error}"
            f"{RESET}"
        )

        return []


def run_cron_scanner():
    """Run the cron scanner."""

    try:

        if hasattr(
            cron_scanner,
            "run_cron_scan"
        ):

            result = cron_scanner.run_cron_scan()

            if isinstance(result, tuple):
                return result[0]

            if isinstance(result, list):
                return result

        print(
            f"{YELLOW}"
            "Cron scanner returned no structured findings."
            f"{RESET}"
        )

    except Exception as error:

        print(
            f"{YELLOW}"
            f"Cron scanner warning: {error}"
            f"{RESET}"
        )

    return []


def run_service_scanner():
    """Run the systemd service scanner."""

    try:

        if hasattr(
            service_scanner,
            "run_service_scan"
        ):

            result = (
                service_scanner.run_service_scan()
            )

            if isinstance(result, tuple):
                return result[0]

            if isinstance(result, list):
                return result

        print(
            f"{YELLOW}"
            "Service scanner returned no structured findings."
            f"{RESET}"
        )

    except Exception as error:

        print(
            f"{YELLOW}"
            f"Service scanner warning: {error}"
            f"{RESET}"
        )

    return []


def run_capabilities_scanner():
    """Run the Linux capabilities scanner."""

    try:

        result = (
            capabilities_scanner.run_capability_scan()
        )

        if isinstance(result, tuple):
            return result[0]

        if isinstance(result, list):
            return result

    except Exception as error:

        print(
            f"{YELLOW}"
            f"Capabilities scanner warning: {error}"
            f"{RESET}"
        )

    return []


def run_kernel_scanner():
    """
    Run the kernel scanner and convert its assessments
    into analyzer-compatible findings.
    """

    findings = []

    try:

        result = (
            kernel_scanner.run_kernel_scan()
        )

        if not isinstance(result, dict):
            return findings

        kernel_data = result.get(
            "kernel",
            {}
        )

        kernel_release = kernel_data.get(
            "kernel_release",
            "Unknown"
        )

        age_assessment = result.get(
            "age_assessment"
        )

        cve_assessment = result.get(
            "cve_assessment"
        )

        if age_assessment:

            findings.append({
                "type": "Kernel Age Assessment",
                "path": kernel_release,
                "severity": age_assessment.get(
                    "severity",
                    "LOW"
                ),
                "finding": age_assessment.get(
                    "finding",
                    "N/A"
                ),
                "recommendation": age_assessment.get(
                    "recommendation",
                    "N/A"
                )
            })

        if cve_assessment:

            findings.append({
                "type": "Kernel CVE Assessment",
                "path": kernel_release,
                "severity": cve_assessment.get(
                    "severity",
                    "LOW"
                ),
                "finding": cve_assessment.get(
                    "finding",
                    "N/A"
                ),
                "recommendation": cve_assessment.get(
                    "recommendation",
                    "N/A"
                )
            })

    except Exception as error:

        print(
            f"{YELLOW}"
            f"Kernel scanner warning: {error}"
            f"{RESET}"
        )

    return findings


def display_findings(analysis):
    """Display consolidated findings."""

    findings = analysis.get(
        "findings",
        []
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "CONSOLIDATED SECURITY FINDINGS"
    )

    print(
        "=" * 70
    )

    if not findings:

        print(
            f"\n{GREEN}"
            "No security findings detected."
            f"{RESET}"
        )

        return

    for number, finding in enumerate(
        findings,
        start=1
    ):

        print(
            "\n" + "-" * 70
        )

        print(
            f"FINDING #{number}"
        )

        print(
            "Scanner:",
            finding.get(
                "scanner",
                "Unknown"
            )
        )

        print(
            "Type:",
            finding.get(
                "type",
                "Unknown"
            )
        )

        severity = finding.get(
            "severity",
            "LOW"
        )

        if severity == "HIGH":

            print(
                f"{RED}"
                f"Severity: {severity}"
                f"{RESET}"
            )

        elif severity == "MEDIUM":

            print(
                f"{YELLOW}"
                f"Severity: {severity}"
                f"{RESET}"
            )

        else:

            print(
                f"{GREEN}"
                f"Severity: {severity}"
                f"{RESET}"
            )

        if "service" in finding:

            print(
                "Service:",
                finding["service"]
            )

        if "path" in finding:

            print(
                "Path:",
                finding["path"]
            )

        if "permissions" in finding:

            print(
                "Permissions:",
                finding["permissions"]
            )

        if "owner" in finding:

            print(
                "Owner:",
                finding["owner"]
            )

        if "group" in finding:

            print(
                "Group:",
                finding["group"]
            )

        if "binary" in finding:

            print(
                "Binary:",
                finding["binary"]
            )

        if "capabilities" in finding:

            print(
                "Capabilities:",
                finding["capabilities"]
            )

        if "rule" in finding:

            print(
                "Rule:",
                finding["rule"]
            )

        print(
            "Finding:",
            finding.get(
                "finding",
                "N/A"
            )
        )

        print(
            "Recommendation:",
            finding.get(
                "recommendation",
                "N/A"
            )
        )


def main():

    start_time = time.time()

    print(
        "=" * 70
    )

    print(
        "LINUX PRIVILEGE ESCALATION AUTOMATION TOOLKIT"
    )

    print(
        "=" * 70
    )

    print(
        "\nMode: Detection Only"
    )

    print(
        "Purpose: Authorized security auditing and "
        "laboratory assessment"
    )

    print(
        "=" * 70
    )

    # ---------------------------------------------------------
    # System Information
    # ---------------------------------------------------------

    print(
        f"\n{CYAN}"
        "[1/8] Collecting system information..."
        f"{RESET}"
    )

    system_information = (
        collect_system_information()
    )

    # ---------------------------------------------------------
    # SUID / SGID
    # ---------------------------------------------------------

    print(
        f"\n{CYAN}"
        "[2/8] Running SUID/SGID scanner..."
        f"{RESET}"
    )

    scanner_results = {}

    scanner_results[
        "SUID/SGID Scanner"
    ] = run_suid_scanner()

    # ---------------------------------------------------------
    # Permissions
    # ---------------------------------------------------------

    print(
        f"\n{CYAN}"
        "[3/8] Running permissions scanner..."
        f"{RESET}"
    )

    scanner_results[
        "Permissions Scanner"
    ] = run_permissions_scanner()

    # ---------------------------------------------------------
    # Sudo
    # ---------------------------------------------------------

    print(
        f"\n{CYAN}"
        "[4/8] Running sudo scanner..."
        f"{RESET}"
    )

    scanner_results[
        "Sudo Scanner"
    ] = run_sudo_scanner()

    # ---------------------------------------------------------
    # Cron
    # ---------------------------------------------------------

    print(
        f"\n{CYAN}"
        "[5/8] Running cron scanner..."
        f"{RESET}"
    )

    scanner_results[
        "Cron Scanner"
    ] = run_cron_scanner()

    # ---------------------------------------------------------
    # Services
    # ---------------------------------------------------------

    print(
        f"\n{CYAN}"
        "[6/8] Running systemd service scanner..."
        f"{RESET}"
    )

    scanner_results[
        "Service Scanner"
    ] = run_service_scanner()

    # ---------------------------------------------------------
    # Capabilities
    # ---------------------------------------------------------

    print(
        f"\n{CYAN}"
        "[7/8] Running Linux capabilities scanner..."
        f"{RESET}"
    )

    scanner_results[
        "Capabilities Scanner"
    ] = run_capabilities_scanner()

    # ---------------------------------------------------------
    # Kernel
    # ---------------------------------------------------------

    print(
        f"\n{CYAN}"
        "[8/8] Running kernel scanner..."
        f"{RESET}"
    )

    scanner_results[
        "Kernel Scanner"
    ] = run_kernel_scanner()

    # ---------------------------------------------------------
    # Analysis
    # ---------------------------------------------------------

    print(
        f"\n{CYAN}"
        "Analyzing scanner results..."
        f"{RESET}"
    )

    analysis = (
        analyzer.analyze_all_scanner_results(
            scanner_results
        )
    )

    display_findings(
        analysis
    )

    analyzer.print_analysis_summary(
        analysis
    )

    # ---------------------------------------------------------
    # Report
    # ---------------------------------------------------------

    print(
        f"\n{CYAN}"
        "Generating security report..."
        f"{RESET}"
    )

    report_file = os.path.join(
        os.getcwd(),
        "security_report.txt"
    )

    report_generator.generate_report(
        analysis,
        system_information,
        report_file
    )

    elapsed_time = (
        time.time() - start_time
    )

    # ---------------------------------------------------------
    # Final Summary
    # ---------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "SCAN COMPLETED"
    )

    print(
        "=" * 70
    )

    print(
        "Total Findings:",
        analysis["total_findings"]
    )

    print(
        "Risk Score:",
        analysis["risk_score"]
    )

    print(
        "Overall Status:",
        analysis["overall_status"]
    )

    print(
        "Report:",
        report_file
    )

    print(
        f"Execution Time: "
        f"{elapsed_time:.2f} seconds"
    )

    print(
        "=" * 70
    )

    print(
        f"\n{GREEN}"
        "Linux Privilege Escalation Automation Toolkit "
        "completed successfully."
        f"{RESET}"
    )


if __name__ == "__main__":
    main()
