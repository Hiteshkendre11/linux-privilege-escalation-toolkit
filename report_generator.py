"""
Security report generator for the Linux Privilege Escalation
Automation Toolkit.

This module converts analyzed scanner findings into a
structured text security report.

Detection and reporting only. No exploitation is performed.
"""

from datetime import datetime


def generate_report(
    analysis,
    system_info=None,
    output_file="security_report.txt"
):
    """
    Generate a structured security report.

    Parameters:
        analysis:
            Dictionary returned by analyzer.py.

        system_info:
            Optional dictionary containing system information.

        output_file:
            File where the report will be saved.
    """

    findings = analysis.get(
        "findings",
        []
    )

    counts = analysis.get(
        "counts",
        {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
    )

    total_findings = analysis.get(
        "total_findings",
        len(findings)
    )

    risk_score = analysis.get(
        "risk_score",
        0
    )

    overall_status = analysis.get(
        "overall_status",
        "UNKNOWN"
    )

    report_lines = []

    # ---------------------------------------------------------
    # Report Header
    # ---------------------------------------------------------

    report_lines.append("=" * 70)
    report_lines.append(
        "LINUX PRIVILEGE ESCALATION SECURITY AUDIT REPORT"
    )
    report_lines.append("=" * 70)

    report_lines.append(
        f"Report Generated: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    report_lines.append(
        "Assessment Type: Automated Security Audit"
    )

    report_lines.append(
        "Mode: Detection Only"
    )

    report_lines.append("")

    # ---------------------------------------------------------
    # System Information
    # ---------------------------------------------------------

    report_lines.append("=" * 70)
    report_lines.append("SYSTEM INFORMATION")
    report_lines.append("=" * 70)

    if system_info:

        for key, value in system_info.items():

            report_lines.append(
                f"{key}: {value}"
            )

    else:

        report_lines.append(
            "System information was not supplied."
        )

    report_lines.append("")

    # ---------------------------------------------------------
    # Executive Summary
    # ---------------------------------------------------------

    report_lines.append("=" * 70)
    report_lines.append("EXECUTIVE SUMMARY")
    report_lines.append("=" * 70)

    report_lines.append(
        f"Total Findings: {total_findings}"
    )

    report_lines.append(
        f"HIGH Risk Findings: {counts.get('HIGH', 0)}"
    )

    report_lines.append(
        f"MEDIUM Risk Findings: {counts.get('MEDIUM', 0)}"
    )

    report_lines.append(
        f"LOW Risk Findings: {counts.get('LOW', 0)}"
    )

    report_lines.append(
        f"Risk Score: {risk_score}"
    )

    report_lines.append(
        f"Overall Status: {overall_status}"
    )

    report_lines.append("")

    # ---------------------------------------------------------
    # Findings
    # ---------------------------------------------------------

    report_lines.append("=" * 70)
    report_lines.append("DETAILED FINDINGS")
    report_lines.append("=" * 70)

    if not findings:

        report_lines.append(
            "No security findings were detected."
        )

    else:

        for number, finding in enumerate(
            findings,
            start=1
        ):

            report_lines.append("")
            report_lines.append(
                f"FINDING #{number}"
            )
            report_lines.append(
                "-" * 70
            )

            report_lines.append(
                f"Scanner: "
                f"{finding.get('scanner', 'Unknown')}"
            )

            report_lines.append(
                f"Type: "
                f"{finding.get('type', 'Unknown')}"
            )

            report_lines.append(
                f"Severity: "
                f"{finding.get('severity', 'LOW')}"
            )

            if "service" in finding:

                report_lines.append(
                    f"Service: "
                    f"{finding['service']}"
                )

            if "path" in finding:

                report_lines.append(
                    f"Path: "
                    f"{finding['path']}"
                )

            if "permissions" in finding:

                report_lines.append(
                    f"Permissions: "
                    f"{finding['permissions']}"
                )

            if "capabilities" in finding:

                report_lines.append(
                    f"Capabilities: "
                    f"{finding['capabilities']}"
                )

            if "rule" in finding:

                report_lines.append(
                    f"Rule: "
                    f"{finding['rule']}"
                )

            report_lines.append(
                f"Finding: "
                f"{finding.get('finding', 'N/A')}"
            )

            report_lines.append(
                f"Recommendation: "
                f"{finding.get('recommendation', 'N/A')}"
            )

            if "related_findings" in finding:

                report_lines.append(
                    "Related Checks: "
                    + ", ".join(
                        finding["related_findings"]
                    )
                )

    report_lines.append("")

    # ---------------------------------------------------------
    # Mitigation Summary
    # ---------------------------------------------------------

    report_lines.append("=" * 70)
    report_lines.append("MITIGATION SUMMARY")
    report_lines.append("=" * 70)

    if not findings:

        report_lines.append(
            "No immediate mitigation actions were identified."
        )

    else:

        mitigation_number = 1

        for finding in findings:

            recommendation = finding.get(
                "recommendation"
            )

            if not recommendation:
                continue

            report_lines.append(
                f"{mitigation_number}. "
                f"{recommendation}"
            )

            mitigation_number += 1

    report_lines.append("")

    # ---------------------------------------------------------
    # Security Interpretation
    # ---------------------------------------------------------

    report_lines.append("=" * 70)
    report_lines.append("SECURITY INTERPRETATION")
    report_lines.append("=" * 70)

    if counts.get("HIGH", 0) > 0:

        report_lines.append(
            "HIGH-risk findings were detected. "
            "These findings should be prioritized for "
            "security review and remediation."
        )

    elif counts.get("MEDIUM", 0) > 0:

        report_lines.append(
            "MEDIUM-risk findings were detected. "
            "These configurations should be reviewed "
            "and hardened where appropriate."
        )

    else:

        report_lines.append(
            "No HIGH-risk findings were detected. "
            "Continue regular security auditing and "
            "system patching."
        )

    report_lines.append("")

    # ---------------------------------------------------------
    # Limitations
    # ---------------------------------------------------------

    report_lines.append("=" * 70)
    report_lines.append("LIMITATIONS")
    report_lines.append("=" * 70)

    report_lines.append(
        "1. Findings represent potentially risky "
        "configurations and do not automatically prove "
        "exploitability."
    )

    report_lines.append(
        "2. Individual findings require manual validation "
        "by an authorized security professional."
    )

    report_lines.append(
        "3. Kernel vulnerability information should be "
        "verified against official distribution security "
        "advisories and trusted CVE databases."
    )

    report_lines.append(
        "4. The toolkit performs detection and analysis "
        "only and does not execute privilege-escalation "
        "exploits."
    )

    report_lines.append("")

    # ---------------------------------------------------------
    # Disclaimer
    # ---------------------------------------------------------

    report_lines.append("=" * 70)
    report_lines.append("DISCLAIMER")
    report_lines.append("=" * 70)

    report_lines.append(
        "This report is intended for authorized security "
        "testing, education, auditing and laboratory "
        "environments only."
    )

    report_lines.append(
        "Do not use the toolkit against systems without "
        "proper authorization."
    )

    report_lines.append("=" * 70)

    report_text = "\n".join(
        report_lines
    )

    try:

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as report_file:

            report_file.write(
                report_text
            )

        return report_text

    except OSError as error:

        print(
            f"ERROR: Unable to create report: {error}"
        )

        return report_text


def print_report(report_text):
    """Display the generated report."""

    print(report_text)


if __name__ == "__main__":

    print("=" * 70)
    print("REPORT GENERATOR MODULE")
    print("=" * 70)

    print(
        "\nReport generator module loaded successfully."
    )

    print(
        "It is ready to generate structured security "
        "reports from analyzer results."
    )

    print("=" * 70)
