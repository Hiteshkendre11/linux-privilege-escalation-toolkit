"""
Central analysis engine for the Linux Privilege Escalation
Automation Toolkit.

This module does not perform exploitation.
It only analyzes and normalizes findings produced by
the individual scanner modules.
"""


# Severity ranking
SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3
}


def normalize_finding(finding, scanner_name="Unknown"):
    """
    Normalize a scanner finding into a consistent structure.
    """

    normalized = {
        "scanner": scanner_name,
        "type": finding.get("type", "Unknown Finding"),
        "path": finding.get(
            "path",
            finding.get("rule", "N/A")
        ),
        "severity": finding.get(
            "severity",
            "LOW"
        ).upper(),
        "finding": finding.get(
            "finding",
            "No description available."
        ),
        "recommendation": finding.get(
            "recommendation",
            "Review the configuration and apply least privilege."
        )
    }

    # Preserve useful optional information
    optional_fields = [
        "service",
        "permissions",
        "capabilities",
        "rule"
    ]

    for field in optional_fields:

        if field in finding:
            normalized[field] = finding[field]

    # Validate severity
    if normalized["severity"] not in SEVERITY_LEVELS:
        normalized["severity"] = "LOW"

    return normalized


def normalize_findings(findings, scanner_name="Unknown"):
    """
    Normalize a list of findings.
    """

    normalized = []

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        normalized.append(
            normalize_finding(
                finding,
                scanner_name
            )
        )

    return normalized


def create_finding_key(finding):
    """
    Create a key used to identify exact duplicate findings.
    """

    return (
        finding.get("type", ""),
        finding.get("path", ""),
        finding.get("service", ""),
        finding.get("rule", "")
    )


def remove_exact_duplicates(findings):
    """
    Remove exact duplicate findings while preserving order.
    """

    unique_findings = []
    seen = set()

    for finding in findings:

        key = create_finding_key(finding)

        if key in seen:
            continue

        seen.add(key)
        unique_findings.append(finding)

    return unique_findings


def consolidate_related_findings(findings):
    """
    Consolidate related findings affecting the same path.

    Example:
    A file that is both world-writable and a writable SUID file
    represents one underlying security condition.

    The most severe finding is retained while the descriptions
    of related findings are combined.
    """

    grouped = {}

    for finding in findings:

        path = finding.get("path", "N/A")

        # Only consolidate actual filesystem paths.
        if path == "N/A" or not path.startswith("/"):
            grouped.setdefault(
                ("unique", id(finding)),
                []
            ).append(finding)
            continue

        grouped.setdefault(path, []).append(finding)

    consolidated = []

    for key, group in grouped.items():

        if len(group) == 1:

            consolidated.append(group[0])
            continue

        # Select highest-severity finding
        primary = max(
            group,
            key=lambda item: SEVERITY_LEVELS.get(
                item.get("severity", "LOW"),
                1
            )
        )

        related_types = []

        for finding in group:

            finding_type = finding.get(
                "type",
                "Unknown Finding"
            )

            if finding_type not in related_types:
                related_types.append(finding_type)

        primary = primary.copy()

        if len(related_types) > 1:

            primary["related_findings"] = related_types

            primary["finding"] = (
                primary["finding"]
                + " Related checks also identified: "
                + ", ".join(
                    item for item in related_types
                    if item != primary["type"]
                )
                + "."
            )

        consolidated.append(primary)

    return consolidated


def sort_findings_by_severity(findings):
    """
    Sort findings from highest to lowest severity.
    """

    return sorted(
        findings,
        key=lambda finding: SEVERITY_LEVELS.get(
            finding.get("severity", "LOW"),
            1
        ),
        reverse=True
    )


def calculate_severity_counts(findings):
    """
    Calculate HIGH, MEDIUM and LOW finding counts.
    """

    counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:

        severity = finding.get(
            "severity",
            "LOW"
        )

        if severity not in counts:
            severity = "LOW"

        counts[severity] += 1

    return counts


def determine_overall_status(findings):
    """
    Determine the overall security status.
    """

    if not findings:
        return "NO FINDINGS"

    counts = calculate_severity_counts(
        findings
    )

    if counts["HIGH"] > 0:
        return "HIGH RISK FINDING DETECTED"

    if counts["MEDIUM"] > 0:
        return "MEDIUM RISK FINDING DETECTED"

    return "NO HIGH-RISK FINDINGS"


def calculate_risk_score(findings):
    """
    Calculate a simple risk score.

    HIGH   = 3 points
    MEDIUM = 2 points
    LOW    = 1 point

    This is an internal prioritization score and is not
    a CVSS score.
    """

    score = 0

    for finding in findings:

        severity = finding.get(
            "severity",
            "LOW"
        )

        score += SEVERITY_LEVELS.get(
            severity,
            1
        )

    return score


def analyze_findings(
    findings,
    scanner_name="Unknown"
):
    """
    Perform the complete analysis pipeline.

    Pipeline:

        Raw findings
             ↓
        Normalization
             ↓
        Duplicate removal
             ↓
        Related finding consolidation
             ↓
        Severity sorting
             ↓
        Risk calculation
             ↓
        Final analysis
    """

    normalized = normalize_findings(
        findings,
        scanner_name
    )

    unique_findings = remove_exact_duplicates(
        normalized
    )

    consolidated_findings = consolidate_related_findings(
        unique_findings
    )

    sorted_findings = sort_findings_by_severity(
        consolidated_findings
    )

    counts = calculate_severity_counts(
        sorted_findings
    )

    overall_status = determine_overall_status(
        sorted_findings
    )

    risk_score = calculate_risk_score(
        sorted_findings
    )

    return {
        "findings": sorted_findings,
        "counts": counts,
        "total_findings": len(sorted_findings),
        "risk_score": risk_score,
        "overall_status": overall_status
    }


def analyze_all_scanner_results(scanner_results):
    """
    Analyze findings from multiple scanner modules.

    Expected input:

    {
        "SUID/SGID Scanner": [...],
        "Permissions Scanner": [...],
        "Sudo Scanner": [...],
        ...
    }
    """

    all_findings = []

    for scanner_name, findings in scanner_results.items():

        if not isinstance(findings, list):
            continue

        normalized = normalize_findings(
            findings,
            scanner_name
        )

        all_findings.extend(
            normalized
        )

    unique_findings = remove_exact_duplicates(
        all_findings
    )

    consolidated_findings = consolidate_related_findings(
        unique_findings
    )

    sorted_findings = sort_findings_by_severity(
        consolidated_findings
    )

    counts = calculate_severity_counts(
        sorted_findings
    )

    overall_status = determine_overall_status(
        sorted_findings
    )

    risk_score = calculate_risk_score(
        sorted_findings
    )

    return {
        "findings": sorted_findings,
        "counts": counts,
        "total_findings": len(sorted_findings),
        "risk_score": risk_score,
        "overall_status": overall_status
    }


def print_analysis_summary(analysis):
    """
    Display a concise analysis summary.
    """

    counts = analysis["counts"]

    print("=" * 60)
    print("SECURITY ANALYSIS SUMMARY")
    print("=" * 60)

    print(
        "Total Findings:",
        analysis["total_findings"]
    )

    print(
        "Risk Score:",
        analysis["risk_score"]
    )

    print(
        f"HIGH Risk Findings: "
        f"{counts['HIGH']}"
    )

    print(
        f"MEDIUM Risk Findings: "
        f"{counts['MEDIUM']}"
    )

    print(
        f"LOW Risk Findings: "
        f"{counts['LOW']}"
    )

    print(
        "Overall Status:",
        analysis["overall_status"]
    )

    print("=" * 60)


if __name__ == "__main__":

    print("=" * 60)
    print("ANALYZER MODULE")
    print("=" * 60)

    print(
        "\nAnalyzer module loaded successfully."
    )

    print(
        "This module is designed to process findings "
        "from the toolkit's scanner modules."
    )

    print("=" * 60)
