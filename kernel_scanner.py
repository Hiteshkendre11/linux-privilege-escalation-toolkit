import platform
import os
import re
import subprocess


# Terminal colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


# ------------------------------------------------------------------
# Local CVE reference database
# ------------------------------------------------------------------
#
# This is a small offline reference dataset for demonstration and
# defensive auditing purposes.
#
# IMPORTANT:
# - This is NOT a complete CVE database.
# - CVE applicability depends on distribution backports and patches.
# - A version match is only an indication requiring verification.
# - No exploitation is performed.
#
# Version format:
#     (major, minor, patch)
#
# affected_before means versions below that version are potentially
# affected according to the local reference entry.
#
# ------------------------------------------------------------------

CVE_REFERENCES = [
    {
        "cve": "CVE-2022-0847",
        "description":
            "Linux kernel Dirty Pipe vulnerability.",
        "affected_before": (5, 10, 102),
        "severity": "HIGH",
        "recommendation":
            "Verify the kernel against official distribution "
            "security advisories and install the appropriate "
            "security update if affected."
    },

    {
        "cve": "CVE-2022-2586",
        "description":
            "Linux kernel use-after-free vulnerability in nft tables.",
        "affected_before": (5, 18, 17),
        "severity": "HIGH",
        "recommendation":
            "Verify the installed kernel against the distribution "
            "security advisory and apply the appropriate security "
            "update."
    },

    {
        "cve": "CVE-2023-0386",
        "description":
            "Linux kernel OverlayFS privilege-escalation vulnerability.",
        "affected_before": (6, 2, 0),
        "severity": "HIGH",
        "recommendation":
            "Verify whether the distribution has backported the "
            "security fix and install the appropriate kernel update."
    }
]


def run_command(command):
    """Run a system command safely."""

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        return result.stdout.strip()

    except subprocess.TimeoutExpired:

        return ""

    except FileNotFoundError:

        return ""

    except Exception:

        return ""


def get_kernel_information():
    """Collect kernel and architecture information."""

    kernel_release = platform.release()
    kernel_version = platform.version()
    architecture = platform.machine()
    system = platform.system()

    return {
        "system": system,
        "kernel_release": kernel_release,
        "kernel_version": kernel_version,
        "architecture": architecture
    }


def get_os_information():
    """Read Linux distribution information."""

    information = {}

    os_release = "/etc/os-release"

    if not os.path.exists(os_release):
        return information

    try:

        with open(
            os_release,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line in file:

                line = line.strip()

                if "=" not in line:
                    continue

                key, value = line.split(
                    "=",
                    1
                )

                information[key] = value.strip(
                    '"'
                )

    except (
        PermissionError,
        OSError
    ):

        pass

    return information


def parse_kernel_version(kernel_release):
    """
    Extract major, minor and patch components.

    Example:

        6.6.15-amd64

    becomes:

        (6, 6, 15)
    """

    match = re.match(
        r"^(\d+)\.(\d+)\.(\d+)",
        kernel_release
    )

    if not match:
        return None

    return (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3))
    )


def check_kernel_age(kernel_release):
    """
    Perform a conservative kernel-age assessment.

    This is separate from CVE matching.
    """

    version = parse_kernel_version(
        kernel_release
    )

    if version is None:

        return {
            "severity": "LOW",
            "finding":
                "Kernel version could not be parsed.",
            "recommendation":
                "Verify the installed kernel version manually "
                "and check the distribution security advisories."
        }

    major, minor, patch = version

    if major < 5:

        return {
            "severity": "HIGH",
            "finding":
                "Kernel release appears significantly outdated.",
            "recommendation":
                "Update the kernel using the operating system's "
                "supported security update mechanism."
        }

    elif major == 5:

        return {
            "severity": "MEDIUM",
            "finding":
                "Kernel belongs to an older major release and "
                "should be reviewed for available security updates.",
            "recommendation":
                "Check the distribution's official security "
                "advisories and install supported kernel updates."
        }

    else:

        return {
            "severity": "LOW",
            "finding":
                "Kernel release does not appear unusually old "
                "based on the scanner's conservative version check.",
            "recommendation":
                "Continue applying security updates and verify "
                "the kernel against official distribution advisories."
        }


def check_known_cve_references(kernel_release):
    """
    Match the detected kernel version against the local CVE
    reference database.

    This is a defensive offline assessment.

    A match does NOT prove exploitability because Linux
    distributions may backport security patches.
    """

    version = parse_kernel_version(
        kernel_release
    )

    if version is None:

        return {
            "severity": "LOW",
            "cves": [],
            "finding":
                "Kernel version could not be parsed, so the "
                "local CVE reference check could not be completed.",
            "recommendation":
                "Verify the kernel version manually and compare "
                "it with official distribution security advisories."
        }

    matched_cves = []

    for reference in CVE_REFERENCES:

        affected_before = reference[
            "affected_before"
        ]

        if version < affected_before:

            matched_cves.append(
                reference
            )

    # ----------------------------------------------------------
    # No local matches
    # ----------------------------------------------------------

    if not matched_cves:

        return {
            "severity": "LOW",
            "cves": [],
            "finding":
                "No matching CVE was identified in the "
                "local reference database for this kernel version.",
            "recommendation":
                "Continue applying security updates and verify "
                "the kernel against official Kali/Debian security "
                "advisories and trusted CVE databases."
        }

    # ----------------------------------------------------------
    # CVE matches
    # ----------------------------------------------------------

    highest_severity = "LOW"

    for cve in matched_cves:

        if cve["severity"] == "HIGH":

            highest_severity = "HIGH"
            break

        elif cve["severity"] == "MEDIUM":

            highest_severity = "MEDIUM"

    cve_names = ", ".join(
        cve["cve"]
        for cve in matched_cves
    )

    finding = (
        f"Kernel version matches the affected-version range "
        f"of the following local CVE references: {cve_names}."
    )

    recommendation = (
        "Verify each CVE against the installed distribution's "
        "security advisories because distributions may backport "
        "security fixes without changing the upstream version. "
        "Do not assume vulnerability solely from this version match."
    )

    return {
        "severity": highest_severity,
        "cves": [
            cve["cve"]
            for cve in matched_cves
        ],
        "finding": finding,
        "recommendation": recommendation
    }


def run_kernel_scan():
    """Run the complete kernel information and assessment."""

    kernel_info = get_kernel_information()

    os_info = get_os_information()

    age_assessment = check_kernel_age(
        kernel_info["kernel_release"]
    )

    cve_assessment = check_known_cve_references(
        kernel_info["kernel_release"]
    )

    return {
        "kernel": kernel_info,
        "os": os_info,
        "age_assessment": age_assessment,
        "cve_assessment": cve_assessment
    }


def print_assessment(title, assessment):
    """Print an assessment using severity colors."""

    print(
        "-" * 60
    )

    print(
        title
    )

    severity = assessment[
        "severity"
    ]

    if severity == "HIGH":

        print(
            f"{RED}Severity: "
            f"{severity}{RESET}"
        )

        print(
            f"{RED}Finding: "
            f"{assessment['finding']}{RESET}"
        )

    elif severity == "MEDIUM":

        print(
            f"{YELLOW}Severity: "
            f"{severity}{RESET}"
        )

        print(
            "Finding:",
            assessment["finding"]
        )

    else:

        print(
            f"{GREEN}Severity: "
            f"{severity}{RESET}"
        )

        print(
            "Finding:",
            assessment["finding"]
        )

    print(
        "Recommendation:",
        assessment["recommendation"]
    )

    if assessment.get("cves"):

        print(
            "CVE References:",
            ", ".join(
                assessment["cves"]
            )
        )


def main():

    print(
        "=" * 60
    )

    print(
        "KERNEL SECURITY SCANNER"
    )

    print(
        "=" * 60
    )

    results = run_kernel_scan()

    kernel = results[
        "kernel"
    ]

    os_info = results[
        "os"
    ]

    print(
        "\nSYSTEM INFORMATION"
    )

    print(
        "-" * 60
    )

    print(
        "Operating System:",
        kernel["system"]
    )

    print(
        "Distribution:",
        os_info.get(
            "PRETTY_NAME",
            "Unknown"
        )
    )

    print(
        "Kernel Release:",
        kernel["kernel_release"]
    )

    print(
        "Kernel Version:",
        kernel["kernel_version"]
    )

    print(
        "Architecture:",
        kernel["architecture"]
    )

    print_assessment(
        "KERNEL AGE ASSESSMENT",
        results["age_assessment"]
    )

    print_assessment(
        "CVE ASSESSMENT",
        results["cve_assessment"]
    )

    age_severity = results[
        "age_assessment"
    ]["severity"]

    cve_severity = results[
        "cve_assessment"
    ]["severity"]

    high_count = 0
    medium_count = 0
    low_count = 0

    for severity in [
        age_severity,
        cve_severity
    ]:

        if severity == "HIGH":

            high_count += 1

        elif severity == "MEDIUM":

            medium_count += 1

        else:

            low_count += 1

    print(
        "\n" + "=" * 60
    )

    print(
        "KERNEL SCAN SUMMARY"
    )

    print(
        "=" * 60
    )

    print(
        "Assessments:",
        high_count
        + medium_count
        + low_count
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

    print(
        "\nNOTE: CVE matches are based on a limited local "
        "reference database. Always verify applicability "
        "against official distribution security advisories."
    )


if __name__ == "__main__":

    main()
