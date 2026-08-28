import os
import subprocess
import stat


high_risk_binaries = [
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
]


def scan_files(permission):
    result = subprocess.run(
        ["find", "/", "-perm", f"-{permission}", "-type", "f"],
        capture_output=True,
        text=True
    )

    files = result.stdout.splitlines()

    return files


def analyze_file(path, permission_type):
    result = subprocess.run(
        ["ls", "-l", path],
        capture_output=True,
        text=True
    )

    line = result.stdout.strip()
    parts = line.split()

    permissions = parts[0]
    owner = parts[2]
    group = parts[3]
    binary_name = os.path.basename(path)

    file_stat = os.stat(path)
    mode = file_stat.st_mode

    is_world_writable = bool(mode & stat.S_IWOTH)
    is_group_writable = bool(mode & stat.S_IWGRP)

    if is_world_writable:
        severity = "HIGH"
        finding = "Privileged file is world-writable"

    elif binary_name in high_risk_binaries:
        severity = "HIGH"
        finding = "Binary matches a known privilege-escalation pattern"

    else:
        severity = "LOW"
        finding = "No obvious high-risk condition detected"

    if severity == "HIGH":
        recommendation = (
            "Review binary against approved privilege-escalation "
            "references and remove unnecessary SUID/SGID permissions."
        )
    else:
        recommendation = (
            "No immediate action required; continue monitoring "
            "privileged binaries."
        )

    print("------------------------------------------------")
    print("Type:", permission_type)
    print("Permissions:", permissions)
    print("Owner:", owner)
    print("Group:", group)
    print("Binary:", binary_name)
    print("Path:", path)
    print("World-Writable:", is_world_writable)
    print("Group-Writable:", is_group_writable)

    if severity == "HIGH":
        print("\033[91mSeverity:", severity, "\033[0m")
        print("\033[91mFinding:", finding, "\033[0m")
    else:
        print("Severity:", severity)
        print("Finding:", finding)

    print("Recommendation:", recommendation)

    return severity


def main():

    suid_files = scan_files(4000)

    print("SUID Files:")

    high_count = 0
    low_count = 0

    for file in suid_files:
        severity = analyze_file(file, "SUID")

        if severity == "HIGH":
            high_count += 1
        else:
            low_count += 1

    print("\n--------------------------------------------")

    sgid_files = scan_files(2000)

    print("SGID Files:")

    for file in sgid_files:
        severity = analyze_file(file, "SGID")

        if severity == "HIGH":
            high_count += 1
        else:
            low_count += 1

    print("\n============================================")
    print("SCAN SUMMARY")
    print("============================================")
    print("SUID Files Found:", len(suid_files))
    print("SGID Files Found:", len(sgid_files))
    print("HIGH Risk Findings:", high_count)
    print("LOW Risk Findings:", low_count)

    if high_count > 0:
        print("\033[91mOverall Status: HIGH RISK FINDING DETECTED\033[0m")
    else:
        print("Overall Status: NO HIGH RISK FINDINGS DETECTED")

    print("============================================")


if __name__ == "__main__":
    main()
