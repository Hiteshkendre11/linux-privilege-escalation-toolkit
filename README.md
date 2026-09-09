# Linux Privilege Escalation Automation Toolkit

A Python-based Linux security auditing toolkit designed to identify
potential privilege-escalation conditions involving SUID and SGID files.

This project was developed as part of a cybersecurity internship and
tested in a controlled Linux laboratory environment.

## Features

- SUID file discovery
- SGID file discovery
- File permission analysis
- Owner and group identification
- World-writable detection
- Group-writable detection
- High-risk binary pattern detection
- HIGH / LOW severity classification
- Security recommendations
- Red highlighting for HIGH-risk findings
- Scan summary
- System information collection
- Controlled laboratory testing

## Requirements

- Linux operating system
- Python 3
- sudo privileges recommended for complete filesystem scanning

No external Python packages are required.

## Installation

Clone the repository:

    git clone https://github.com/Hiteshkendre11/linux-privilege-escalation-toolkit.git

Enter the project directory:

    cd linux-privilege-escalation-toolkit

## Usage

Run the system information scanner:

    python3 system_info.py

Run the SUID/SGID scanner:

    python3 suid_scanner.py

## Example Output

    ============================================
    SCAN SUMMARY
    ============================================
    SUID Files Found: 34
    SGID Files Found: 8
    HIGH Risk Findings: 1
    LOW Risk Findings: 41
    Overall Status: HIGH RISK FINDING DETECTED
    ============================================

## Testing

The toolkit was tested in a controlled and authorized Linux laboratory
environment.

A controlled laboratory file can be used to verify the scanner's ability
to detect risky SUID/SGID permission configurations.

Testing should only be performed in isolated and authorized environments.

## Project Structure

    linux-privilege-escalation-toolkit/
    ├── suid_scanner.py
    ├── system_info.py
    ├── requirements.txt
    ├── .gitignore
    ├── README.md
    ├── docs/
    │   └── Project Report
    ├── screenshots/
    │   └── Testing Evidence
    └── lab/
        └── Laboratory Testing Files

## Limitations

A HIGH finding indicates a potentially dangerous configuration based on
the detection rules implemented by the tool.

It does not automatically prove that the file is exploitable.
Individual findings require further manual security assessment.

## Project Documentation

The complete project report contains the project methodology,
implementation details, testing process, results, screenshots,
limitations, and conclusions.

## Internship

**Program:** Cybersecurity Internship  
**Project:** Linux Privilege Escalation Automation Toolkit

## Disclaimer

This project is intended for authorized security testing, education,
and laboratory environments only.

Do not use this tool against systems without proper authorization.
