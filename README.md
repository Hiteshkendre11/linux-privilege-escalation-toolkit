# Linux Privilege Escalation Automation Toolkit

A Python-based Linux security auditing tool designed to identify
potential privilege-escalation conditions involving SUID and SGID files.

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

    cd project-1

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

A controlled laboratory file can be used to verify the scanner's
ability to detect risky SUID/SGID permission configurations.

Testing should be performed only in an isolated and authorized
laboratory environment.

## Project Structure

    project-1/
    ├── suid_scanner.py
    ├── system_info.py
    ├── requirements.txt
    ├── .gitignore
    ├── README.md
    └── lab/

## Limitations

A HIGH finding indicates a potentially dangerous configuration
based on the detection rules implemented by the tool.

It does not automatically prove that the file is exploitable.
Individual findings require further manual security assessment.

## Disclaimer

This project is intended for authorized security testing,
education, and laboratory environments only.

Do not use this tool against systems without proper authorization.
