"""Web dashboard for the Linux Privilege Escalation Automation Toolkit.

Detection-only dashboard. Scans the container hosting this application,
not the browser visitor's computer or any remote target.
"""
import io
import os
import platform
import threading
import time
from datetime import datetime

from flask import Flask, jsonify, render_template, request, send_file

import analyzer
import capabilities_scanner
import cron_scanner
import kernel_scanner
import permissions_scanner
import report_generator
import service_scanner
import sudo_scanner
import suid_scanner

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
SCAN_LOCK = threading.Lock()
LATEST_REPORT = {"text": None, "created": None}

SCANNERS = {
    "suid": ("SUID/SGID Scanner", lambda: suid_scanner.run_suid_scan()[0]),
    "permissions": ("Permissions Scanner", permissions_scanner.run_permission_scan),
    "sudo": ("Sudo Scanner", lambda: sudo_scanner.run_sudo_scan()[0]),
    "cron": ("Cron Scanner", cron_scanner.run_cron_scan),
    "services": ("Systemd Service Scanner", lambda: service_scanner.run_service_scan()[0]),
    "capabilities": ("Linux Capabilities Scanner", lambda: capabilities_scanner.run_capability_scan()[0]),
    "kernel": ("Kernel Assessment Scanner", _kernel_findings if "_kernel_findings" in globals() else None),
}


def _kernel_findings():
    result = kernel_scanner.run_kernel_scan()
    kernel_release = result.get("kernel", {}).get("kernel_release", "Unknown")
    findings = []
    for key, title in (("age_assessment", "Kernel Age Assessment"), ("cve_assessment", "Kernel CVE Assessment")):
        item = result.get(key)
        if item:
            findings.append({
                "type": title,
                "path": kernel_release,
                "severity": item.get("severity", "LOW"),
                "finding": item.get("finding", "N/A"),
                "recommendation": item.get("recommendation", "N/A"),
            })
    return findings

# Bind the kernel callable after its definition.
SCANNERS["kernel"] = ("Kernel Assessment Scanner", _kernel_findings)


def system_information():
    try:
        import pwd
        username = pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        username = os.environ.get("USER", "Unknown")
    return {
        "Operating System": platform.system(),
        "Distribution": platform.platform(),
        "Kernel": platform.release(),
        "Architecture": platform.machine(),
        "Current User": username,
        "Execution UID": str(os.getuid()),
        "Execution Context": "Hosted container (not visitor's device)",
    }


def execute_scans(scan_ids):
    results = {}
    errors = []
    started = time.time()
    for scan_id in scan_ids:
        scanner_name, runner = SCANNERS[scan_id]
        try:
            findings = runner()
            if not isinstance(findings, list):
                findings = []
            results[scanner_name] = findings
        except Exception as exc:
            results[scanner_name] = []
            errors.append({"scanner": scanner_name, "error": str(exc)[:500]})
    analysis = analyzer.analyze_all_scanner_results(results)
    info = system_information()
    report_text = report_generator.generate_report(
        analysis,
        system_info=info,
        output_file="/tmp/security_report_latest.txt",
    )
    LATEST_REPORT["text"] = report_text
    LATEST_REPORT["created"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    return {
        "success": True,
        "scan_names": [SCANNERS[s][0] for s in scan_ids],
        "scanner_results": {name: len(items) for name, items in results.items()},
        "findings": analysis["findings"],
        "counts": analysis["counts"],
        "total_findings": analysis["total_findings"],
        "risk_score": analysis["risk_score"],
        "overall_status": analysis["overall_status"],
        "system_info": info,
        "errors": errors,
        "duration_seconds": round(time.time() - started, 2),
        "report_created": LATEST_REPORT["created"],
    }


@app.get("/")
def index():
    return render_template("index.html", scanner_ids=list(SCANNERS.keys()))


@app.get("/health")
def health():
    return jsonify({"status": "ok", "application": "Linux Privilege Escalation Toolkit"})


@app.post("/api/scan")
def scan():
    data = request.get_json(silent=True) or {}
    scan_ids = data.get("scans")
    if not isinstance(scan_ids, list) or not scan_ids:
        return jsonify({"success": False, "error": "Select at least one scan."}), 400
    if any(not isinstance(item, str) or item not in SCANNERS for item in scan_ids):
        return jsonify({"success": False, "error": "Invalid scanner selection."}), 400
    # Remove duplicates while preserving user-selected order.
    scan_ids = list(dict.fromkeys(scan_ids))
    if not SCAN_LOCK.acquire(blocking=False):
        return jsonify({"success": False, "error": "A security scan is already running. Please wait."}), 429
    try:
        return jsonify(execute_scans(scan_ids))
    finally:
        SCAN_LOCK.release()


@app.get("/api/report")
def download_report():
    report_text = LATEST_REPORT.get("text")
    if not report_text:
        return jsonify({"success": False, "error": "Run a scan before downloading a report."}), 404
    payload = io.BytesIO(report_text.encode("utf-8"))
    payload.seek(0)
    filename = "linux_privilege_escalation_security_report.txt"
    return send_file(payload, mimetype="text/plain", as_attachment=True, download_name=filename)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
