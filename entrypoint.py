#!/usr/bin/env python3
"""GitHub Action entrypoint for Rudor SBOM Scanner."""

import json
import os
import subprocess
import sys
from pathlib import Path


def gh_output(name, value):
    output_file = os.getenv("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")


def gh_log(level, message):
    print(f"::{level}::{message}")


def main():
    project_path = os.getenv("INPUT_PATH", ".")
    output_path = os.getenv("INPUT_OUTPUT", "bom.json")
    project_type = os.getenv("INPUT_PROJECT_TYPE", "")
    disable_cve = os.getenv("INPUT_DISABLE_CVE", "false").lower() == "true"
    verbose = os.getenv("INPUT_VERBOSE", "false").lower() == "true"
    fail_on_severity = os.getenv("INPUT_FAIL_ON_SEVERITY", "none").lower()
    cve_report_path = os.getenv("INPUT_CVE_REPORT_PATH", "cve-report.json")
    rudor_bin = "/app/rudor"

    print("::group::Validating inputs")

    if not Path(rudor_bin).exists():
        gh_log("error", f"Rudor binary not found at {rudor_bin}")
        return 1

    valid_severities = ["critical", "high", "medium", "low", "none"]
    if fail_on_severity not in valid_severities:
        gh_log("error", f"Invalid fail-on-severity: {fail_on_severity}. Must be one of: {', '.join(valid_severities)}")
        return 1

    if not Path(project_path).is_dir():
        gh_log("error", f"Project path does not exist: {project_path}")
        return 1

    print("All inputs validated successfully")
    print("::endgroup::")

    print("::group::Running Rudor scan")
    cmd = [rudor_bin, "generate"]

    if project_path != ".":
        cmd.append(project_path)

    cmd.extend(["-o", output_path])

    if project_type:
        cmd.extend(["-t", project_type])

    if verbose:
        cmd.append("-v")

    if disable_cve:
        cmd.append("--no-cve")

    print(f"Executing: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, check=True)
        print("SBOM generation completed successfully")
    except subprocess.CalledProcessError as e:
        gh_log("error", f"Rudor scan failed with exit code {e.returncode}")
        return 1

    if not Path(output_path).exists():
        gh_log("error", f"SBOM file not found at {output_path}")
        return 1

    gh_output("sbom-path", output_path)

    if Path(cve_report_path).exists():
        gh_output("cve-report-path", cve_report_path)
    else:
        gh_output("cve-report-path", "")

    print("::endgroup::")

    if disable_cve:
        print("Rudor scan completed successfully")
        return 0

    print("::group::Analyzing vulnerability results")

    if not Path(cve_report_path).exists():
        gh_log("warning", "CVE report not found, skipping analysis")
        gh_output("vulnerabilities-found", "false")
        for severity in ["critical", "high", "medium", "low"]:
            gh_output(f"{severity}-count", "0")
        print("::endgroup::")
        return 0

    try:
        with open(cve_report_path) as f:
            report = json.load(f)

        vulnerabilities = report.get("vulnerabilities", [])
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "").lower()
            if severity in counts:
                counts[severity] += 1

    except Exception as e:
        gh_log("warning", f"Failed to parse CVE report: {e}")
        gh_output("vulnerabilities-found", "false")
        for severity in ["critical", "high", "medium", "low"]:
            gh_output(f"{severity}-count", "0")
        print("::endgroup::")
        return 0

    for severity in ["critical", "high", "medium", "low"]:
        gh_output(f"{severity}-count", str(counts[severity]))

    total = sum(counts.values())

    if total == 0:
        gh_output("vulnerabilities-found", "false")
        print("No vulnerabilities found")
        print("::endgroup::")
        return 0

    gh_output("vulnerabilities-found", "true")
    gh_log("notice", f"Vulnerability Summary: {counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, {counts['low']} low")

    if fail_on_severity == "none":
        print("::endgroup::")
        print("Rudor scan completed successfully")
        return 0

    should_fail = False

    if fail_on_severity == "critical" and counts["critical"] > 0:
        gh_log("error", f"Found {counts['critical']} critical vulnerabilities (threshold: critical)")
        should_fail = True
    elif fail_on_severity == "high" and (counts["critical"] > 0 or counts["high"] > 0):
        gh_log("error", f"Found {counts['critical']} critical and {counts['high']} high vulnerabilities (threshold: high)")
        should_fail = True
    elif fail_on_severity == "medium" and (counts["critical"] > 0 or counts["high"] > 0 or counts["medium"] > 0):
        gh_log("error", f"Found {counts['critical']} critical, {counts['high']} high, and {counts['medium']} medium vulnerabilities (threshold: medium)")
        should_fail = True
    elif fail_on_severity == "low" and total > 0:
        gh_log("error", f"Found {total} total vulnerabilities (threshold: low)")
        should_fail = True

    print("::endgroup::")

    if should_fail:
        return 1

    print("Rudor scan completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
