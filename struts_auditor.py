"""Struts Patch-Gap Auditor

Finds Apache Struts 2 libraries on a machine and flags versions that are
vulnerable to CVE-2017-5638 (the flaw exploited in the 2017 Equifax breach).
Optionally scans a web log for exploit-style Content-Type headers.

Usage:  python struts_auditor.py <folder> [--logs access.log] [--csv report.csv]
"""
import argparse
import csv
import os
import re
import sys
import zipfile

# Matches file names such as struts2-core-2.3.31.jar and captures "2.3.31"
JAR_PATTERN = re.compile(r"struts2-core-(\d+(?:\.\d+)+)\.jar$", re.IGNORECASE)

# A Content-Type header containing OGNL-style syntax is suspicious
LOG_PATTERN = re.compile(r"content-type.*(%\{|\$\{|ognl)", re.IGNORECASE)

ORDER = {"VULNERABLE": 0, "REVIEW": 1, "OK": 2}


def parse_version(text):
    """'2.3.31' -> (2, 3, 31) so versions can be compared."""
    return tuple(int(part) for part in text.split("."))


def check_version(version):
    """Compare against the CVE-2017-5638 ranges (Struts advisory S2-045).

    Vulnerable: 2.3.5 - 2.3.31 and 2.5.0 - 2.5.10
    Fixed in:   2.3.32 and 2.5.10.1
    """
    if (2, 3, 5) <= version < (2, 3, 32):
        return "VULNERABLE"
    if (2, 5, 0) <= version < (2, 5, 10, 1):
        return "VULNERABLE"
    if version < (2, 3, 5):
        return "REVIEW"  # very old, outside the documented range
    return "OK"


def look_inside_archive(path):
    """Look for Struts jars packed inside a .war or .zip file."""
    found = []
    try:
        with zipfile.ZipFile(path) as archive:
            for entry in archive.namelist():
                match = JAR_PATTERN.search(entry)
                if match:
                    found.append((path + "!" + entry, match.group(1)))
    except (zipfile.BadZipFile, OSError):
        pass  # unreadable file: skip it
    return found


def find_struts(root):
    """Walk the folder and return a list of (location, version)."""
    found = []
    for folder, _, files in os.walk(root):
        for name in files:
            path = os.path.join(folder, name)
            match = JAR_PATTERN.search(name)
            if match:
                found.append((path, match.group(1)))
            elif name.lower().endswith((".war", ".zip")):
                found.extend(look_inside_archive(path))
    return found


def scan_log(path):
    """Return (line_number, text) for every suspicious log line."""
    alerts = []
    with open(path, errors="ignore") as log:
        for number, line in enumerate(log, start=1):
            if LOG_PATTERN.search(line):
                alerts.append((number, line.strip()))
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Find Struts versions vulnerable to CVE-2017-5638")
    parser.add_argument("path", help="folder to scan")
    parser.add_argument("--logs", help="web server log file to check")
    parser.add_argument("--csv", help="save the results to a CSV file")
    args = parser.parse_args()

    rows = []
    for location, version in find_struts(args.path):
        rows.append((check_version(parse_version(version)), version, location))
    rows.sort(key=lambda row: ORDER[row[0]])

    print("STRUTS PATCH-GAP AUDITOR | CVE-2017-5638")
    print("Scanned:", args.path, "\n")
    print(f"{'STATUS':<12}{'VERSION':<10}LOCATION")
    for status, version, location in rows:
        print(f"{status:<12}{version:<10}{location}")

    vulnerable = sum(1 for row in rows if row[0] == "VULNERABLE")
    print(f"\nFound {len(rows)} Struts library(s), {vulnerable} vulnerable.")
    if vulnerable:
        print("Action: upgrade to a fixed, supported Struts release (2.3.32 / 2.5.10.1 or later).")

    alerts = scan_log(args.logs) if args.logs else []
    if args.logs:
        print(f"\nLog check: {len(alerts)} suspicious line(s) in {args.logs}")
        for number, text in alerts:
            print(f"  line {number}: {text[:70]}")

    if args.csv:
        with open(args.csv, "w", newline="") as out:
            writer = csv.writer(out)
            writer.writerow(["status", "version", "location"])
            writer.writerows(rows)

    sys.exit(1 if vulnerable or alerts else 0)


if __name__ == "__main__":
    main()
