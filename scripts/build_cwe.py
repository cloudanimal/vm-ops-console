#!/usr/bin/env python3
"""Build all-time CVE counts for the most common CWE weakness types.

Counted locally from the fkie-cad NVD mirror (see ``nvd_feed.py``) — no NVD API
key. For each curated CWE we count distinct CVEs whose weakness enumeration
includes that CWE-ID (any source), corpus-wide. Powers the "weakness types"
panel.

Source: https://github.com/fkie-cad/nvd-json-data-feeds (NVD data; not endorsed
by NVD). The previous implementation used the NVD 2.0 API's ``totalResults``
count for a ``cweId`` filter.
"""
import json
import os
from datetime import datetime, timezone

import nvd_feed

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

# Curated set of high-interest CWEs with their short titles.
CWES = [
    ("CWE-79", "Cross-site Scripting"), ("CWE-89", "SQL Injection"),
    ("CWE-787", "Out-of-bounds Write"), ("CWE-125", "Out-of-bounds Read"),
    ("CWE-20", "Improper Input Validation"), ("CWE-22", "Path Traversal"),
    ("CWE-78", "OS Command Injection"), ("CWE-416", "Use After Free"),
    ("CWE-352", "Cross-Site Request Forgery"), ("CWE-434", "Unrestricted File Upload"),
    ("CWE-862", "Missing Authorization"), ("CWE-476", "NULL Pointer Dereference"),
    ("CWE-287", "Improper Authentication"), ("CWE-190", "Integer Overflow"),
    ("CWE-502", "Deserialization of Untrusted Data"), ("CWE-918", "Server-Side Request Forgery"),
    ("CWE-119", "Improper Restriction of Memory Buffer"), ("CWE-200", "Information Exposure"),
    ("CWE-94", "Code Injection"), ("CWE-269", "Improper Privilege Management"),
    ("CWE-863", "Incorrect Authorization"), ("CWE-798", "Hard-coded Credentials"),
    ("CWE-306", "Missing Authentication"), ("CWE-732", "Incorrect Permission Assignment"),
]


def main():
    wanted = {cwe for cwe, _ in CWES}
    counts = {cwe: 0 for cwe, _ in CWES}

    for file_year, items in nvd_feed.iter_years():
        for cve in items:
            for cwe in nvd_feed.cwe_ids(cve) & wanted:
                counts[cwe] += 1
        print(f"  CVE-{file_year} file: {len(items)} records")

    rows = [{"cwe": cwe, "name": name, "count": counts[cwe]} for cwe, name in CWES]
    rows.sort(key=lambda r: r["count"], reverse=True)
    out = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "source": "fkie-cad NVD mirror (counted locally, by cweId)",
        "weaknesses": rows,
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "cwe.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nWrote {len(rows)} weakness types.")


if __name__ == "__main__":
    main()
