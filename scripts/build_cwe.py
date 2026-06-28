#!/usr/bin/env python3
"""Build all-time CVE counts for the most common CWE weakness types.

Same cheap trick as the stats cube: the NVD API returns a ``totalResults``
count for a ``cweId`` filter, so one tiny call per weakness type gives a real
corpus-wide count. Powers the "weakness types" panel without any scraping.

Source: https://services.nvd.nist.gov/rest/json/cves/2.0
"""
import json
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
API_KEY = (os.environ.get("NVD_API_KEY") or "").strip() or None
DELAY = 0.8 if API_KEY else 6.5

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


def total_results(params):
    url = API + "?" + urllib.parse.urlencode(dict(params, resultsPerPage=1))
    headers = {"User-Agent": "cve-explorer/1.0"}
    if API_KEY:
        headers["apiKey"] = API_KEY
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r).get("totalResults", 0)
        except Exception as e:
            if attempt == 3:
                raise
            print(f"  retry ({e}) ...")
            time.sleep(DELAY * (attempt + 2))
    return 0


def main():
    rows = []
    for cwe, name in CWES:
        n = total_results({"cweId": cwe})
        rows.append({"cwe": cwe, "name": name, "count": n})
        print(f"{cwe} {name}: {n}")
        time.sleep(DELAY)
    rows.sort(key=lambda r: r["count"], reverse=True)
    out = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "source": "NVD 2.0 API (totalResults by cweId)",
        "weaknesses": rows,
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "cwe.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nWrote {len(rows)} weakness types.")


if __name__ == "__main__":
    main()
