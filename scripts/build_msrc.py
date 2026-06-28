#!/usr/bin/env python3
"""Build CVE -> Microsoft KB mappings from the MSRC CVRF API into static JSON.

The MSRC API has no CORS headers, so the browser app cannot call it directly.
This script runs server-side (locally or in GitHub Actions), pulls every monthly
security-update document, and writes one JSON file per year:

    data/msrc/2025.json  ->  { "CVE-2025-32712": ["KB5060118", ...], ... }

The app then reads those static files same-origin from GitHub Pages. Each KB
links out to the Microsoft Update Catalog for the actual download.
"""

from __future__ import annotations

import json
import re
import sys
import time
from datetime import date
from pathlib import Path

import requests

API = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month}"
HEADERS = {"Accept": "application/json", "User-Agent": "cve-patch-lookup/1.0"}
START_YEAR, START_MONTH = 2016, 4  # MSRC CVRF coverage begins 2016-Apr
KB_RE = re.compile(r"^\d{6,7}$")
OUT_DIR = Path(__file__).resolve().parent.parent / "data" / "msrc"


def months(until: date):
    y, m = START_YEAR, START_MONTH
    while (y, m) <= (until.year, until.month):
        yield y, m
        m += 1
        if m > 12:
            m, y = 1, y + 1


def month_tag(y: int, m: int) -> str:
    return date(y, m, 1).strftime("%Y-%b")  # e.g. 2025-Jun


def kbs_for_vuln(vuln: dict) -> list[str]:
    found = set()
    for rem in vuln.get("Remediations", []):
        desc = (rem.get("Description") or {}).get("Value", "")
        if KB_RE.match(str(desc).strip()):
            found.add("KB" + str(desc).strip())
    return sorted(found)


def fetch_month(y: int, m: int) -> dict:
    url = API.format(month=month_tag(y, m))
    for attempt in range(3):
        try:
            r = requests.get(url, headers=HEADERS, timeout=60)
            if r.status_code == 404:
                return {}
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            if attempt == 2:
                print(f"  warn: {month_tag(y, m)} failed ({e})", file=sys.stderr)
                return {}
            time.sleep(2)
    return {}


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    today = date.today()
    by_year: dict[int, dict[str, list[str]]] = {}

    for y, m in months(today):
        doc = fetch_month(y, m)
        vulns = doc.get("Vulnerability", []) if doc else []
        if not vulns:
            continue
        added = 0
        for v in vulns:
            cve = v.get("CVE")
            if not cve:
                continue
            kbs = kbs_for_vuln(v)
            if not kbs:
                continue
            year = int(cve.split("-")[1]) if cve.count("-") >= 2 else y
            bucket = by_year.setdefault(year, {})
            existing = set(bucket.get(cve, []))
            existing.update(kbs)
            bucket[cve] = sorted(existing)
            added += 1
        print(f"{month_tag(y, m)}: {added} CVEs with KBs")
        time.sleep(0.3)

    for year, mapping in sorted(by_year.items()):
        path = OUT_DIR / f"{year}.json"
        path.write_text(json.dumps(dict(sorted(mapping.items())), separators=(",", ":")))
        print(f"wrote {path.name}: {len(mapping)} CVEs")

    index = {
        "updated": today.isoformat(),
        "years": sorted(by_year.keys()),
        "total_cves": sum(len(v) for v in by_year.values()),
    }
    (OUT_DIR / "index.json").write_text(json.dumps(index, indent=2))
    print(f"index: {index['total_cves']} CVEs across {len(by_year)} years")


if __name__ == "__main__":
    main()
