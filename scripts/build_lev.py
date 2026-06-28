#!/usr/bin/env python3
"""Compute LEV (Likely Exploited Vulnerabilities) per NIST CSWP 41 into static JSON.

LEV estimates the probability a CVE has *already* been exploited at some point,
by combining its EPSS scores across 30-day windows over its lifetime:

    LEV(v) = 1 - product over windows of (1 - epss_window)

EPSS only exposes the last 30 days live, and the full daily history is large, so
this runs server-side: it downloads one EPSS snapshot per 30-day window since EPSS
began (2021-04-14), accumulates the complement product per CVE, and writes one file
per year under data/lev/. The app reads them same-origin.

LEV is a lower-bound estimate by design (NIST CSWP 41). Coverage starts ~2021.
"""

from __future__ import annotations

import gzip
import io
import json
import sys
import time
from datetime import date, timedelta
from pathlib import Path

import requests

SNAPSHOT_URL = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"
EPSS_START = date(2021, 4, 14)   # first public EPSS daily snapshot
WINDOW_DAYS = 30
OUT_DIR = Path(__file__).resolve().parent.parent / "data" / "lev"
HEADERS = {"User-Agent": "cve-patch-lookup/1.0"}


def snapshot_dates(until: date):
    d = EPSS_START
    while d <= until:
        yield d
        d += timedelta(days=WINDOW_DAYS)


def fetch_snapshot(d: date):
    """Return dict cve->epss for a snapshot date, trying a few days if missing."""
    for offset in range(0, 4):
        day = d + timedelta(days=offset)
        url = SNAPSHOT_URL.format(d=day.isoformat())
        try:
            r = requests.get(url, headers=HEADERS, timeout=120)
            if r.status_code == 404:
                continue
            r.raise_for_status()
            scores = {}
            with gzip.open(io.BytesIO(r.content), "rt") as fh:
                next(fh, None)  # model_version comment line
                next(fh, None)  # header line
                for line in fh:
                    parts = line.split(",")
                    if len(parts) >= 2:
                        try:
                            scores[parts[0]] = float(parts[1])
                        except ValueError:
                            pass
            return day, scores
        except requests.RequestException as e:
            print(f"  warn: {url} ({e})", file=sys.stderr)
            return None, {}
    return None, {}


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    today = date.today()
    not_exploited = {}   # cve -> running product of (1 - epss)
    used = 0

    for d in snapshot_dates(today):
        actual, scores = fetch_snapshot(d)
        if not scores:
            continue
        used += 1
        for cve, epss in scores.items():
            p = max(0.0, min(1.0, epss))
            not_exploited[cve] = not_exploited.get(cve, 1.0) * (1.0 - p)
        print(f"{actual}: {len(scores)} scores  (snapshot {used})")
        time.sleep(0.2)

    by_year = {}
    for cve, prod in not_exploited.items():
        lev = round(1.0 - prod, 4)
        if lev <= 0:
            continue
        try:
            year = int(cve.split("-")[1])
        except (IndexError, ValueError):
            continue
        by_year.setdefault(year, {})[cve] = lev

    for year, mapping in sorted(by_year.items()):
        (OUT_DIR / f"{year}.json").write_text(json.dumps(dict(sorted(mapping.items())), separators=(",", ":")))
        print(f"wrote {year}.json: {len(mapping)} CVEs")

    index = {
        "updated": today.isoformat(),
        "method": "NIST CSWP 41 LEV, 30-day windows",
        "epss_start": EPSS_START.isoformat(),
        "snapshots_used": used,
        "years": sorted(by_year.keys()),
        "total_cves": sum(len(v) for v in by_year.values()),
    }
    (OUT_DIR / "index.json").write_text(json.dumps(index, indent=2))
    print(f"index: {index['total_cves']} CVEs, {used} snapshots")


if __name__ == "__main__":
    main()
