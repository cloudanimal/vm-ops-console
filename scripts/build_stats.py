#!/usr/bin/env python3
"""Build a multi-dimensional CVE statistics cube as static JSON.

Counts are computed locally from the fkie-cad NVD mirror (see ``nvd_feed.py``)
— NVD's own enriched data on GitHub, no API key, no rate limit. For each year
we record: total CVEs, the CVSS v3 severity split, and how many are in CISA KEV.
That lets the front end slice instantly and compute the *exploitation rate*
(KEV / total) over time. We also record an all-time attack-surface profile
(network-attackable and a "wormable" AV:N/AC:L/PR:N/UI:N profile).

CVEs are bucketed by **publication year** (their ``published`` date), matching
the previous NVD-API methodology — not by the CVE-ID year of the source file.

Source: https://github.com/fkie-cad/nvd-json-data-feeds (NVD data; not endorsed
by NVD). The previous implementation used the NVD 2.0 API's ``totalResults``
count trick, which required a key for acceptable speed.
"""
import json
import os
from datetime import datetime, timezone

import nvd_feed

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
START_YEAR = 1999
END_YEAR = datetime.now(timezone.utc).year
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
WORMABLE = "AV:N/AC:L/PR:N/UI:N"


def empty_row():
    row = {"total": 0, "kev": 0}
    for s in SEVERITIES:
        row[s] = 0
    return row


def main():
    by_year = {y: empty_row() for y in range(START_YEAR, END_YEAR + 1)}
    profile = {"network": 0, "wormable": 0, "kev_total": 0}

    seen = 0
    for file_year, items in nvd_feed.iter_years(START_YEAR, END_YEAR):
        for cve in items:
            seen += 1
            pub = cve.get("published") or ""
            try:
                py = int(pub[:4])
            except ValueError:
                continue
            row = by_year.get(py)
            kev = nvd_feed.in_kev(cve)
            sev, vec = nvd_feed.best_v3(cve)
            if kev:
                profile["kev_total"] += 1
            if vec:
                if "AV:N" in vec:
                    profile["network"] += 1
                if WORMABLE in vec:
                    profile["wormable"] += 1
            if row is None:  # published outside the emitted range; counted only in profile
                continue
            row["total"] += 1
            if sev in SEVERITIES:
                row[sev] += 1
            if kev:
                row["kev"] += 1
        print(f"  CVE-{file_year} file: {len(items)} records (running total {seen})")

    severity_totals = {s: sum(by_year[y][s] for y in by_year) for s in SEVERITIES}
    out = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "source": "fkie-cad NVD mirror (counted locally)",
        "note": "NVD data via the fkie-cad GitHub mirror; no NVD API key. CVEs "
                "are bucketed by publication year. Severity buckets use the "
                "primary CVSS v3 base severity (CVEs without a v3 score are "
                "absent from the split). KEV counts use the CISA KEV enrichment "
                "(cisaExploitAdd) carried in the NVD record.",
        "dimensions": ["total"] + SEVERITIES + ["kev"],
        "grand_total": sum(by_year[y]["total"] for y in by_year),
        "by_year": by_year,
        "severity_totals": severity_totals,
        "profile": profile,
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "stats.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nGrand total {START_YEAR}-{END_YEAR}: {out['grand_total']} CVEs; "
          f"network={profile['network']} wormable={profile['wormable']} "
          f"kev_total={profile['kev_total']}")


if __name__ == "__main__":
    main()
