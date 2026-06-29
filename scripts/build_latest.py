#!/usr/bin/env python3
"""Build data/latest.json — the newest CVEs by publication date, from the
fkie-cad NVD mirror (see nvd_feed.py). The in-app "Latest CVEs" view reads this
static file instead of hammering the rate-limited NVD API from the browser
(which fails with "Load failed"). No API key, no rate limit.

Each record is slimmed to what the front end renders: id, published,
lastModified, the English description, CVSS metrics, and the CISA-KEV add date.
"""
import json
import os
from datetime import datetime, timezone, timedelta

import nvd_feed

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
WINDOW_DAYS = 35      # keep enough history for the UI's 1/7/14/30-day filters
CAP = 3000            # newest-N safety cap


def slim(cve):
    en = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            en = d.get("value", ""); break
    rec = {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "descriptions": [{"lang": "en", "value": en}],
        "metrics": cve.get("metrics", {}),
    }
    if cve.get("cisaExploitAdd"):
        rec["cisaExploitAdd"] = cve["cisaExploitAdd"]
    return rec


def main():
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=WINDOW_DAYS)).strftime("%Y-%m-%d")
    recs = []
    for year in (now.year, now.year - 1):   # prev year covers the early-January boundary
        try:
            items = nvd_feed.load_year(year)
        except Exception as e:
            print(f"  skip {year}: {e}"); continue
        for c in items:
            pub = (c.get("published") or "")[:10]
            if pub and pub >= cutoff:
                recs.append(slim(c))
    recs.sort(key=lambda r: r.get("published") or "", reverse=True)
    recs = recs[:CAP]
    out = {
        "updated": now.strftime("%Y-%m-%d"),
        "count": len(recs),
        "source": "fkie-cad NVD mirror (newest by publication date)",
        "window_days": WINDOW_DAYS,
        "cves": recs,
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "latest.json"), "w") as f:
        json.dump(out, f)
    print(f"Wrote {len(recs)} CVEs to latest.json (published since {cutoff}).")


if __name__ == "__main__":
    main()
