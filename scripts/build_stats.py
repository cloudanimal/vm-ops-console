#!/usr/bin/env python3
"""Build a multi-dimensional CVE statistics cube as static JSON, without
mirroring the whole NVD database.

The trick: the NVD 2.0 API returns a ``totalResults`` field for any filtered
query, so a request with ``resultsPerPage=1`` tells us how many CVEs match a
filter while transferring almost nothing. Counting CVEs across dimensions is
therefore a few hundred tiny metadata calls rather than a quarter million
records. Every number here is a real NVD count.

For each year we record: total CVEs, the CVSS v3 severity split, and how many
are in CISA KEV (``hasKev``). That lets the front end slice instantly and, in
particular, compute the *exploitation rate* (KEV / total) over time. We also
record an all-time attack-surface profile (network-attackable and a
"wormable" AV:N/AC:L/PR:N/UI:N profile).

Two NVD constraints shape the queries:
  * a publication-date range may span at most 120 days, so each year is summed
    over four quarterly windows;
  * results are cached per-query on disk (data/.cache), so an interrupted run
    resumes for free and the scheduled refresh only pays for what changed.

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
CACHE_DIR = os.path.join(OUT_DIR, ".cache")
CACHE_FILE = os.path.join(CACHE_DIR, "stats_cube.json")
START_YEAR = 1999
END_YEAR = datetime.now(timezone.utc).year
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
API_KEY = (os.environ.get("NVD_API_KEY") or "").strip() or None
DELAY = 0.8 if API_KEY else 6.5
# Quarterly windows keep every range under NVD's 120-day cap.
QUARTERS = [("01-01", "03-31"), ("04-01", "06-30"),
            ("07-01", "09-30"), ("10-01", "12-31")]

# Cache keyed by the query string; only the current year is volatile, so a
# rerun re-counts just the open year plus anything missing.
_cache = {}


def load_cache():
    global _cache
    try:
        with open(CACHE_FILE) as f:
            _cache = json.load(f)
    except (OSError, ValueError):
        _cache = {}


def save_cache():
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(_cache, f)


def total_results(params, cache_ok=True):
    key = urllib.parse.urlencode(sorted(params.items()))
    if cache_ok and key in _cache:
        return _cache[key]
    q = dict(params, resultsPerPage=1, startIndex=0)
    url = API + "?" + urllib.parse.urlencode(q)
    headers = {"User-Agent": "cve-explorer/1.0"}
    if API_KEY:
        headers["apiKey"] = API_KEY
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as r:
                n = json.load(r).get("totalResults", 0)
            _cache[key] = n
            time.sleep(DELAY)
            return n
        except Exception as e:
            if attempt == 3:
                raise
            print(f"  retry ({e}) ...")
            time.sleep(DELAY * (attempt + 2))
    return 0


def quarter_params(year, extra=None):
    for start_md, end_md in QUARTERS:
        p = {"pubStartDate": f"{year}-{start_md}T00:00:00.000",
             "pubEndDate": f"{year}-{end_md}T23:59:59.999"}
        if extra:
            p.update(extra)
        yield p


def count_year(year, extra=None, cache_ok=True):
    return sum(total_results(p, cache_ok=cache_ok)
               for p in quarter_params(year, extra))


def validate_key():
    """NVD returns 404 for a malformed/invalid apiKey, which would abort the
    whole run. Probe once; if the key is rejected, drop to unauthenticated
    mode (slower but it still completes) and say so loudly."""
    global API_KEY, DELAY
    if not API_KEY:
        print("No NVD_API_KEY set; running unauthenticated (slower).")
        return
    try:
        req = urllib.request.Request(API + "?resultsPerPage=1",
                                     headers={"User-Agent": "cve-explorer/1.0", "apiKey": API_KEY})
        with urllib.request.urlopen(req, timeout=60) as r:
            r.read()
        print("NVD API key accepted; running in fast mode.")
    except Exception as e:
        print(f"WARNING: NVD rejected the API key ({e}). "
              f"Check the NVD_API_KEY value for typos/whitespace. "
              f"Falling back to unauthenticated mode (slower).")
        API_KEY = None
        DELAY = 6.5


def main():
    validate_key()
    load_cache()
    current = datetime.now(timezone.utc).year
    by_year = {}
    for year in range(START_YEAR, END_YEAR + 1):
        # The open (current) year keeps changing, so never serve it from cache.
        fresh = (year == current)
        row = {"total": count_year(year, cache_ok=not fresh)}
        for s in SEVERITIES:
            row[s] = count_year(year, {"cvssV3Severity": s}, cache_ok=not fresh)
        row["kev"] = count_year(year, {"hasKev": ""}, cache_ok=not fresh)
        by_year[year] = row
        save_cache()  # checkpoint after each year
        print(f"{year}: total={row['total']} kev={row['kev']} "
              f"crit={row['CRITICAL']} high={row['HIGH']}")

    # All-time attack-surface profile (cheap, three calls).
    profile = {
        "network": total_results({"cvssV3Metrics": "AV:N"}),
        "wormable": total_results({"cvssV3Metrics": "AV:N/AC:L/PR:N/UI:N"}),
        "kev_total": total_results({"hasKev": ""}),
    }
    save_cache()

    severity_totals = {s: sum(by_year[y][s] for y in by_year) for s in SEVERITIES}
    out = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "source": "NVD 2.0 API (totalResults)",
        "note": "Severity buckets use CVSS v3; CVEs without a v3 score are "
                "absent from the split. KEV counts use the NVD hasKev flag.",
        "dimensions": ["total"] + SEVERITIES + ["kev"],
        "grand_total": sum(by_year[y]["total"] for y in by_year),
        "by_year": by_year,
        "severity_totals": severity_totals,
        "profile": profile,
    }
    with open(os.path.join(OUT_DIR, "stats.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nGrand total {START_YEAR}-{END_YEAR}: {out['grand_total']} CVEs; "
          f"network={profile['network']} wormable={profile['wormable']}")


if __name__ == "__main__":
    main()
