#!/usr/bin/env python3
"""Build the EPSS exploitability distribution as static JSON.

EPSS (Exploit Prediction Scoring System) gives every CVE a probability of
being exploited in the next 30 days. The full daily dataset is one gzipped
CSV, so we can summarize the whole corpus locally: a histogram of scores and
cumulative "how many CVEs are at least this likely to be exploited" buckets.

This powers the "likely exploitable" lens in the statistics explorer, the
predictive complement to CISA KEV's confirmed-exploited list.

Source: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz (FIRST EPSS)
"""
import gzip
import io
import json
import os
import urllib.request
from datetime import datetime, timezone

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
# Cumulative thresholds for the headline "likely exploitable" stats.
THRESHOLDS = [
    (0.9, "Very high (>=90%)"),
    (0.5, "High (>=50%)"),
    (0.1, "Elevated (>=10%)"),
    (0.01, "Non-trivial (>=1%)"),
]
HIST_BINS = 20  # 0.05-wide buckets across 0..1


def fetch_rows():
    req = urllib.request.Request(EPSS_URL, headers={"User-Agent": "cve-explorer/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    text = gzip.GzipFile(fileobj=io.BytesIO(data)).read().decode("utf-8", "replace")
    model_version = ""
    lines = text.splitlines()
    for line in lines:
        if line.startswith("#"):
            # e.g. "#model_version:v2026.06.15,score_date:..."
            for part in line.lstrip("#").split(","):
                if part.startswith("model_version:"):
                    model_version = part.split(":", 1)[1]
            continue
        if line.startswith("cve,"):
            continue
        yield line, model_version


def main():
    hist = [0] * HIST_BINS
    cum = {t: 0 for t, _ in THRESHOLDS}
    by_year = {}            # CVEs scored, per CVE year
    high_by_year = {}       # CVEs with EPSS >= 0.5, per CVE year
    total = 0
    model_version = ""

    for line, mv in fetch_rows():
        model_version = mv or model_version
        parts = line.split(",")
        if len(parts) < 2:
            continue
        cve = parts[0]
        try:
            epss = float(parts[1])
        except ValueError:
            continue
        total += 1
        b = min(int(epss * HIST_BINS), HIST_BINS - 1)
        hist[b] += 1
        for t, _ in THRESHOLDS:
            if epss >= t:
                cum[t] += 1
        # CVE year, for the "likely-exploitable rate by year" view
        try:
            year = cve.split("-")[1]
            by_year[year] = by_year.get(year, 0) + 1
            if epss >= 0.5:
                high_by_year[year] = high_by_year.get(year, 0) + 1
        except IndexError:
            pass

    out = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "source": "FIRST EPSS",
        "model_version": model_version,
        "total_scored": total,
        "thresholds": [
            {"t": t, "label": label, "count": cum[t]} for t, label in THRESHOLDS
        ],
        "histogram": {
            "bin_width": 1.0 / HIST_BINS,
            "bins": hist,
        },
        "by_year": dict(sorted(by_year.items())),
        "high_by_year": dict(sorted(high_by_year.items())),
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "epss_dist.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"EPSS {model_version}: {total} CVEs scored; "
          + ", ".join(f"{c['count']} {c['label']}" for c in out["thresholds"]))


if __name__ == "__main__":
    main()
