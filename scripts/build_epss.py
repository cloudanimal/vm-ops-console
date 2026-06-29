#!/usr/bin/env python3
"""Build data/epss.json.gz — the full FIRST EPSS score set ({CVE: epss_probability}).

Source: FIRST's daily EPSS bulk file (no API key, no rate limit):
  https://epss.cyentia.com/epss_scores-current.csv.gz
The CSV is: one #comment line (carries score_date), a `cve,epss,percentile` header, then rows.

Output is gzipped JSON ({cve: epss}) so the ~344k-CVE map ships small (~2.5 MB) and the app
decompresses it in-browser (DecompressionStream). EPSS then drives the Findings risk score, an
EPSS column, and a filter — for every finding, not just the drawer's live per-CVE lookup.
"""
import gzip, io, json, os, urllib.request

SRC = "https://epss.cyentia.com/epss_scores-current.csv.gz"
OUT = os.path.join(os.path.dirname(__file__), "..", "data", "epss.json.gz")


def main():
    req = urllib.request.Request(SRC, headers={"User-Agent": "vm-ops-console/build_epss"})
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = gzip.decompress(r.read())
    text = raw.decode("utf-8", "replace")

    score_date = ""
    scores = {}
    for line in text.splitlines():
        if not line:
            continue
        if line[0] == "#":
            # e.g. #model_version:v2026.06.15,score_date:2026-06-29T12:00:29Z
            for part in line[1:].split(","):
                if part.startswith("score_date:"):
                    score_date = part.split(":", 1)[1].split("T")[0]
            continue
        if line.startswith("cve,"):
            continue  # header
        c = line.split(",")
        if len(c) < 2 or not c[0].startswith("CVE-"):
            continue
        try:
            e = float(c[1])
        except ValueError:
            continue
        if e > 0:                       # skip 0.0 scores — absence == 0, saves ~1/3 of the file
            scores[c[0]] = round(e, 5)

    payload = {"updated": score_date, "source": "FIRST EPSS", "count": len(scores), "scores": scores}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with gzip.open(OUT, "wt", encoding="utf-8") as f:
        json.dump(payload, f, separators=(",", ":"))
    print("wrote", OUT, "—", len(scores), "CVEs, score_date", score_date)


if __name__ == "__main__":
    main()
