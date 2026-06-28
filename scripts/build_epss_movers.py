#!/usr/bin/env python3
"""Build "EPSS movers": the CVEs whose exploitation probability changed most
over the past week.

FIRST publishes a dated EPSS file per day, so we can diff today's scores
against a week ago, entirely self-contained (no stored baseline needed). The
biggest risers are an early-warning signal: the model now thinks these are far
more likely to be exploited than it did a week ago.

Source: https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz (FIRST EPSS)
"""
import gzip
import io
import json
import os
import time
import urllib.request
from datetime import datetime, timedelta, timezone

BASE = "https://epss.empiricalsecurity.com/epss_scores-{}.csv.gz"
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
LOOKBACK_DAYS = 7
TOP_N = 30
UA = {"User-Agent": "cve-explorer/1.0 (+https://cloudanimal.github.io/cve-explorer)"}


def load_scores(date_str):
    """Return {cve: epss} for a given date, or None if that file isn't up yet."""
    try:
        req = urllib.request.Request(BASE.format(date_str), headers={"User-Agent": "cve-explorer/1.0"})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
    except Exception:
        return None
    text = gzip.GzipFile(fileobj=io.BytesIO(data)).read().decode("utf-8", "replace")
    scores = {}
    for line in text.splitlines():
        if line.startswith("#") or line.startswith("cve,"):
            continue
        p = line.split(",")
        if len(p) < 2:
            continue
        try:
            scores[p[0]] = float(p[1])
        except ValueError:
            pass
    return scores


def first_available(start_offset):
    """EPSS files publish on a slight delay; try a few recent dates."""
    for back in range(start_offset, start_offset + 4):
        d = (datetime.now(timezone.utc).date() - timedelta(days=back)).isoformat()
        s = load_scores(d)
        if s:
            return d, s
    return None, None


# --- short product/title label per CVE, from the official CVE List (no API key, no rate limit) ---
def cvelist_url(cve):
    _, yr, num = cve.split("-")
    return "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/%s/%sxxx/%s.json" % (yr, int(num) // 1000, cve)


def label_of(rec):
    cna = (rec.get("containers") or {}).get("cna") or {}
    if cna.get("title"):
        return cna["title"][:90]
    for a in (cna.get("affected") or []):
        v, p = a.get("vendor"), a.get("product")
        if p and p not in ("n/a", "unknown"):
            return ((v + " " + p) if v and v not in ("n/a", "unknown") else p)[:90]
    for d in (cna.get("descriptions") or []):
        if (d.get("lang") or "").startswith("en") and d.get("value"):
            return d["value"][:110]
    return ""


def add_names(items, cache):
    for m in items:
        c = m["id"]
        if c not in cache:
            try:
                req = urllib.request.Request(cvelist_url(c), headers=UA)
                with urllib.request.urlopen(req, timeout=60) as r:
                    cache[c] = label_of(json.load(r))
            except Exception:
                cache[c] = ""
            time.sleep(0.03)
        m["name"] = cache[c]


def main():
    cur_date, cur = first_available(0)
    prev_date, prev = first_available(LOOKBACK_DAYS)
    if not cur or not prev:
        print("Could not fetch both EPSS snapshots; skipping movers.")
        return

    movers = []
    for cve, now in cur.items():
        then = prev.get(cve)
        if then is None:
            continue
        delta = now - then
        if delta > 0:
            movers.append({"id": cve, "now": round(now, 5), "prev": round(then, 5), "delta": round(delta, 5)})
    movers.sort(key=lambda m: m["delta"], reverse=True)

    out = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "source": "FIRST EPSS",
        "current_date": cur_date,
        "previous_date": prev_date,
        "risers": movers[:TOP_N],
        "newly_high": [m for m in movers if m["now"] >= 0.5 and m["prev"] < 0.5][:TOP_N],
    }
    # enrich the shown rows with a short product/title from the CVE List
    name_cache = {}
    add_names(out["risers"], name_cache)
    add_names(out["newly_high"], name_cache)
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "epss_movers.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"EPSS movers {prev_date} -> {cur_date}: "
          f"{len(out['risers'])} top risers, {len(out['newly_high'])} newly crossed 50%.")


if __name__ == "__main__":
    main()
