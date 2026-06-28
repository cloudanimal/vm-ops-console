#!/usr/bin/env python3
"""Build data/ubuntu/<year>.json — per-CVE Ubuntu fix status.

The Ubuntu Security Team tracks, for every CVE that affects an Ubuntu package,
the fix status per release (focal, jammy, noble, …). The data is public and free
(https://ubuntu.com/security/cves/<CVE>.json) but the site sends no CORS header,
so the browser can't fetch it directly — we pre-build it here, the same way the
MSRC and LEV datasets are built, and the detail page reads the static JSON.

Scope: the CVEs the app actually surfaces — the union of the KEV catalog and the
aggregated known-exploited feed — so the dataset stays bounded. Results (including
"not tracked") are cached in data/.ubuntu_cache.json so reruns are cheap.
"""
import json
import os
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

WORKERS = 8

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
OUT_DIR = os.path.join(DATA, "ubuntu")
CACHE = os.path.join(DATA, ".ubuntu_cache.json")
UA = {"User-Agent": "cve-explorer/1.0 (+https://cloudanimal.github.io/cve-explorer)"}
KEEP_STATUS = {"released", "needed", "deferred", "pending", "not-affected", "ignored"}


def candidate_cves():
    cves = set()
    kev = os.path.join(DATA, "kev.json")
    if os.path.exists(kev):
        for e in json.load(open(kev)).get("entries", []):
            if e.get("id"):
                cves.add(e["id"])
    exp = os.path.join(DATA, "exploited.json")
    if os.path.exists(exp):
        for c in json.load(open(exp)).get("cves", []):
            if c.get("cve"):
                cves.add(c["cve"])
    return sorted(cves)


def fetch(cve):
    """Return a compact {priority, packages:[...]} dict, or None if Ubuntu doesn't track it."""
    url = "https://ubuntu.com/security/cves/%s.json" % cve
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=60) as r:
            d = json.load(r)
    except Exception:
        return None
    pkgs = []
    for p in (d.get("packages") or []):
        rels = {}
        for s in (p.get("statuses") or []):
            cn, st = s.get("release_codename"), s.get("status")
            if cn and st and st in KEEP_STATUS:
                rels[cn] = st
        if rels:
            pkgs.append({"name": p.get("name", ""), "releases": rels})
    if not pkgs:
        return None
    return {"priority": d.get("priority") or "", "packages": pkgs[:12]}


def main():
    cache = {}
    if os.path.exists(CACHE):
        try:
            cache = json.load(open(CACHE))
        except Exception:
            cache = {}
    cves = candidate_cves()
    todo = [c for c in cves if c not in cache]
    print("Ubuntu tracker: %d candidates, %d cached, %d to fetch (with %d workers)" % (len(cves), len(cache), len(todo), WORKERS), flush=True)
    done = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(fetch, c): c for c in todo}
        for fut in as_completed(futures):
            c = futures[fut]
            try:
                cache[c] = fut.result()    # may be None (not tracked) — cached so we don't refetch
            except Exception:
                cache[c] = None
            done += 1
            if done % 500 == 0:
                json.dump(cache, open(CACHE, "w"))
                print("  …%d/%d" % (done, len(todo)), flush=True)
    json.dump(cache, open(CACHE, "w"))

    by_year = defaultdict(dict)
    hits = 0
    for c in cves:
        info = cache.get(c)
        if not info:
            continue
        hits += 1
        try:
            yr = c.split("-")[1]
        except Exception:
            continue
        by_year[yr][c] = info

    os.makedirs(OUT_DIR, exist_ok=True)
    for yr, m in by_year.items():
        with open(os.path.join(OUT_DIR, yr + ".json"), "w") as f:
            json.dump(m, f, separators=(",", ":"))
    print("Wrote %d per-year files; %d of %d CVEs are tracked by Ubuntu." % (len(by_year), hits, len(cves)))


if __name__ == "__main__":
    main()
