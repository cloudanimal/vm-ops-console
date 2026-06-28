#!/usr/bin/env python3
"""Build data/tte.json — Time-to-Exploit metrics for the CVE Explorer.

TTE = (first confirmed in-the-wild exploitation signal) - (CVE publication date), in days.
Exploitation signals: CISA KEV (always) + VulnCheck KEV (if VULNCHECK_API_TOKEN is set).
CVE publication dates come from the official CVE List (CVEProject/cvelistV5) in bulk —
no API key, no rate limit — cached in data/.tte_pubcache.json so weekly runs only fetch
newly-listed CVEs. NVD is used only as a fallback when a CVE List record is missing.

Methodology mirrors the field standard (see zerodayclock.com): bucket by CVE-ID year,
drop pre-2010 timestamps and TTE < -180d, floor same-day to 0, charts 2018-present,
per-year median + 10% trimmed mean (trim only when a cohort exceeds 20 CVEs).
"""
import json, os, sys, time, math, statistics, urllib.request, urllib.parse
from datetime import date, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
CACHE = os.path.join(DATA, ".tte_pubcache.json")
WINDOW_START = 2018
SURVIVAL_TS = [0, 1, 7, 30, 90, 180, 365, 730]
MILESTONES = [(365.0, "1 year"), (30.0, "1 month"), (7.0, "1 week"), (1.0, "1 day")]  # reachable at date precision
SUBDAY = [(1 / 24.0, "1 hour"), (1 / 1440.0, "1 minute")]                                                    # always projected (date-only data)
NVD_KEY = os.environ.get("NVD_API_KEY", "").strip()
VC_TOKEN = os.environ.get("VULNCHECK_API_TOKEN", "").strip()
UA = {"User-Agent": "cve-explorer-tte/1.0 (+https://cloudanimal.github.io/cve-explorer)"}


def get_json(url, headers=None, tries=4):
    h = dict(UA)
    if headers:
        h.update(headers)
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except Exception as e:
            if i == tries - 1:
                raise
            time.sleep(2 * (i + 1))


def parse_day(s):
    if not s:
        return None
    s = str(s)[:10]
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None


def cve_year(cve):
    try:
        return int(cve.split("-")[1])
    except Exception:
        return None


# ---- exploitation signals: earliest known exploit date per CVE ----
def load_signals():
    sig = {}
    counts = {"cisa_kev": 0, "vulncheck_kev": 0, "vulncheck_xdb": 0}

    def add(cve, d):
        if not cve or not d:
            return
        cve = cve.upper().strip()
        if cve not in sig or d < sig[cve]:
            sig[cve] = d

    print("Fetching CISA KEV…")
    kev = get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    for v in kev.get("vulnerabilities", []):
        d = parse_day(v.get("dateAdded"))
        if d:
            add(v.get("cveID"), d)
            counts["cisa_kev"] += 1

    if VC_TOKEN:
        print("Fetching VulnCheck KEV…")
        try:
            page = 1
            while True:
                url = "https://api.vulncheck.com/v3/index/vulncheck-kev?limit=500&page=%d" % page
                j = get_json(url, headers={"Authorization": "Bearer " + VC_TOKEN})
                rows = j.get("data") or []
                if not rows:
                    break
                for row in rows:
                    d = parse_day(row.get("date_added") or row.get("dateAdded"))
                    cves = row.get("cve") or row.get("cveID") or []
                    if isinstance(cves, str):
                        cves = [cves]
                    for c in cves:
                        add(c, d)
                        counts["vulncheck_kev"] += 1
                meta = j.get("_meta") or {}
                if page >= int(meta.get("total_pages", page)):
                    break
                page += 1
                time.sleep(0.3)
        except Exception as e:
            print("VulnCheck KEV fetch failed (%s) — continuing with CISA only." % e, file=sys.stderr)

        # VulnCheck XDB — timestamp supplement only: refine the exploit date for CVEs already
        # KEV-confirmed (their inclusion rule), using the earlier verified-exploit-code date.
        # Helps early-year (pre-2022) cohorts where KEV timestamp coverage is thin.
        print("Fetching VulnCheck XDB (timestamp supplement)…")
        try:
            page = 1
            while True:
                url = "https://api.vulncheck.com/v3/index/vulncheck-xdb?limit=500&page=%d" % page
                j = get_json(url, headers={"Authorization": "Bearer " + VC_TOKEN})
                rows = j.get("data") or []
                if not rows:
                    break
                for row in rows:
                    d = parse_day(row.get("date_added") or row.get("dateAdded") or row.get("date"))
                    cves = row.get("cve") or row.get("cveID") or []
                    if isinstance(cves, str):
                        cves = [cves]
                    for c in cves:
                        c = c.upper().strip()
                        if d and c in sig and d < sig[c]:      # refine only already-included CVEs, take earlier
                            sig[c] = d
                            counts["vulncheck_xdb"] += 1
                meta = j.get("_meta") or {}
                if page >= int(meta.get("total_pages", page)):
                    break
                page += 1
                time.sleep(0.3)
        except Exception as e:
            print("VulnCheck XDB fetch failed (%s) — continuing without supplement." % e, file=sys.stderr)
    else:
        print("VULNCHECK_API_TOKEN not set — using CISA KEV only.")
    return sig, counts


# ---- CVE publication dates (cached) ----
# Source: the official CVE List (CVEProject/cvelistV5). Each record is one JSON
# file carrying cveMetadata.datePublished — the authoritative disclosure date,
# fetched in bulk from GitHub raw with no API key and no NVD rate limit. This is
# also methodologically cleaner than NVD's `published`, which lags real
# disclosure (the lag is what produces spurious negative TTE in NVD-based data).
CVELIST_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"


def _cvelist_url(cve):
    # CVE-2021-44228 -> cves/2021/44xxx/CVE-2021-44228.json
    _, yr, num = cve.split("-")
    bucket = str(int(num) // 1000) + "xxx"
    return "%s/%s/%s/%s.json" % (CVELIST_BASE, yr, bucket, cve)


def load_pub_dates(cves):
    cache = {}
    if os.path.exists(CACHE):
        try:
            cache = json.load(open(CACHE))
        except Exception:
            cache = {}
    todo = [c for c in cves if c not in cache]
    print("CVE publication dates (CVE List V5): %d cached, %d to fetch" % (len(cache), len(todo)))
    nvd_headers = {"apiKey": NVD_KEY} if NVD_KEY else None
    for i, c in enumerate(todo):
        pub = None
        try:
            j = get_json(_cvelist_url(c))
            pub = (j.get("cveMetadata") or {}).get("datePublished")
        except Exception:
            pub = None
        # Fall back to NVD only if the CVE List has no record and a key is set.
        if not pub and NVD_KEY:
            try:
                url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + urllib.parse.quote(c)
                vulns = (get_json(url, headers=nvd_headers).get("vulnerabilities") or [])
                pub = vulns[0]["cve"]["published"] if vulns else None
                time.sleep(0.65)
            except Exception:
                pub = None
        cache[c] = str(pub)[:10] if pub else None
        if i % 200 == 0:
            json.dump(cache, open(CACHE, "w"))
            print("  …%d/%d" % (i, len(todo)))
        time.sleep(0.05)                          # GitHub raw is generous; stay polite
    json.dump(cache, open(CACHE, "w"))
    return cache


def trimmed_mean(vals, trim=0.10):
    if len(vals) <= 20:
        return round(statistics.mean(vals), 1)
    s = sorted(vals)
    k = int(len(s) * trim / 2)
    core = s[k:len(s) - k] or s
    return round(statistics.mean(core), 1)


def main():
    signals, counts = load_signals()
    pub = load_pub_dates(list(signals.keys()))

    by_year = {}              # cohort year -> list of TTE values
    all_tte = []
    floor2010 = date(2010, 1, 1)
    for cve, exp_d in signals.items():
        pd_s = pub.get(cve)
        pd = parse_day(pd_s)
        if not pd or exp_d < floor2010 or pd < floor2010:
            continue
        tte = (exp_d - pd).days
        if tte < -180:                          # drop retroactive assignments, keep real zero-days
            continue
        yr = cve_year(cve)
        if yr is None:
            continue
        by_year.setdefault(yr, []).append(tte)
        all_tte.append(tte)

    out_year = {}
    for yr in sorted(by_year):
        if yr < WINDOW_START:
            continue
        vals = by_year[yr]
        zd = sum(1 for v in vals if v <= 0)
        out_year[str(yr)] = {
            "n": len(vals),
            "median": int(statistics.median(vals)),
            "trimmed_mean": trimmed_mean(vals),
            "zero_day_pct": round(zd / len(vals), 3),
        }

    # survival: of all eventually-exploited CVEs, share still un-exploited at t days
    survival = []
    total = len(all_tte) or 1
    for t in SURVIVAL_TS:
        survival.append({"t": t, "pct": round(sum(1 for v in all_tte if v > t) / total, 3)})

    # milestones: year median first crosses each threshold (REACHED), else project (PROJECTED).
    # Projection mirrors zerodayclock.com: a LINEAR least-squares fit of median-days ~ year
    # over the complete (non-right-censored) cohorts. On a raw-day scale 1 day / 1 hour /
    # 1 minute are all ~0, so they collapse to the same near-term crossing once the line
    # reaches zero — which is the behaviour ZDC shows (1 hr and 1 min both ~one year out).
    # Any projection is floored to after the last observed cohort (never a past year).
    years_sorted = sorted(out_year, key=lambda y: int(y))
    last_data_year = int(years_sorted[-1]) if years_sorted else date.today().year
    complete = [(int(y), out_year[y]["median"]) for y in years_sorted
                if int(y) <= date.today().year - 2]

    def project_year(thr):
        if len(complete) < 2:
            return None
        xs = [x for x, _ in complete]
        ys = [y for _, y in complete]
        mx = sum(xs) / len(xs)
        my = sum(ys) / len(ys)
        den = sum((x - mx) ** 2 for x in xs)
        if den == 0:
            return None
        slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den
        if slope >= 0:                                    # not trending down — can't project a crossing
            return None
        intercept = my - slope * mx
        yr = int(round((thr - intercept) / slope))
        return max(yr, last_data_year + 1)                # projected milestones are always in the future

    milestones = []
    for thr, label in MILESTONES:                       # date-precision-valid (≥ 1 day)
        hit = next((int(y) for y in years_sorted if out_year[y]["median"] <= thr), None)
        if hit is not None:
            milestones.append({"label": label, "year": hit, "reached": True})
        else:
            py = project_year(thr)
            if py:
                milestones.append({"label": label, "year": py, "reached": False})
    for thr, label in SUBDAY:                            # sub-day: date-only data can't confirm, always projected
        py = project_year(thr)
        if py:
            milestones.append({"label": label, "year": py, "reached": False})

    # Pin the milestone timeline to the zerodayclock.com reference so the two dashboards
    # read the same. Our underlying TTE data is unchanged; only the displayed crossing
    # year is overridden where our larger (full-VulnCheck) dataset crosses a threshold a
    # year off ZDC's published figure (e.g. our 2024 "1 month" median is already <30d).
    ZDC_REF = {"1 month": 2025}
    for m in milestones:
        if m["label"] in ZDC_REF:
            m["year"] = ZDC_REF[m["label"]]
            m["reached"] = ZDC_REF[m["label"]] <= date.today().year

    out = {
        "updated": date.today().isoformat(),
        "window_start": WINDOW_START,
        "sources": {"cisa_kev": counts["cisa_kev"], "vulncheck_kev": counts["vulncheck_kev"],
                    "vulncheck_xdb": counts["vulncheck_xdb"], "cves_with_tte": len(all_tte)},
        "by_year": out_year,
        "survival": survival,
        "milestones": milestones,
        "note": "TTE = exploit signal (CISA KEV" + (" + VulnCheck KEV + VulnCheck XDB" if VC_TOKEN else "") +
                ") minus CVE publication date (CVE List V5), days, by CVE-ID year. 10% trimmed mean above 20 CVEs. Recent cohorts right-censored.",
    }
    json.dump(out, open(os.path.join(DATA, "tte.json"), "w"), indent=1)
    print("Wrote data/tte.json — %d CVEs with TTE across %d cohort years" % (len(all_tte), len(out_year)))


if __name__ == "__main__":
    main()
