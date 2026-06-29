#!/usr/bin/env python3
"""Build data/exploited.json — the VM Ops Console CVE dataset (zerodayclock.com/explorer style).

A per-CVE table of CVEs with known exploits/PoCs aggregated across multiple public
sources, enriched with publication date, CVSS, severity, product, and time-to-exploit.

Sources (each contributes CVE -> earliest exploit/PoC date):
  - cisa-kev        CISA Known Exploited Vulnerabilities (dateAdded)
  - vulncheck-kev   VulnCheck KEV            (VULNCHECK_API_TOKEN)
  - vulncheck-xdb   VulnCheck XDB exploits   (VULNCHECK_API_TOKEN)
  - exploitdb       Exploit-DB files_exploits.csv (date_published)
  - metasploit      Metasploit modules_metadata_base.json (disclosure_date)
  - google-p0       Google Project Zero 0days-in-the-wild (best effort)
  - nvd-exploit-ref CVE List references tagged "exploit" (from the enrichment fetch)

Enrichment + publication dates come from the official CVE List (CVEProject/cvelistV5),
cached in data/.explorer_cache.json. To stay static-site-friendly the candidate set is
limited to recently-disclosed CVEs plus everything in a confirmed-exploited source.
"""
import json, os, sys, re, csv, io, time, urllib.request
from datetime import date, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
CACHE = os.path.join(DATA, ".explorer_cache.json")
VC_TOKEN = os.environ.get("VULNCHECK_API_TOKEN", "").strip()
RECENT_FROM = date.today().year - 2        # include CVEs disclosed in the last ~3 years…
MAX_ROWS = 6000                            # …plus all confirmed-exploited; capped to keep the JSON small
UA = {"User-Agent": "cve-explorer/1.0 (+https://cloudanimal.github.io/cve-explorer)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def _open(url, headers=None):
    h = dict(UA); h.update(headers or {})
    return urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=90)


def get_json(url, headers=None, tries=4):
    for i in range(tries):
        try:
            with _open(url, headers) as r:
                return json.load(r)
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(2 * (i + 1))


def get_text(url, tries=3):
    for i in range(tries):
        try:
            with _open(url) as r:
                return r.read().decode("utf-8", "replace")
        except Exception:
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


# ---------------- source loaders: cve -> earliest signal date ----------------
def add(d, cve, day):
    cve = cve.upper().strip()
    if not CVE_RE.fullmatch(cve):
        return
    if cve not in d or (day and (d[cve] is None or day < d[cve])):
        d[cve] = day


def src_cisa():
    out = {}
    j = get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    for v in j.get("vulnerabilities", []):
        add(out, v.get("cveID", ""), parse_day(v.get("dateAdded")))
    return out


def src_vulncheck(index):
    out = {}
    page = 1
    while True:
        url = "https://api.vulncheck.com/v3/index/%s?limit=500&page=%d" % (index, page)
        j = get_json(url, headers={"Authorization": "Bearer " + VC_TOKEN})
        rows = j.get("data") or []
        if not rows:
            break
        for row in rows:
            day = parse_day(row.get("date_added") or row.get("dateAdded") or row.get("date"))
            cves = row.get("cve") or row.get("cveID") or []
            for c in ([cves] if isinstance(cves, str) else cves):
                add(out, c, day)
        meta = j.get("_meta") or {}
        if page >= int(meta.get("total_pages", page)):
            break
        page += 1
        time.sleep(0.3)
    return out


def src_exploitdb():
    out = {}
    txt = get_text("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv")
    for row in csv.DictReader(io.StringIO(txt)):
        day = parse_day(row.get("date_published") or row.get("date"))
        for m in CVE_RE.findall(row.get("codes") or ""):
            add(out, m, day)
    return out


def src_metasploit():
    out = {}
    j = get_json("https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json")
    for mod in j.values():
        day = parse_day(mod.get("disclosure_date"))
        for ref in (mod.get("references") or []):
            for m in CVE_RE.findall(str(ref)):
                add(out, m, day)
    return out


def src_googlep0():
    # Google Project Zero tracks in-the-wild 0-days as per-CVE root-cause analyses; the
    # 0day-RCAs/ directory listing gives the CVE ids. No date in the listing (signal only).
    out = {}
    try:
        j = get_json("https://api.github.com/repos/googleprojectzero/0days-in-the-wild/git/trees/main?recursive=1")
    except Exception:
        return out
    for node in (j.get("tree") or []):
        p = node.get("path") or ""
        if "0day-RCAs/" in p:
            for m in CVE_RE.findall(p):
                add(out, m, None)
    return out


def src_nomisec():
    # nomi-sec/PoC-in-GitHub catalogs CVEs that have a public proof-of-concept repo on
    # GitHub, organised as {year}/{CVE}.json. We list the filenames per year (signal only,
    # no reliable date) via the git tree API — same approach as Google P0.
    out = {}
    try:
        root = get_json("https://api.github.com/repos/nomi-sec/PoC-in-GitHub/git/trees/master")
    except Exception:
        return out
    years = [t for t in (root.get("tree") or []) if t.get("type") == "tree" and re.fullmatch(r"\d{4}", t.get("path", ""))]
    for yr in years:
        try:
            tr = get_json("https://api.github.com/repos/nomi-sec/PoC-in-GitHub/git/trees/" + yr["sha"])
        except Exception:
            continue
        for node in (tr.get("tree") or []):
            for m in CVE_RE.findall(node.get("path") or ""):
                add(out, m, None)
        time.sleep(0.1)
    return out


SOURCES = [
    ("cisa-kev", src_cisa, False),
    ("exploitdb", src_exploitdb, False),
    ("metasploit", src_metasploit, False),
    ("google-p0", src_googlep0, False),
    ("nomi-sec", src_nomisec, False),
    ("vulncheck-kev", lambda: src_vulncheck("vulncheck-kev"), True),
    ("vulncheck-xdb", lambda: src_vulncheck("vulncheck-xdb"), True),
]
CONFIRMED = {"cisa-kev", "vulncheck-kev", "vulncheck-xdb"}   # confirmed in-the-wild → always kept regardless of age


# ---------------- enrichment from the official CVE List ----------------
def cvelist_url(cve):
    _, yr, num = cve.split("-")
    return "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/%s/%sxxx/%s.json" % (yr, int(num) // 1000, cve)


def best_cvss(rec):
    best = (None, None)
    cna = (rec.get("containers") or {}).get("cna") or {}
    adp = (rec.get("containers") or {}).get("adp") or []
    metric_sets = [cna.get("metrics") or []] + [a.get("metrics") or [] for a in adp]
    for ms in metric_sets:
        for m in ms:
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                d = m.get(key)
                if d and d.get("baseScore") is not None:
                    if best[0] is None or d["baseScore"] > best[0]:
                        best = (d.get("baseScore"), (d.get("baseSeverity") or "").upper())
    return best


def sev_from_score(s):
    if s is None:
        return ""
    return "CRITICAL" if s >= 9 else "HIGH" if s >= 7 else "MEDIUM" if s >= 4 else "LOW" if s > 0 else "NONE"


def product_of(rec):
    cna = (rec.get("containers") or {}).get("cna") or {}
    if cna.get("title"):
        return cna["title"][:120]
    for a in (cna.get("affected") or []):
        v, p = a.get("vendor"), a.get("product")
        if p and p not in ("n/a", "unknown"):
            return ((v + " " + p) if v and v not in ("n/a", "unknown") else p)[:120]
    for d in (cna.get("descriptions") or []):
        if (d.get("lang") or "").startswith("en") and d.get("value"):
            return d["value"][:120]
    return ""


def enrich(cves):
    cache = {}
    if os.path.exists(CACHE):
        try:
            cache = json.load(open(CACHE))
        except Exception:
            cache = {}
    todo = [c for c in cves if c not in cache]
    print("Enriching from CVE List V5: %d cached, %d to fetch" % (len(cache), len(todo)))
    for i, c in enumerate(todo):
        info = {"pub": None, "cvss": None, "sev": "", "product": "", "exploit_ref": False}
        try:
            rec = get_json(cvelist_url(c))
            info["pub"] = str((rec.get("cveMetadata") or {}).get("datePublished") or "")[:10] or None
            score, sev = best_cvss(rec)
            info["cvss"] = score
            info["sev"] = sev or sev_from_score(score)
            info["product"] = product_of(rec)
            refs = ((rec.get("containers") or {}).get("cna") or {}).get("references") or []
            info["exploit_ref"] = any("exploit" in (t.lower() for t in (r.get("tags") or [])) for r in refs)
        except Exception:
            pass
        cache[c] = info
        if i % 250 == 0:
            json.dump(cache, open(CACHE, "w")); print("  …%d/%d" % (i, len(todo)))
        time.sleep(0.05)
    json.dump(cache, open(CACHE, "w"))
    return cache


def main():
    per_src = {}
    present = []
    for name, fn, needs_token in SOURCES:
        if needs_token and not VC_TOKEN:
            print("%-14s skipped (no VULNCHECK_API_TOKEN)" % name); continue
        try:
            print("Fetching %s…" % name)
            m = fn()
            per_src[name] = m
            present.append(name)
            print("  %s: %d CVEs" % (name, len(m)))
        except Exception as e:
            print("  %s failed (%s) — skipping" % (name, e), file=sys.stderr)

    # union of CVE -> {sources:set, exploit_date:earliest}
    agg = {}
    for name, m in per_src.items():
        for cve, day in m.items():
            a = agg.setdefault(cve, {"sources": set(), "exploit": None})
            a["sources"].add(name)
            if day and (a["exploit"] is None or day < a["exploit"]):
                a["exploit"] = day

    # candidate set: confirmed-exploited (any age) + recently-disclosed
    cands = [c for c, a in agg.items()
             if (a["sources"] & CONFIRMED) or ((cve_year(c) or 0) >= RECENT_FROM)]
    cands.sort(key=lambda c: (agg[c]["exploit"] or date(1970, 1, 1)), reverse=True)
    cands = cands[:MAX_ROWS]
    print("Candidates: %d (of %d total signalled)" % (len(cands), len(agg)))

    info = enrich(cands)

    rows = []
    for c in cands:
        a = agg[c]; meta = info.get(c) or {}
        pub = parse_day(meta.get("pub"))
        exp = a["exploit"]
        tte = (exp - pub).days if (pub and exp) else None
        srcs = sorted(a["sources"])
        if meta.get("exploit_ref"):
            srcs = sorted(set(srcs) | {"nvd-exploit-ref"})
        rows.append({
            "cve": c, "product": meta.get("product") or "",
            "cve_date": meta.get("pub"), "exploit_date": exp.isoformat() if exp else None,
            "tte": tte, "cvss": meta.get("cvss"), "severity": meta.get("sev") or "",
            "sources": srcs,
        })
    rows.sort(key=lambda r: (r["cve_date"] or "0000"), reverse=True)

    src_counts = {}
    for r in rows:
        for s in r["sources"]:
            src_counts[s] = src_counts.get(s, 0) + 1
    all_sources = sorted(src_counts.keys())   # only sources that actually contributed a CVE

    out = {
        "updated": date.today().isoformat(),
        "sources": all_sources,
        "source_counts": src_counts,
        "count": len(rows),
        "note": "CVEs with known exploits/PoCs across %d public sources; TTE = exploit signal − CVE publication date." % len(all_sources),
        "cves": rows,
    }
    with open(os.path.join(DATA, "exploited.json"), "w") as f:
        json.dump(out, f, separators=(",", ":"))
    print("Wrote data/exploited.json — %d CVEs across %s" % (len(rows), ", ".join(all_sources)))


if __name__ == "__main__":
    main()
