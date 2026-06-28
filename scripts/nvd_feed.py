#!/usr/bin/env python3
"""Shared loader for the fkie-cad NVD JSON mirror.

The legacy NVD JSON data feeds were retired on 2023-12-15; the only first-party
replacement is the rate-limited NVD 2.0 API (which needs a key for any real
volume). The fkie-cad project reconstructs the old per-year feeds from the NVD
API and republishes them on GitHub, synced bi-hourly — so we get NVD's own
enriched data (CVSS, CWE, KEV flags, CPE configs) with **no API key and no rate
limit**. The build scripts then compute corpus-wide counts locally instead of
asking NVD to count for them.

  Per-year feed: .../releases/latest/download/CVE-<YEAR>.json.xz
  Each decompresses to {"cve_items": [ <NVD 2.0 cve object>, ... ]}.

Decompressed years are cached under data/.cache/nvd_feed/, keyed by the release
tag, so a rerun within the same release reuses them and two builders running in
one CI job share a single download.

Source: https://github.com/fkie-cad/nvd-json-data-feeds (not endorsed by NVD).
"""
import json
import lzma
import os
import time
import urllib.request
from datetime import datetime, timezone

REPO = "fkie-cad/nvd-json-data-feeds"
DL_BASE = f"https://github.com/{REPO}/releases/latest/download"
TAG_API = f"https://api.github.com/repos/{REPO}/releases/latest"
CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", ".cache", "nvd_feed")
FIRST_YEAR = 1999

_tag = None
_cache_state = None  # None=unknown, True=reuse cached files, "build"=(re)download


def current_year():
    return datetime.now(timezone.utc).year


def _http(url, timeout=180):
    headers = {"User-Agent": "vm-ops-console/1.0 (+https://github.com/cloudanimal/vm-ops-console)"}
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:
            if attempt == 3:
                raise
            print(f"  retry {url} ({e})")
            time.sleep(3 * (attempt + 1))


def latest_tag():
    global _tag
    if _tag is None:
        try:
            _tag = json.loads(_http(TAG_API, timeout=60))["tag_name"]
        except Exception:
            _tag = "unknown"
    return _tag


def _tag_path():
    return os.path.join(CACHE_DIR, "_tag")


def _year_path(year):
    return os.path.join(CACHE_DIR, f"CVE-{year}.json")


def _cache_state_for_run():
    """Decide once per process whether the on-disk cache matches the current
    release. If stale, stamp the new tag now so files downloaded during this run
    are treated as valid."""
    global _cache_state
    if _cache_state is not None:
        return _cache_state
    os.makedirs(CACHE_DIR, exist_ok=True)
    try:
        with open(_tag_path()) as f:
            fresh = f.read().strip() == latest_tag()
    except OSError:
        fresh = False
    if fresh:
        _cache_state = True
    else:
        with open(_tag_path(), "w") as f:
            f.write(latest_tag())
        _cache_state = "build"
    return _cache_state


def load_year(year):
    """Return the list of NVD cve objects for one CVE-ID year (cached on disk)."""
    path = _year_path(year)
    if _cache_state_for_run() is True and os.path.exists(path):
        with open(path) as f:
            return json.load(f).get("cve_items", [])
    raw = _http(f"{DL_BASE}/CVE-{year}.json.xz")
    data = json.loads(lzma.decompress(raw))
    with open(path, "w") as f:
        json.dump(data, f)
    return data.get("cve_items", [])


def iter_years(first=FIRST_YEAR, last=None):
    """Yield (year, cve_items) for each CVE-ID year file. Note the file year is
    the CVE *ID* year, not the publication year — callers that bucket by
    publication date should read each record's ``published`` field."""
    last = last or current_year()
    for year in range(first, last + 1):
        yield year, load_year(year)


def best_v3(cve):
    """NVD's primary CVSS v3 (severity, vector), v3.1 preferred over v3.0.

    NVD's cvssV3Severity / cvssV3Metrics API filters count only NVD's own
    *Primary* score (source nvd@nist.gov), not CNA/Secondary scores — verified
    against the live API (a Secondary fallback over-counts 2024 criticals ~60%
    because of NVD's analysis backlog). So we deliberately ignore Secondary
    scores here; a CVE NVD hasn't scored is absent from the severity split,
    exactly as in the previous API-based build. Returns ('', '') if none."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key) or []:
            if m.get("type") == "Primary":
                data = m.get("cvssData", {})
                return data.get("baseSeverity"), data.get("vectorString", "")
    return "", ""


def cwe_ids(cve):
    """Set of CWE-IDs from a CVE's NVD *Primary* weakness assignment.

    Like the CVSS filters, NVD's cweId API filter counts only NVD's own Primary
    weakness (source nvd@nist.gov), not CNA/Secondary CWEs — verified exact
    against the live API (any-source ~doubles the counts). So we ignore
    Secondary weaknesses here for parity with the previous build."""
    out = set()
    for w in cve.get("weaknesses", []):
        if w.get("type") != "Primary":
            continue
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-"):
                out.add(v)
    return out


def in_kev(cve):
    """True if the record carries CISA KEV enrichment (NVD's hasKev flag)."""
    return bool(cve.get("cisaExploitAdd"))
