#!/usr/bin/env python3
"""Build data/manifest.json — an auto-discovered index of every shipped dataset.

The Datasets & freshness panel reads this so new datasets show up automatically:
the panel never has to be hand-edited when a build script starts emitting a new
file. Curated descriptions (what each one powers) are overlaid in the front end
by filename; anything not described there still appears, with auto-derived info.

Run after the data builds (or on its own daily schedule). Walks data/, records
each .json's size, `updated` field (if present), and a best-effort record count.
"""
import json
import os
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")


def record_count(obj):
    if isinstance(obj, dict):
        for k in ("count", "total", "grand_total", "total_scored"):
            if isinstance(obj.get(k), int):
                return obj[k]
        for k in ("cves", "entries", "risers", "weaknesses", "items", "vulnerabilities"):
            if isinstance(obj.get(k), list):
                return len(obj[k])
        # a plain {CVE: ...} map (e.g. msrc/lev/ubuntu year files)
        if obj and all(str(key).upper().startswith("CVE-") for key in list(obj)[:5]):
            return len(obj)
    if isinstance(obj, list):
        return len(obj)
    return None


def entry(path, rel):
    try:
        st = os.stat(path)
        updated = None
        cnt = None
        try:
            with open(path) as f:
                obj = json.load(f)
            updated = obj.get("updated") if isinstance(obj, dict) else None
            cnt = record_count(obj)
        except Exception:
            pass
        return {
            "file": rel,
            "bytes": st.st_size,
            "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "updated": updated,
            "records": cnt,
        }
    except Exception:
        return None


def main():
    files = []
    # top-level data/*.json
    for name in sorted(os.listdir(DATA)):
        if name.startswith(".") or not name.endswith(".json") or name == "manifest.json":
            continue
        e = entry(os.path.join(DATA, name), name)
        if e:
            files.append(e)
    # per-year subfolders (ubuntu, lev, msrc) — aggregate into one logical entry each
    for sub in ("ubuntu", "lev", "msrc"):
        d = os.path.join(DATA, sub)
        if not os.path.isdir(d):
            continue
        yrs = sorted(n for n in os.listdir(d) if n.endswith(".json"))
        total, newest, recs = 0, None, 0
        for y in yrs:
            e = entry(os.path.join(d, y), sub + "/" + y)
            if not e:
                continue
            total += e["bytes"]
            recs += e["records"] or 0
            if newest is None or e["modified"] > newest:
                newest = e["modified"]
        if yrs:
            files.append({"file": sub + "/", "bytes": total, "modified": newest, "updated": None, "records": recs, "group": len(yrs)})

    out = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": files,
    }
    with open(os.path.join(DATA, "manifest.json"), "w") as f:
        json.dump(out, f, separators=(",", ":"))
    print("Wrote data/manifest.json — %d datasets indexed." % len(files))


if __name__ == "__main__":
    main()
