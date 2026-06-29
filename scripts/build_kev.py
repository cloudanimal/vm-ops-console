#!/usr/bin/env python3
"""Build a compact, browsable copy of the CISA Known Exploited Vulnerabilities
catalog plus a few aggregate stats, written as static JSON the front end can
load directly.

The full KEV catalog is small enough (~1.3k entries) to ship in its own right,
which is what lets VM Ops Console browse confirmed-exploited CVEs entirely
client side, with no backend.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
import json
import os
import urllib.request
from collections import Counter
from datetime import datetime, timezone

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "cve-explorer/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def main():
    raw = fetch(KEV_URL)
    vulns = raw.get("vulnerabilities", [])

    # Trim each entry to the fields the UI actually renders.
    def clean(s):
        return s.strip() if isinstance(s, str) else s

    entries = []
    for v in vulns:
        entries.append({
            "id": clean(v.get("cveID")),
            "vendor": clean(v.get("vendorProject")),
            "product": clean(v.get("product")),
            "name": clean(v.get("vulnerabilityName")),
            "added": v.get("dateAdded"),
            "due": v.get("dueDate"),
            "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
            "action": clean(v.get("requiredAction")),
        })
    entries.sort(key=lambda e: (e.get("added") or ""), reverse=True)

    by_year = Counter()
    by_vendor = Counter()
    by_product = Counter()
    ransomware = 0
    for e in entries:
        if e["added"]:
            by_year[e["added"][:4]] += 1
        if e["vendor"]:
            by_vendor[e["vendor"]] += 1
        if e["product"]:
            by_product[f'{e["vendor"]} {e["product"]}'] += 1
        if e["ransomware"]:
            ransomware += 1

    catalog = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "source": "CISA KEV",
        "catalog_version": raw.get("catalogVersion"),
        "count": len(entries),
        "ransomware_count": ransomware,
        "entries": entries,
    }
    stats = {
        "updated": catalog["updated"],
        "total": len(entries),
        "ransomware_count": ransomware,
        "by_year": dict(sorted(by_year.items())),
        "top_vendors": by_vendor.most_common(20),
        "top_products": by_product.most_common(20),
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "kev.json"), "w") as f:
        json.dump(catalog, f, separators=(",", ":"))
    with open(os.path.join(OUT_DIR, "kev_stats.json"), "w") as f:
        json.dump(stats, f, indent=2)

    print(f"KEV: {len(entries)} entries, {ransomware} ransomware-linked, "
          f"catalog v{catalog['catalog_version']}")


if __name__ == "__main__":
    main()
