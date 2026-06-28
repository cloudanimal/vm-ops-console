#!/usr/bin/env python3
"""Build a compact "latest detections" feed from Tenable's public newest-plugins
RSS.

Tenable's plugin database is proprietary, so this does not mirror it. It
syndicates only the lightweight metadata an RSS feed exists to share, plugin
ID, short title, severity, date, and the canonical link back to Tenable, plus
the CVE IDs each plugin references so CVE Explorer can cross-link a detection
to its own CVE pages. The descriptive prose in the feed is deliberately not
stored.

Source: https://www.tenable.com/plugins/feeds?sort=newest  (Copyright Tenable, Inc.)
"""
import json
import os
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

FEED_URL = "https://www.tenable.com/plugins/feeds?sort=newest"
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
MAX_ITEMS = 60

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
SEV_RE = re.compile(r"with\s+(Critical|High|Medium|Low|Info)\s+Severity", re.I)
PID_RE = re.compile(r"/plugins/\w+/(\d+)")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "cve-explorer/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def main():
    root = ET.fromstring(fetch(FEED_URL))
    channel = root.find("channel")
    items = []
    for it in channel.findall("item")[:MAX_ITEMS]:
        link = (it.findtext("link") or "").strip()
        title = (it.findtext("title") or "").strip()
        desc = it.findtext("description") or ""
        pid_m = PID_RE.search(link)
        sev_m = SEV_RE.search(desc)
        cves = sorted(set(CVE_RE.findall(desc)))
        items.append({
            "id": pid_m.group(1) if pid_m else None,
            "title": title,
            "severity": sev_m.group(1).title() if sev_m else None,
            "date": (it.findtext("pubDate") or "").strip(),
            "link": link,
            "cves": cves,
        })

    out = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "source": "Tenable newest-plugins RSS",
        "source_url": "https://www.tenable.com/plugins",
        "attribution": "Plugin metadata (c) Tenable, Inc. Syndicated from the public RSS feed; see each link for full details.",
        "count": len(items),
        "items": items,
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "tenable_latest.json"), "w") as f:
        json.dump(out, f, indent=2)
    linked = sum(1 for i in items if i["cves"])
    print(f"Tenable latest: {len(items)} plugins, {linked} reference a CVE")


if __name__ == "__main__":
    main()
