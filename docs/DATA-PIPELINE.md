# Data pipeline

The CVE-intelligence views read from two places: **live public APIs** (fetched at view time) and
**pre-built static datasets** in `data/`. The static datasets exist because some feeds are large or
CORS-blocked, so they're built server-side by Python, committed to the repo, and refreshed on a schedule.
The browser only ever *reads* `data/`; it never runs the builders.

## Builders (`scripts/*.py`)

| Script | Produces | Source(s) |
|---|---|---|
| `build_kev.py` | `data/kev.json`, `data/kev_stats.json` | CISA KEV catalog |
| `build_epss.py` | `data/epss.json.gz` | FIRST EPSS (full current set, gzipped; ~340k CVEs) |
| `build_epss_dist.py` | `data/epss_dist.json` | EPSS score distribution |
| `build_epss_movers.py` | `data/epss_movers.json` | biggest EPSS risers |
| `build_explorer.py` | `data/exploited.json` | aggregated known-exploited / PoC set (CISA KEV, VulnCheck, Exploit-DB, Metasploit, Google P0, Nomi-sec) |
| `build_stats.py` | `data/stats.json` | NVD corpus counts (per-year/severity via `totalResults`) |
| `build_latest.py` | `data/latest.json` | newest CVEs (fkie-cad NVD mirror) |
| `build_cwe.py` | `data/cwe.json` | CWE weakness catalog |
| `build_lev.py` | `data/lev/<year>.json` + `index.json` | NIST LEV probabilities (CSWP 41, from EPSS history) |
| `build_msrc.py` | `data/msrc/<year>.json` + `index.json` | Microsoft Security Response Center KBs |
| `build_ubuntu.py` | `data/ubuntu/<year>.json` | Ubuntu CVE Tracker per-release package status |
| `build_tte.py` | `data/tte.json` | time-to-exploit |
| `build_tenable.py` | `data/tenable_latest.json` | newest Tenable plugins (for the Morning Report) |
| `build_manifest.py` | `data/manifest.json` | index of all datasets (see below) |
| `nvd_feed.py` | — (shared helper) | NVD API access used by several builders |

Build-script caches live in `data/.cache/` (gitignored) and `data/.*cache*.json`.

## Scheduled refresh (`.github/workflows/refresh-*.yml`)

Each dataset (or group) has a workflow that runs its builder on a cron and commits the refreshed file(s):

| Workflow | Cadence (typical) |
|---|---|
| `refresh-kev.yml` | daily (KEV + EPSS) |
| `refresh-stats.yml` | weekly |
| `refresh-explorer.yml` | ~weekly (exploited set) |
| `refresh-lev.yml`, `refresh-msrc.yml`, `refresh-ubuntu.yml`, `refresh-tte.yml` | monthly |
| `refresh-manifest.yml` | after data changes (re-indexes) |

They require repo secrets (API keys) — see the workflow files. Because the SW is network-first for
same-origin files, refreshed data reaches users without a stale-cache problem.

## The manifest (`data/manifest.json`)

Auto-generated index that powers the About → "Datasets & freshness" table. Shape:
```json
{ "generated": "2026-07-02T07:03:15Z",
  "files": [
    { "file": "kev.json", "bytes": 490436, "modified": "2026-07-02T07:03:14Z",
      "updated": "2026-07-01", "records": 1630 },
    ...
  ] }
```
- `modified` = when the file was last written; `updated` = the data's own as-of date; `records` = row count.
- The About page fetches this with `cache:'no-store'` so freshness is honest (and fails visibly offline).

## Live (not-prebuilt) sources

Fetched directly from the browser at view time (all CORS-open):
- **NVD** — search, browse, latest, CVE detail, corpus counts.
- **FIRST EPSS API** — per-CVE EPSS on the detail/drawer.
- **endoflife.date v1 API** (`/api/v1/products`, `/api/v1/products/{name}`) — the End of Life page.
- Detection: **deep-links** to each scanner vendor's own lookup (Tenable/Qualys/Rapid7) — plugin/QID DBs
  are proprietary, so they're linked, not embedded.

## Sample fixtures (`sample-data/`)

Gzipped demo data for the "Load sample data" buttons so the dashboards are explorable without real exports:
`sample-data/acd/{ad-computers.json.gz, manageengine.csv.gz, tenable-agents.csv.gz, crowdstrike.csv.gz}` and
`sample-data/tvd/*.gz`. Loaded relatively and decompressed in-browser (`DecompressionStream('gzip')`).
