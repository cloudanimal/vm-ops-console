# File map

Every tracked file and what it's responsible for. Line counts are approximate.

## Entry point & shell

| File | Role |
|---|---|
| `index.html` (~3100 lines) | The whole shell. Contains: the `<head>` meta (OG/Twitter/canonical, favicon), the **one `<style>` block** with all shell CSS + design tokens, the top `<nav>` + Ops Dashboard tab strip, the `#app` mount, and **one large IIFE** holding the router (`route()`) and every CVE-intelligence view (`viewSearch`, `viewDetail`, `viewBrowse`, `viewLatest`, `viewKev`, `viewExplorer`, `viewStats`, `viewEol`, `viewAbout`, `viewFaq`, `viewAsk`, `viewReport`, `viewTriage`, `viewNasl`, `viewAnalyze`, `viewDetections`, …), the Ask AI intent router, and the endoflife.date integration. |

## Operational modules (attach to `window`, render into `#app`)

| File | `window` API | Role |
|---|---|---|
| `vmops.js` (~1140) | `window.VMOPS` = `{dashboard, findings, import, settings, wiz}` | Findings workbench (grid, triage, per-column filters, grouping, drawer, CSV export), Ops Dashboard (KPIs), unified Data Import page, Settings (branding, SLA, ticketing, API keys), Wiz placeholder. Owns the finding data model + `STATE`. |
| `vmops.css` (~158) | — | Styles for the above, scoped under `.vmops`. |
| `acd.js` (~970) | `window.ACD` = `{open, …}` | Agent Coverage: parse AD + agent exports, `buildModel()` reconciles by normalized hostname, KPI cards, charts, coverage matrix, orphans, exports. Sets `window._model` after render. |
| `acd.css` (~107) | — | Scoped under `.acdapp`. |
| `tvd.js` (~1005) | `window.TVD` = `{open, …}` | Tenable VM dashboard: parse cumulative + mitigated Tenable SC exports, KPIs, severity/SLA/host breakdowns, top findings, per-panel save, report export. |
| `tvd.css` (~104) | — | Scoped under `.tvdapp`. |
| `pscan.js` / `pscan.css` | `window.PSCAN` = `{open}` | AI Prompt Scanner: scan pasted agent instructions / MCP configs / skill files for prompt-injection & malicious-instruction patterns. |
| `vmstore.js` | `window.VMStore` | Tiny IndexedDB (`vmops-data` / `files`) cache of **raw uploaded file text** keyed by source id (`acd:ad`, `acd:me`, `acd:tsc`, `acd:tio`, `acd:cs`, `findings`). Lets the unified Data Import page feed every dashboard; each consumer parses on read. |

## Runtime support

| File | Role |
|---|---|
| `sw.js` | Service worker: offline caching + deploy freshness (see ARCHITECTURE). |
| `config.json` | Default thresholds for Agent Coverage + Tenable (`staleDays`, `logonDays`, per-profile agent `health` day thresholds). Loaded at runtime; user changes override in-session. |
| `vendor/chart.umd.js` | Chart.js — all charts. |
| `vendor/papaparse.min.js` | CSV parsing (some importers). |
| `vendor/xlsx.full.min.js` | SheetJS — Excel (`.xlsx`) export/import. |
| `vendor/html2canvas.min.js` | Rasterize a panel to PNG for "save this card". |
| `vendor/gifenc.global.js` | GIF encoding (animated exports). |

## Data & build pipeline

| Path | Role |
|---|---|
| `data/*.json`, `data/*.json.gz` | Pre-built public-CVE datasets (KEV, EPSS, exploited, stats, latest, cwe, tte, …). `epss.json.gz` is gzip (large). |
| `data/lev/<year>.json`, `data/msrc/<year>.json`, `data/ubuntu/<year>.json` | Per-year sharded datasets (LEV probabilities, Microsoft KBs, Ubuntu fix status) + an `index.json` per folder. |
| `data/manifest.json` | Auto-generated index of every dataset: file, bytes, modified, `updated` (data as-of), record count. Powers the About → "Datasets & freshness" table. |
| `data/.cache/`, `data/.*cache*.json` | Build-script caches. `.cache/` is **gitignored**. |
| `scripts/build_*.py`, `scripts/nvd_feed.py` | Python builders — one per dataset (see DATA-PIPELINE). Run by GitHub Actions, **never by the browser**. |
| `.github/workflows/refresh-*.yml` | Scheduled Actions that run the builders and commit refreshed data. |
| `.github/copilot-instructions.md` | Repo custom-instructions auto-loaded by GitHub Copilot Chat. |

## Assets, samples, misc

| Path | Role |
|---|---|
| `sample-data/acd/*.gz`, `sample-data/tvd/*.gz` | Gzipped demo fixtures for the "Load sample data" buttons (AD/ME/Tenable/CrowdStrike; Tenable SC exports). |
| `assets/og-image.html`, `assets/og-image.png` | Social/OG card (HTML template + rendered PNG). Re-render by headless-screenshotting the HTML at 1200×630. |
| `docs/` | This documentation + `ops-dashboard.png` (README hero image). |
| `tools/port/` | Retired standalone generators for acd/tvd/pscan, kept for reference; the repo files are canonical. |
| `README.md` | Public repo readme. |
| `sharepoint-test.html` | Scratch/experimental page (not part of the app nav). |
