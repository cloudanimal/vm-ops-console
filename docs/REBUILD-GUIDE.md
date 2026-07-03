# Rebuild guide

How to reconstruct VM Ops Console from scratch, in dependency order, with an acceptance check per step.
Read [ARCHITECTURE.md](ARCHITECTURE.md) and [DATA-MODEL.md](DATA-MODEL.md) first — this guide assumes them.

## Ground rules

- **No build tooling.** Author plain `.html` / `.css` / `.js`. No npm, no bundler, no transpile. Third-party
  libs are dropped into `vendor/` and loaded with `<script>`.
- **Serve over HTTP** to develop (`python3 -m http.server 8000`, or a Live Server extension). Not `file://`.
- Match existing code style per file (see conventions). Keep CSS scoped (`.vmops`/`.acdapp`/`.tvdapp`).

## Step 0 — scaffold

Create `index.html` with: `<head>` meta + favicon, one `<style>` block defining the design tokens
(STYLING doc), a top `<nav>`, an empty `<div id="app">`, an empty `#ds-tabs` strip, and `<script>` tags for
`vendor/*`, `vmstore.js`, `vmops.js`, `acd.js`, `tvd.js`, `pscan.js`, and the shell IIFE (inline or a file).
**Accept:** page loads over HTTP, dark/light tokens apply, nav renders, no console errors.

## Step 1 — router + shell shell

In the shell IIFE, implement `route()` (hash → `parts`/`query` → dispatch), `parseQuery`, `setActive`,
`updateDashTabs`, and stub `viewX()` functions that render a heading. Wire `window.addEventListener('hashchange', route)` and call `route()` on load.
**Accept:** every route in [ROUTES.md](ROUTES.md) renders its stub; nav highlights correctly; the dashboard
tab strip shows only on the dashboard family.

## Step 2 — CVE intelligence (live-data views)

Build the public-data views that need no imported data: `viewSearch`, `viewDetail` (the five models +
fix-state + EOL + detection links), `viewBrowse`, `viewLatest`, `viewKev`, `viewExplorer`, `viewStats`,
`viewEol`, `viewReport`, `viewTriage`, `viewNasl`, `viewAbout`, `viewFaq`. Fetch NVD / EPSS / endoflife.date
live; read `data/*` for the pre-built sets. Add the shared table patterns (`ktable` sort + per-column
filters; `eolEnhanceTable`).
**Accept:** search returns real CVEs; KEV/Exploited tables sort + filter per column; CVE detail shows all
five models; End of Life browses by category/tag with full release history; About shows the datasets table.

## Step 3 — data pipeline

Write `scripts/build_*.py` (one per dataset in [DATA-PIPELINE.md](DATA-PIPELINE.md)) and
`build_manifest.py`. Add `.github/workflows/refresh-*.yml` to run them on a cron and commit results.
**Accept:** running a builder locally writes a valid `data/<x>.json`; the manifest indexes it; the About
freshness table renders from `data/manifest.json`.

## Step 4 — Ask AI (on-device intent router)

In the shell: `ASK_ROUTES` (whitelist regexes), `ASK_INTENTS` (label + example phrases + optional `build`),
`askSignals`/`askKeyword`, and `askResolve` (Transformers.js `Xenova/all-MiniLM-L6-v2`, embed question +
intents, cosine-nearest, extract params, navigate to a whitelisted route). Model loads once from a public
CDN and is cached; provide an explicit "make available offline" button.
**Accept:** typing "overdue KEV vulnerabilities" navigates to `#/kev?due=overdue`; "is windows server end of
life" → `#/eol/windows-server`; low-confidence falls back to search; it never fabricates CVE data.

## Step 5 — VMStore + Data Import

`vmstore.js`: IndexedDB `vmops-data`/`files`, `get/put/list` of raw uploaded file text keyed by source id.
`viewImport` (in vmops.js): a unified page that accepts each source's file, stores raw text in VMStore, and
routes users to the relevant dashboard.
**Accept:** uploading a file persists it (survives reload); each dashboard can read its source from VMStore.

## Step 6 — Findings workbench (`vmops.js`)

Implement the `STATE` + finding model (DATA-MODEL), the CSV/`.nessus` parsers (header-regex column
detection), `importScan`/`mergeFindings` (rescan delta: preserve `firstSeen`, stamp `lastSeen`, auto-resolve
gone findings, track new keys), `visibleFindings` (filters incl. `colf` + sort), the resizable/sortable grid
with the per-column filter row, grouping, the finding drawer (all five models), Settings (branding/SLA/
ticketing/keys), the Ops Dashboard (`kpis()`), and CSV export. Expose `window.VMOPS`.
**Accept:** import a Tenable CSV → findings appear; triage status/owner/notes persist; per-column filters +
grouping + sort compose; SLA/overdue compute; ticket deep-links open; CSV export includes notes/updates;
dashboard KPIs match.

## Step 7 — Agent Coverage (`acd.js`)

Parse AD + ME/Tenable/CrowdStrike exports; `colsFor()` + `HOST_PATS` hostname-column detection; `norm()`
short-name join; `buildModel()` reconciliation; KPI cards; the "Matched on hostname" transparency line
(red warning on detection failure); charts (Chart.js); coverage matrix; orphans; exports; `config.json`
health/stale defaults. Expose `window.ACD`, set `window._model` after render.
**Accept:** load the acd sample → AD denominator + per-agent coverage %/health/stale, fully-covered,
no-coverage, orphans; the match-key line shows the detected hostname column per source; changing scope
(enabled/all, OU/group filters, stale threshold) recomputes live.

## Step 8 — Tenable dashboard (`tvd.js`) + Prompt Scanner (`pscan.js`)

`tvd.js`: parse cumulative + mitigated Tenable SC exports → severity/SLA/host breakdowns, top findings,
per-panel PNG save (html2canvas), report export; "Load sample" replaces. `pscan.js`: scan pasted
agent/MCP/skill text for prompt-injection & malicious-instruction patterns. Expose `window.TVD` / `window.PSCAN`.
**Accept:** tvd sample renders KPIs + charts + top findings and exports a report; pscan flags an injected
instruction in a pasted prompt.

## Step 9 — service worker + polish

`sw.js`: network-first for same-origin app files, cache-first for `vendor/`/`sample-data/`/model host/fonts,
bypass `no-store`. Register it on load. Add OG/meta, the color-blind palette toggles, accessibility (focus
rings, ARIA), and the custom-branding path (`applyBrand`).
**Accept:** second visit works offline (shell + cached model); a deploy of changed JS is picked up
(network-first); Lighthouse/passes with no console errors across all routes.

## Step 10 — deploy

Push to `main`; GitHub Pages serves the repo root. No build action required.
**Accept:** the live URL renders every route with zero console errors; `data/manifest.json` freshness shows.

## Global acceptance

- Every route in ROUTES.md renders with **zero console errors** (fresh reload, light + dark).
- No imported data leaves the browser (check the Network tab — only public CVE sources + optional Power BI).
- CSS scoping holds: visiting acd/tvd doesn't re-theme the shell.
