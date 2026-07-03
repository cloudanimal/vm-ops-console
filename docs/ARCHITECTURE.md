# Architecture

## The shape

A **static single-page app**. No backend, no build step, no framework, no bundler. Everything is plain
HTML/CSS/JS served as files. Deployed on **GitHub Pages** straight from `main`.

```
Browser
├── index.html ............ the shell: <nav>, #app mount point, one big <style> block,
│                           and the CVE-intelligence half of the app (one large IIFE)
├── vmops.js / vmops.css .. Findings workbench, Ops Dashboard, Settings, Data Import (window.VMOPS)
├── acd.js  / acd.css ..... Agent Coverage dashboard              (window.ACD)   scoped .acdapp
├── tvd.js  / tvd.css ..... Tenable VM dashboard                  (window.TVD)   scoped .tvdapp
├── pscan.js/ pscan.css ... AI Prompt Scanner                     (window.PSCAN)
├── vmstore.js ............ shared IndexedDB file cache           (window.VMStore)
├── sw.js ................. service worker (offline + freshness)
├── vendor/ ............... third-party libs (Chart.js, PapaParse, SheetJS, html2canvas, gifenc)
├── data/ ................. pre-built public-CVE datasets (refreshed by GitHub Actions)
└── scripts/ ............. Python dataset builders (run by the Actions, not by the browser)
```

## Module boundaries & how they connect

The **shell** (`index.html`) owns the router, the nav, the design tokens, and the CVE-intelligence views.
Each operational area is a **separate JS file that attaches a small API to `window`** and renders into the
same `#app` element:

- `window.VMOPS = { dashboard, findings, import, settings, wiz }` — each is a render function.
- `window.ACD = { open, ... }` — Agent Coverage.
- `window.TVD = { open, ... }` — Tenable dashboard.
- `window.PSCAN = { open }` — Prompt Scanner.
- `window.VMStore` — shared IndexedDB helper (get/put/list uploaded source files).
- `window.VM_BRAND` — the current display brand (custom-branding feature).

There is **no shared framework state**. The shell dispatches a hash route to the right render function; that
function reads from its own module-private `STATE` (a closure variable, deliberately **not** on `window`)
and writes DOM into `#app`. Cross-module data sharing happens through **VMStore** (raw uploaded files in
IndexedDB) — each consumer parses on read with its own logic, which guarantees format compatibility.

> Gotcha: because each module's `STATE` is closure-private, you cannot read it from the console or a test
> harness. Assert against the DOM instead. (`acd.js` does expose `window._model` after a render for
> debugging.)

## Routing

Hash-based. `location.hash` → `route()` in `index.html`:

1. Split the path (`#/foo/bar?x=y` → `parts=['foo','bar']`, `query='x=y'`).
2. If `window.VMOPS[parts[0]]` exists → call it (Findings/Dashboard/Settings/Import/Wiz).
3. Else special-case `agent-coverage` → `ACD.open()`, `tvd` → `TVD.open()`, `prompt-scanner` → `PSCAN.open()`.
4. Else dispatch to a shell `viewX()` function (search, cve, kev, browse, latest, exploited, stats, eol,
   about, faq, ask, report, triage, nasl, …).

See [ROUTES.md](ROUTES.md) for the full table. Query params are parsed with `parseQuery(query)`.
The app scopes `#app`'s class per module (`.vmops` / `.acdapp` / `.tvdapp`) so CSS stays isolated.

## Rendering model

- Views build an HTML string and set `element.innerHTML`, then wire event listeners by `id`/class.
- Re-render on interaction is common: change a filter → rebuild the affected fragment → re-wire. Where an
  input drives a re-render (search boxes, per-column filters), the code **saves and restores focus + caret**
  so typing isn't interrupted (see `wireColFilters` in `index.html`, the Findings `colf` wiring in `vmops.js`).
- Charts use **Chart.js** (`vendor/chart.umd.js`); destroy old chart instances before re-creating.

## Data planes

**Read (public CVE data).** Two paths feed the CVE-intelligence views:
- **Live API calls** straight from the browser — NVD, FIRST EPSS, endoflife.date (all CORS-open), etc.
- **Pre-built static datasets** in `data/` for larger / CORS-blocked feeds (KEV, exploited set, EPSS
  distribution, LEV, TTE, Ubuntu fix status, stats). Built by `scripts/*.py`, committed, refreshed by
  scheduled GitHub Actions, indexed by `data/manifest.json`. See [DATA-PIPELINE.md](DATA-PIPELINE.md).

**Private (the user's own data).** Imported scan/agent exports are parsed in-browser and held in `STATE` +
persisted to localStorage / IndexedDB. Nothing is uploaded.

**Optional connected plane.** For teams at scale, an on-prem connector can land Tenable/ManageEngine/AD in
Power BI, which the browser reads directly via Entra sign-in; the connector also brokers ServiceNow/Jira.
This is additive and not yet built — see [BACKEND-CONNECTOR.md](BACKEND-CONNECTOR.md).

## Service worker (`sw.js`)

- **Network-first** for same-origin app files (so deploys are never stuck stale), **cache-first** for
  `vendor/`, `sample-data/`, the Transformers.js ESM + Hugging Face model hosts, and Google Fonts.
- Live CVE API calls pass through (network only). Requests with `cache:'no-store'/'no-cache'` bypass the
  cache (the dataset-freshness check uses this, so it fails honestly offline).
- Net effect: after the first online visit, the app shell + on-device Ask AI model work offline; only live
  public-CVE lookups need a connection.
- **Dev note:** because the network-first fetch respects normal HTTP caching, if you *unregister* the SW
  while developing, the browser may serve a stale `.js`. During active dev, keep DevTools "Update on reload"
  on or hard-refresh; the `<script>` tags are not URL-versioned.

## Ask AI (on-device intent router)

No server, no API key. A small language model (**Transformers.js**, `Xenova/all-MiniLM-L6-v2`, loaded once
from a public CDN, ~25 MB, then cached) embeds the user's question and each intent's example phrasings,
picks the nearest intent by cosine similarity, extracts light parameters (CVE ids, year, severity, time
window) with regex, and navigates to a **whitelisted** route (`ASK_ROUTES`). It never generates CVE data —
it only chooses which existing view to open. See `ASK_ROUTES` / `ASK_INTENTS` / `askResolve` in `index.html`.
