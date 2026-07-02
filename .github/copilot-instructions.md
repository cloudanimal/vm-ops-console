# VM Ops Console — working notes for Copilot

Static, backend-free vulnerability-management console. Vanilla JS, **no build step**, hash routing, deployed on GitHub Pages. Live: https://cloudanimal.github.io/vm-ops-console/

## Run it locally (needed to test real data uploads)
- Must be served over **HTTP, not `file://`** — the app uses `fetch` + a service worker.
- `python3 -m http.server 8799` in the repo root → open http://localhost:8799/ — or use the VS Code **Live Server** extension.
- After editing, **hard-refresh** (Cmd/Ctrl+Shift+R). `sw.js` caches aggressively; during active dev, unregister it in DevTools → Application → Service Workers so you always see fresh code.

## Layout
- `index.html` — app shell + all CVE-intelligence views (search / browse / latest / KEV / exploited / stats / **End of Life**), About / FAQ / Ask AI. One big IIFE; CSS lives in the single `<style>` block near the top.
- `vmops.js` / `vmops.css` — **Findings workbench**, Ops dashboard, Settings + Data Import, finding drawer, KPIs. `STATE` is closure-private (not on `window`).
- `acd.js` / `acd.css` — Agent Coverage (AD vs agents), scoped under `.acdapp`.
- `tvd.js` / `tvd.css` — Tenable VM dashboard, scoped under `.tvdapp`.
- `data/` — prebuilt datasets (KEV, EPSS, exploited…), refreshed by `.github/workflows/`.
- `scripts/` — Python dataset builders. `sample-data/*.gz` — demo fixtures for the "Load sample" buttons.

## Conventions
- No framework / bundler — edit JS/CSS directly.
- **CSS scoping**: shell tokens in `index.html`; `vmops` under `.vmops`, acd under `.acdapp`, tvd under `.tvdapp`. Never put page tokens on `:root` in the sub-app CSS — it leaks and re-themes the shell.
- Per-column table filter rows are a recent pattern: Findings (`vmops.js`: `gridFilterRow` / `COLF_COLS` / `colfVal`), KEV + Exploited (`index.html`: `colFilterRow` / `wireColFilters`), End of Life (`eolEnhanceTable`).
- Keep the `Co-Authored-By` trailer on commits (owner preference). Don't commit secrets — API keys live in `localStorage` only.

## ⚠️ CURRENT TASK — real-export numbers

### Agent Coverage dashboard (`acd.js`) — where the wrong numbers were seen
Root cause (fixed 2026-07-02, verify with real data): coverage is computed by matching AD hosts to each agent export **by hostname** (`norm()` = short name, uppercased). The hostname column in each agent export is auto-detected by `colsFor()`. The old patterns were too narrow — real **Tenable** exports label the host column `DNS Name` / `NetBIOS Name` (not `Hostname`), and **ManageEngine** may use `Resource Name` — so detection missed them and **silently fell back to the first column**, breaking every match → wrong coverage %.
- Fix applied: broadened detection to a shared `HOST_PATS` list (DNS/FQDN/NetBIOS/computer/machine/device/resource/… name); broadened the AD name column too.
- Added a **"Matched on hostname — AD → … · ManageEngine → … · Tenable → …"** line under the KPI cards. **When you upload real data, read that line first**: if a source shows a red "hostname column not detected" warning or the wrong column, that's the bug — add its exact header to `HOST_PATS` in `acd.js`. If every source shows the right column and numbers are still off, the issue is elsewhere (health/stale thresholds, denominator, or dedup on duplicate short-names across domains).
- Key spots: `colsFor()` + `HOST_PATS`, `norm()`, `buildModel()` (the `idx`/match loop), and the render's KPI section (all in `acd.js`).

### Findings / Tenable-dashboard imports (not yet checked by the owner)
If the Findings workbench or the `#/tvd` dashboard numbers also look off, the likely causes there, in order:

1. **One row explodes into one finding PER CVE.** `parseCsv` (`vmops.js` ~line 925) does `cves.forEach(...)`, so a plugin listing N CVEs becomes N findings. Tenable counts plugin×host *instances*, not CVE×host — so totals diverge. **Probably the biggest discrepancy.** Decide whether to count instances (one row = one finding, CVEs as a list) or keep CVE-centric and reconcile the KPI labels.
2. **Rows with no CVE are dropped** — `if (!cves.length) return;`. Tenable "vulnerabilities" include plugins with no CVE (info / local checks); those vanish here, lowering totals.
3. **Host column mis-map.** `iHost` patterns (`vmops.js` ~918) include `/^name$/i`, which can match a Tenable **"Name"** (plugin-name) column when no *DNS Name / Host / Hostname* appears before *IP Address* — host then becomes the plugin name, corrupting host counts and dedup (`keyOf` = cve+host). Check your export's header order.
4. **Severity / Info.** `normSev` (`vmops.js` ~941) maps by word/number; "Info" / severity `0` falls through to **Medium**. Confirm how the export labels severity, and whether Info should be excluded.
5. **There are three separate parse paths** — be sure you debug the one you uploaded to:
   - Findings workbench import → `vmops.js` `handleSourceFile` → `parseCsv` → `importScan`/`mergeFindings` → `kpis`.
   - Tenable **export analyzer** (Analyze/Detections view) → `index.html` `parseCsvFindings` / `parseNessus` (~2637 / 2662).
   - Tenable **dashboard** (`#/tvd`) → `tvd.js` has its own parse + KPI math.

**Fastest first step:** add `console.log(head)` (and the detected `iCve/iSev/iHost/...` indices) in the relevant parser, upload the real file, and compare detected columns against the actual headers.

## Recent history
Latest big commit (`b6e97bf`): End of Life page (endoflife.date v1 API + category/tag selector + sortable/filterable tables), per-column filter rows on Findings / KEV / Exploited, About page reorg. See `git log` for the trail.
