# Routes

Hash routing. `route()` in `index.html` parses `location.hash` into `parts` (path segments) + `query`,
then dispatches. Dispatch order: **`window.VMOPS[parts[0]]` first**, then the special module routes, then
the shell `viewX()` functions.

## Full table

| Hash | Handler | Module | Notes |
|---|---|---|---|
| `#/` (empty) | `viewAsk()` | shell | Default landing = Ask AI. |
| `#/ask` | `viewAsk()` | shell | On-device NL navigator. |
| `#/report` | `viewReport()` | shell | Morning Report (daily briefing). |
| `#/search/:q` | `viewSearch(q)` | shell | Keyword/product CVE search (live NVD). |
| `#/cve/:id` | `viewDetail(ID)` | shell | Single CVE detail — all five models + fix state + EOL + detection links. |
| `#/browse?year=&sev=&cwe=` | `viewBrowse(params)` | shell | Browse the corpus (renders `.hit` cards). |
| `#/latest?days=&mode=` | `viewLatest(params)` | shell | Newest/updated CVEs (`.hit` cards; has its own keyword filter). |
| `#/kev?due=&q=` | `viewKev(params)` | shell | CISA KEV catalog (`.ktable`, sortable, per-column filters). |
| `#/exploited?days=` | `viewExplorer()` | shell | All-sources known-exploited feed (`.ktable`, per-column filters). |
| `#/stats?tab=` | `viewStats(params)` | shell | CVE statistics (charts + small tables). |
| `#/tte` | `viewStats({tab:'tte'})` | shell | Time-to-exploit view. |
| `#/eol[/:product][?tag=]` | `viewEol(params)` | shell | Software End of Life (endoflife.date v1 API): category/tag selector + full release history, sortable + per-column filters. |
| `#/triage[/:list][?view=compare]` | `viewTriage(...)` | shell | Paste-a-list bulk triage / side-by-side compare. |
| `#/compare/:ids` | `viewTriage(ids,'compare')` | shell | Compare specific CVEs. |
| `#/nasl` | `viewNasl()` | shell | NASL viewer — read a Nessus plugin's source in-browser. |
| `#/analyze` | `viewAnalyze()` | shell | Tenable export analyzer (client-side). |
| `#/detections` | `viewDetections()` | shell | Detection deep-links. |
| `#/about` (or `#/data`) | `viewAbout()` | shell | About + architecture + **Datasets & freshness** table. |
| `#/faq` | `viewFaq()` | shell | FAQ / explainers. |
| `#/dashboard` | `VMOPS.dashboard` → `viewDashboard()` | vmops.js | Ops Dashboard (KPIs over imported findings). |
| `#/findings[?…]` | `VMOPS.findings` → `viewFindings()` | vmops.js | Findings workbench (grid + per-column filters + grouping). Query params seed filters (sev/status/owner/overdue/q…). |
| `#/import` | `VMOPS.import` → `viewImport()` | vmops.js | Unified Data Import page (feeds every dashboard via VMStore). |
| `#/settings` | `VMOPS.settings` → `viewSettings()` | vmops.js | Branding, SLA windows, ticketing, API-key config. |
| `#/wiz` | `VMOPS.wiz` → `viewWiz()` | vmops.js | Wiz placeholder ("not connected yet"). |
| `#/agent-coverage` | `ACD.open()` | acd.js | Agent Coverage dashboard. |
| `#/tvd` | `TVD.open()` | tvd.js | Tenable VM dashboard. |
| `#/prompt-scanner` | `PSCAN.open()` | pscan.js | AI Prompt Scanner. |

## Nav & the Ops Dashboard tab strip

- Top `<nav>` links (`data-route=…`): Ask AI, Morning Report, Ops Dashboard, Findings, plus **CVE
  Intelligence** and **Tools** dropdowns, then FAQ, About, Settings.
- The **Ops Dashboard tab strip** (`#ds-tabs`) appears only on the dashboard family
  (`dashboard`, `findings`, `agent-coverage`, `tvd`, `wiz`) and marks the active tab. Managed by
  `updateDashTabs(parts[0])`, called from `route()`.
- `setActive(route)` highlights the correct top-nav item. The ACD/TVD/Findings/Wiz routes call
  `setActive('dashboard')` so the top nav stays on "Ops Dashboard" while the strip shows the sub-tab.

## Conventions

- Query strings are parsed with `parseQuery(query)`.
- Deep links seed state but are parsed **only when the query changes** (guarded), so later in-view filter
  changes aren't clobbered by a re-parse.
- Ask AI may only navigate to routes matching the `ASK_ROUTES` whitelist regexes.
