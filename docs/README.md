# VM Ops Console — documentation

A complete specification of this app, written so an AI coding assistant (or a new engineer)
could **rebuild it from scratch** and understand every moving part. Start here, then read in order.

| Doc | What it covers |
|---|---|
| [OVERVIEW.md](OVERVIEW.md) | What the app is, who it's for, the product surface, guiding principles |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The static-SPA model, module boundaries, routing, service worker, the two data planes |
| [FILE-MAP.md](FILE-MAP.md) | Every file in the repo and exactly what it's responsible for |
| [ROUTES.md](ROUTES.md) | The full hash-route table and which function renders each view |
| [DATA-MODEL.md](DATA-MODEL.md) | In-memory `STATE` shapes, the finding + override model, persistence (localStorage / IndexedDB), `config.json` |
| [DATA-PIPELINE.md](DATA-PIPELINE.md) | The `data/` datasets, the Python builders in `scripts/`, the GitHub Actions that refresh them, and the manifest |
| [STYLING-AND-CONVENTIONS.md](STYLING-AND-CONVENTIONS.md) | CSS design tokens, the scoping rules, coding conventions, and the gotchas that will bite you |
| [BACKEND-CONNECTOR.md](BACKEND-CONNECTOR.md) | The optional on-prem connector + Power BI + ServiceNow/Jira design (not yet built) |
| [REBUILD-GUIDE.md](REBUILD-GUIDE.md) | Step-by-step order to reconstruct the app, with acceptance checks |

## The one-paragraph version

VM Ops Console is a **backend-free, static single-page app** (vanilla JS, no build step, deployed on
GitHub Pages) for vulnerability-management operations. It pairs a **public-CVE intelligence front end**
(search, browse, KEV, exploited feeds, statistics, end-of-life, a daily report) with **operational tooling
that runs your own data client-side**: a findings workbench, a Tenable vulnerability dashboard, and an
AD-vs-agent coverage reconciler — plus an on-device natural-language "Ask AI" box. All of it is one
`index.html` shell that hash-routes to views, several standalone JS modules that attach to `window`, a
folder of pre-built public-CVE datasets refreshed by scheduled GitHub Actions, and a service worker for
offline use. There is **no server**; imported data stays in the browser (localStorage + IndexedDB).

**Live:** https://cloudanimal.github.io/vm-ops-console/ · **Repo:** `cloudanimal/vm-ops-console`

## Non-negotiables (read before changing anything)

- **No build step, no framework, no bundler.** Plain ES5-ish JS in `.js` files loaded with `<script>`.
  Edit the source directly; there is nothing to compile.
- **Serve over HTTP, not `file://`** — the app uses `fetch` and a service worker.
- **CSS is scoped per module** (`.vmops`, `.acdapp`, `.tvdapp`). Never leak page tokens onto `:root`
  from a sub-app stylesheet — it re-themes the whole shell. See STYLING-AND-CONVENTIONS.
- **Nothing about the user's imported data leaves the browser.** Only outbound calls are to public
  CVE data sources (and, if configured, the user's own Power BI / connector).
