# Styling & conventions

## Design tokens (CSS custom properties)

The shell (`index.html` `<style>`) defines the palette as CSS variables on `:root`, with a dark-mode
override. Everything themes off these — never hardcode colors.

Shell tokens (names to preserve):
```
--paper   page background        --ink     primary text        --soft   secondary text
--faint   tertiary/hint text     --line    hairline borders    --accent brand accent (navy)
--surface card background        --badge-ink text-on-severity
--crit --high --med --low        severity ramp
--hl      highlight (search)     --ok      success/green
```
Typography: `--sans`, `--mono` (and a serif voice for headings). Theme is stored in `cve-theme`
(light/dark) and also respects `prefers-color-scheme`.

## CSS scoping (the rule that will bite you)

Each operational module's CSS is **scoped under a wrapper class**, and `#app` gets that class when the
module is active:

- Shell views: no wrapper (they use the shell tokens directly).
- `vmops.css` → everything under `.vmops`.
- `acd.css` → everything under `.acdapp`.
- `tvd.css` → everything under `.tvdapp`.

**Never put page tokens on `:root` (or bare `html`/`body`) inside a sub-app stylesheet.** Doing so leaks
the sub-app's palette onto the whole shell and re-themes unrelated pages. If a module needs its own token
values (e.g. tvd's severity palette, or a color-blind override), scope them:
`.tvdapp { --med: … }` and `:root[data-theme=dark] .tvdapp { … }` — and set runtime palette overrides on the
wrapper element, not `document.documentElement`.

Responsive `@media` blocks inside a scoped stylesheet must keep the wrapper prefix on every selector, or
they'll restyle the shell at that breakpoint.

## Coding conventions

- **Plain JS, no framework/build.** `index.html` + `vmops.js` use ES5-ish `var`/`function` style; `acd.js`
  / `tvd.js` use more modern `const`/arrow style. Match the file you're editing.
- **Render = build an HTML string, set `innerHTML`, then wire listeners by id/class.** Re-render fragments
  on interaction; destroy Chart.js instances before recreating.
- **Focus preservation:** when an `<input>` drives a re-render (search, per-column filters), record the
  active column + caret position, re-render, then restore focus + `setSelectionRange`. See `wireColFilters`
  (index.html), the Findings `colf` wiring (vmops.js), and the `kq`/`exq` handlers.
- **Column detection over fixed indices:** parsers detect columns by header regex (`findCol` / `col`), not
  fixed positions, so real-world exports with varied headers still map. Keep the pattern lists broad and
  **surface the detected column** where a wrong guess would corrupt results (see the Agent Coverage
  "Matched on hostname" line).
- **Escape user/text content** before inserting into HTML (`esc()` / `escH()`).
- **`STATE` is closure-private** per module — don't rely on reading it from the console; assert against DOM.
- Keep the `Co-Authored-By` trailer on commits (owner preference). Never commit secrets — API keys are
  entered in Settings and live only in `localStorage`.

## Tables (three shared patterns)

- **Findings grid** (`vmops.js`): `table.grid.resizable`, `table-layout:fixed`, columns from `COL_DEFS`,
  resizable + sortable, plus a per-column filter row (`gridFilterRow` / `COLF_COLS` / `colfVal`).
- **CVE lists** (`index.html`): `table.ktable` (KEV, Exploited) with their own sort + a per-column filter
  row (`colFilterRow` / `wireColFilters`).
- **End of Life** (`index.html`): `eolEnhanceTable(table)` adds generic sort + per-column filter to a table.

## Branding

`applyBrand()` reads `cfg.brand`/`brandIcon`/`brandIconColor` and updates the nav brand text, document
title, favicon (rebuilt as an SVG data-URI), and `.brandname` spans + `window.VM_BRAND`. README/OG-meta stay
as the canonical product name (docs can't be runtime-branded).

## Accessibility

WCAG-AA contrast on tokens; `:focus-visible` rings; ARIA on nav dropdowns (`aria-haspopup`/`-expanded`),
menus, and icon-only buttons. Severity is never encoded by color alone — badges carry text labels, and a
color-blind palette toggle exists on the dashboards.
