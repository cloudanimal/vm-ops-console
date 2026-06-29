# Port scripts (legacy — do not re-run blindly)

These are the **one-time** scripts that originally ported three standalone apps into
VM Ops Console as native, same-origin views:

| Script | Generated | From standalone repo |
|---|---|---|
| `buildacd.js` | `acd.js`, `acd.css` | `agent-coverage-dashboard` |
| `buildtvd.js` | `tvd.js`, `tvd.css` | `tenable-vm-dashboard` |
| `buildpscan.js` | `pscan.js`, `pscan.css` | `agent-supply-chain-scanner` |

## ⚠️ The generated files are now hand-maintained — these scripts are out of date

`acd.{js,css}`, `tvd.{js,css}`, and `pscan.{js,css}` in the repo root are the **source of
truth**. They have since diverged substantially from what these scripts produce:

- chrome tokens scoped under `.acdapp` / `.tvdapp` (light base + dark override) so they no
  longer leak onto the shell, with `--bg/--panel/--txt/--muted` remapped to the app tokens
- the color-blind palette JS (`applyPalette`) + chart/var reads scoped to the `.acdapp` /
  `.tvdapp` element instead of `document.documentElement`
- the Tenable responsive `@media` block scoped to `.tvdapp`; pill colors rebuilt from tokens
- Agent Coverage drawer close button id fixed (`acdDrawerX`); icon-button `aria-label`s
- sample data vendored gzipped under `sample-data/{acd,tvd}/*.gz` and decompressed in-browser
  (the loaders fetch the local `.gz`, not the standalone repos)
- branding updated from "CVE Explorer" → "VM Ops Console" throughout
- the pscan header recast to the overline + serif `h1` + lede view pattern

**Re-running any of these scripts will overwrite those fixes.** They are kept only to document
how the initial port was done. If you ever need to pull a change from a standalone app, port
that specific change by hand into the repo file (or first re-apply the divergences above to the
script). The scripts also expect the standalone source repos to be checked out at the `SRC`
paths near the top of each file.
