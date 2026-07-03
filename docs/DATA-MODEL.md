# Data model

Each module keeps its own `STATE` (a closure-private object, **not** on `window`). Persistence is
localStorage for small structured state + IndexedDB (`VMStore`) for raw uploaded files.

## Findings workbench (`vmops.js`)

### `STATE`
```js
var STATE = {
  findings: load('vmops-findings', []),   // Finding[]  (see below)
  ov:       load('vmops-overrides', {}),  // { [key]: Override }  keyed by keyOf(finding)
  cfg:      Object.assign({}, DEFAULT_CFG, load('vmops-config', {})),
  sort:     { col: 'risk', dir: 1 },      // active grid sort
  filt:     { q:'', status:'', sev:'', owner:'', repo:'', overdue:false, seen:'',
              exploited:false, fresh:false, epssHi:false, noTicket:false, colf:{}, group:'' }
};
// plus runtime-only: STATE._newKeys (from 'vmops-newkeys'), STATE._colW (from 'vmops-colw'),
//                     STATE._view / STATE._viewSig (saved views), STATE._findingsQuery (deep-link guard)
```

### `Finding`
Produced by the CSV/`.nessus` parsers. One row → **one finding per CVE** (a plugin listing N CVEs yields N
findings — this is intentional but means counts are CVE×host, not Tenable's plugin×host; see the note in
`.github/copilot-instructions.md`).
```js
{ cve, host, severity /* Critical|High|Medium|Low */, cvss /* number|null */,
  vpr /* number|null */, plugin, name, desc, repo, source /* 'Tenable' */,
  firstSeen /* ISO date */, lastSeen /* ISO date, set on rescan merge */ }
```

### `Override` (`STATE.ov[key]`)
User-applied triage state, kept separate from the imported finding so re-imports don't lose it.
```js
{ status /* one of STATUS keys */, owner, notes,
  updates: [{ at /* ISO */, text }],        // dated status-update log
  ticket:  { sys /* 'jira'|'snow' */, key, url, status, synced },
  updated /* ISO */ }
```

### Keys & identity
- `keyOf(f) = f.cve + '|' + norm(f.host)` — the stable identity of a finding (`norm` lowercases/trims host).
- `ovOf(f) = STATE.ov[keyOf(f)] || {}`.
- Rescan/merge preserves the earliest `firstSeen`, stamps `lastSeen`, auto-resolves open findings absent
  from the new scan, and tracks newly-seen keys in `STATE._newKeys` (drives the "New" chip + filter).

### `STATUS` (the triage lifecycle) — exact
```
new            (open)   Freshly imported — not yet reviewed.
triaged        (open)   Reviewed & assessed (owner/priority set); fix not started.
in_remediation (open)   Actively being fixed — patch/config in progress.
resolved       (closed) Fixed/remediated. Auto-set when a rescan no longer detects it.
risk_accepted  (closed) Deliberately accepted — won't fix now; documented & tracked.
false_positive (closed) Not a real vulnerability — scanner misdetection; dismissed.
```
Open states run the SLA clock and rank highest; closed states are off the worklist. `SLABEL` maps key→label;
`OPEN_STATES` = the open keys.

### `DEFAULT_CFG` (Settings)
```js
{ brand:'', brandIcon:'', brandIconColor:'',
  sla: { Critical:7, High:30, Medium:90, Low:180 },   // days per severity
  jiraBase:'', jiraPid:'', jiraType:'', snowBase:'',   // ticketing deep-link config
  tsUrl:'', tsAccess:'', tsSecret:'', tioAccess:'', tioSecret:'',   // Tenable SC / .io keys
  meUrl:'', meClientId:'', meClientSecret:'' }          // ManageEngine OAuth (Zoho self-client)
```

### Derived
- `riskScore(f)` folds CVSS + EPSS (`+epss*300`) + KEV (`+600`) / ransomware (`+250`) / public exploit
  (`+200`) + VPR (`+vpr*20`), minus a large penalty for closed findings.
- `priorityOf(f)` → P1/P2/P3. `slaWindow`/`dueDate`/`dueIn`/`slaState` compute SLA. `kpis()` returns the
  dashboard counts (total/open/overdue/comp/crit/assets/unassigned/noTicket).

## Agent Coverage (`acd.js`)

### `STATE`
```js
STATE = { ad:[], me:[], ten:[], cs:[],   // parsed record arrays per source
          adCols:[],                     // AD column union (header detection)
          src:{}, staleDays:30, denom:'enabled' /* 'enabled'|'all' */,
          health:{ server:{me,ten,cs}, workstation:{me,ten,cs} },  // day thresholds
          excludeNonReal, logonFilter, logonDays, ouSel, grpSel, srcFilters, … }
```

### The reconciliation (`buildModel()`)
- **AD is the denominator.** Every AD computer is matched to each agent source **by normalized hostname**:
  `norm(h) = String(h).trim().split('.')[0].toUpperCase()` — strips the domain so FQDN and short names
  reconcile.
- Each source's hostname column is auto-detected by `colsFor()` using the shared `HOST_PATS` list
  (DNS/FQDN/NetBIOS/computer/machine/device/resource-name variants). **If detection fails it must not
  silently fall back** — the dashboard shows a "Matched on hostname — …" line and flags a red warning.
- Output: `{ ad:[{name,key,seg,domain,ou,groups,type,os,enabled,cov,nAgents,isReal,logonDays,…}],
  sources, matched, orphans }` where `cov[k]` = `{present, rec, days, stale, healthDays, unhealthy, invalid}`.
- KPIs (coverage %, health %, fully-covered, no-coverage, no-EDR, single-agent, orphans) are computed over
  the **in-scope** subset (denominator filtered by enabled/real/logon/OU/group).

## Tenable dashboard (`tvd.js`)
```js
STATE = { cumulative:[], mitigated:[], hostOverride:{}, topN:5, summaryN:5,
          cbTheme:'protanopia', topSev:'all', hostsN:10, hostsSev:'all', segFilter:'all', … }
```
Parses a Tenable SC **cumulative** export + a **mitigated** export; computes severity/SLA/host breakdowns
and top findings. "Load sample" replaces (does not append).

## Shared file cache (`vmstore.js`)
IndexedDB `vmops-data` / object store `files`, keyed by source id. Each record:
`{ id, name, text /* raw file text */, kind:'json'|'csv', size, importedAt }`. Source ids: `acd:ad`,
`acd:me`, `acd:tsc`, `acd:tio`, `acd:cs`, `findings`. Consumers read the raw text and parse with their own
logic. Local-only, never uploaded.

## `config.json` (shipped defaults for acd/tvd)
```json
{ "staleDays": 30, "logonDays": 15,
  "health": { "server":      { "me": 2,  "ten": 2,  "cs": 2 },
              "workstation": { "me": 14, "ten": 14, "cs": 7 } } }
```

## localStorage keys (complete)
| Key | Owner | Contents |
|---|---|---|
| `vmops-findings` | vmops | `Finding[]` |
| `vmops-overrides` | vmops | `{ key: Override }` |
| `vmops-config` | vmops | Settings (`cfg`) |
| `vmops-colw` | vmops | Findings grid column widths |
| `vmops-newkeys` | vmops | keys newly seen in the last rescan |
| `vmops-views` | vmops | saved smart views |
| `acd-cb` | acd | color-blind palette choice |
| `tvd-cb` | tvd | color-blind palette choice |
| `cve-theme` | shell | light/dark theme |
| `ask-model-cached` | shell | flag: Ask AI model downloaded/cached |

> Everything in localStorage/IndexedDB is per-browser and never leaves the device.
