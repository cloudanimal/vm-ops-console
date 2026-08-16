(function () {
  'use strict';
  var app = document.getElementById('app');
  var CVE_DETAIL = '#/cve/';                                                   // in-app CVE detail view
  var CVE_DETAIL_ABS = 'https://cloudanimal.github.io/vm-ops-console/#/cve/';  // absolute, for copied ticket text

  // Theme + main nav are now provided by the shared global top bar (shared/topbar.js).

  // ---------- helpers ----------
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function todayISO() { var n = new Date(); return n.getFullYear() + '-' + String(n.getMonth() + 1).padStart(2, '0') + '-' + String(n.getDate()).padStart(2, '0'); }
  function daysSince(iso) { if (!iso) return null; var d = new Date(iso + 'T00:00:00'); if (isNaN(d)) return null; return Math.floor((Date.now() - d.getTime()) / 86400000); }
  function addDays(iso, n) { var d = new Date(iso + 'T00:00:00'); d.setDate(d.getDate() + n); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); }
  function toast(m) { var t = document.getElementById('toast'); if(!t){ t=document.createElement('div'); t.id='toast'; t.className='toast vmops'; document.body.appendChild(t); } t.textContent = m; t.classList.add('show'); clearTimeout(t._t); t._t = setTimeout(function () { t.classList.remove('show'); }, 2200); }
  function legacyCopy(t) { var ta = document.createElement('textarea'); ta.value = t; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.focus(); ta.select(); try { document.execCommand('copy'); toast('Copied'); } catch (e) {} document.body.removeChild(ta); }
  function copyText(t) { if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(t).then(function () { toast('Copied'); }, function () { legacyCopy(t); }); } else { legacyCopy(t); } }
  // ---- undo for bulk / status changes (snapshot the affected findings' overrides) ----
  function snapOv(fs) { return fs.map(function (f) { var k = keyOf(f); return { k: k, ov: STATE.ov[k] ? JSON.parse(JSON.stringify(STATE.ov[k])) : null }; }); }
  function undoOv(snap) { snap.forEach(function (s) { if (s.ov) STATE.ov[s.k] = s.ov; else delete STATE.ov[s.k]; }); save('vmops-overrides', STATE.ov); currentView(); toast('Undone'); }
  function toastUndo(msg, snap) {
    var t = document.getElementById('toast'); if (!t) { t = document.createElement('div'); t.id = 'toast'; t.className = 'toast vmops'; document.body.appendChild(t); }
    t.innerHTML = esc(msg) + ' <a href="#" class="toast-undo">Undo</a>';
    t.classList.add('show'); clearTimeout(t._t); t._t = setTimeout(function () { t.classList.remove('show'); }, 6000);
    var u = t.querySelector('.toast-undo'); if (u) u.onclick = function (e) { e.preventDefault(); undoOv(snap); t.classList.remove('show'); };
  }
  function norm(h) { return String(h || '').trim().split('.')[0].toUpperCase(); }
  var SHIELD = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>';
  function privSlim() { return '<div class="privacy slim">' + SHIELD + '<div><b>100% local.</b> Findings, status, owners, notes, and configuration stay in this browser — nothing is uploaded. Ticketing is via deep-links to your own Jira / ServiceNow.</div></div>'; }
  // Privacy notice for the Ask AI page: the model runs on-device, so nothing leaves the browser.
  function askPriv() { return '<div class="privacy slim info">' + SHIELD + '<div><b>100% on-device.</b> Ask AI runs a small language model in your browser (Transformers.js) — your question and findings never leave this browser, and there’s no API key.</div></div>'; }

  // ---------- model / persistence ----------
  var STATUS = [
    { k: 'new', l: 'New', open: true, d: 'Freshly imported — not yet reviewed.' },
    { k: 'triaged', l: 'Triaged', open: true, d: 'Reviewed & assessed (owner/priority set); fix not started.' },
    { k: 'in_remediation', l: 'In Remediation', open: true, d: 'Actively being fixed — patch/config in progress.' },
    { k: 'resolved', l: 'Resolved', open: false, d: 'Fixed/remediated. Auto-set when a rescan no longer detects it.' },
    { k: 'risk_accepted', l: 'Risk Accepted', open: false, d: 'Deliberately accepted — won’t fix now; documented & tracked.' },
    { k: 'false_positive', l: 'False Positive', open: false, d: 'Not a real vulnerability — scanner misdetection; dismissed.' }
  ];
  var SLABEL = {}; STATUS.forEach(function (s) { SLABEL[s.k] = s.l; });
  var ST_ORDER = {}; STATUS.forEach(function (s, i) { ST_ORDER[s.k] = i; });   // sort by workflow order (new, triaged, in remediation, resolved...), not alphabetically
  var OPEN_STATES = STATUS.filter(function (s) { return s.open; }).map(function (s) { return s.k; });
  var SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  // Weights let the user tune how the risk models combine (see riskComponents). 1 = default.
  var DEFAULT_WEIGHTS = { cvss: 1, epss: 1, kev: 1, lev: 1, ssvc: 1, asset: 1 };
  var RW_SIGNALS = [
    { k: 'cvss', l: 'CVSS / severity' }, { k: 'epss', l: 'EPSS probability' },
    { k: 'kev', l: 'Exploitation (KEV / ransomware / PoC)' }, { k: 'lev', l: 'LEV (already-exploited)' },
    { k: 'ssvc', l: 'SSVC decision' }, { k: 'asset', l: 'Asset criticality' }
  ];
  var DEFAULT_CFG = { brand: '', brandIcon: '', brandIconColor: '', sla: { Critical: 7, High: 30, Medium: 90, Low: 180 }, jiraBase: '', jiraPid: '', jiraType: '', snowBase: '', tioAccess: '', tioSecret: '', meUrl: '', meClientId: '', meClientSecret: '', epssLive: false, recurThreshold: 1, navHidden: [], riskWeights: Object.assign({}, DEFAULT_WEIGHTS) };
  var DEFAULT_BRAND = 'Vulnerability Management Console';
  var DEFAULT_ICON_COLOR = '#28415d';

  function load(k, d) { try { var v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch (e) { return d; } }
  function save(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch (e) { return false; } }
  function safeDecode(s) { try { return decodeURIComponent(s); } catch (e) { return s; } }   // a stray % in a hand-typed/shared deep link must not throw out of the router

  var STATE = {
    findings: load('vmops-findings', []),
    ov: load('vmops-overrides', {}),       // key -> {status, owner, notes, updated}
    assets: load('vmops-assets', {}),      // hostNorm -> {crit, owner, tags}
    sbom: load('vmops-sbom', null),        // {name, at, components:[{name,version,type,license,vulns}]}
    cfg: Object.assign({}, DEFAULT_CFG, load('vmops-config', {})),
    sort: { col: 'risk', dir: -1 },
    filt: defaultFilt()
  };
  STATE.cfg.sla = Object.assign({}, DEFAULT_CFG.sla, STATE.cfg.sla || {});
  STATE.cfg.riskWeights = Object.assign({}, DEFAULT_WEIGHTS, STATE.cfg.riskWeights || {});
  STATE._newKeys = {}; try { (JSON.parse(localStorage.getItem('vmops-newkeys') || '[]') || []).forEach(function (k) { STATE._newKeys[k] = 1; }); } catch (e) {}
  STATE._colW = {}; try { STATE._colW = JSON.parse(localStorage.getItem('vmops-colw') || '{}') || {}; } catch (e) {}
  STATE._colHidden = {}; try { STATE._colHidden = JSON.parse(localStorage.getItem('vmops-colhidden') || '{}') || {}; } catch (e) {}

  // Custom branding: apply the configured app name to the nav brand + document title, and rebuild the
  // favicon (monogram + color) — all default to the Vulnerability Management Console look when unset.
  function brandInitials(s) {
    var w = String(s || '').trim().split(/\s+/).filter(Boolean);
    if (!w.length) return 'VM';
    if (/^[A-Z0-9]{2,3}$/.test(w[0])) return w[0].slice(0, 3);   // leading acronym, e.g. "VM"
    if (w.length === 1) return w[0].slice(0, 2).toUpperCase();
    return (w[0].charAt(0) + w[1].charAt(0)).toUpperCase();
  }
  function faviconURI(mono, col) {
    var fs = mono.length >= 3 ? 24 : 34;
    var svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='14' fill='" + col +
      "'/><text x='32' y='45' font-family='Georgia,serif' font-size='" + fs + "' fill='#faf9f7' text-anchor='middle'>" + mono + "</text></svg>";
    return 'data:image/svg+xml,' + encodeURIComponent(svg);
  }
  // Top-menu items a user can hide from Settings (Settings itself is intentionally never hideable, so the
  // controls stay reachable; hidden routes are still reachable by direct link).
  var NAV_ITEMS = [
    { k: 'ask', label: 'Ask AI', sel: '.tab[data-route="ask"]' },
    { k: 'report', label: 'Morning Report', sel: '.tab[data-route="report"]' },
    { k: 'dashboards', label: 'Dashboards', sel: '.navmenu[data-menu="dashboards"]' },
    { k: 'findings', label: 'Findings', sel: '.tab[data-route="findings"]' },
    { k: 'campaigns', label: 'Campaigns', sel: '.tab[data-route="campaigns"]' },
    { k: 'tools', label: 'Tools', sel: '.navmenu[data-menu="tools"]' },
    { k: 'faq', label: 'FAQ', sel: '.tab[data-route="faq"]' },
    { k: 'about', label: 'About', sel: '.tab[data-route="about"]' }
  ];
  // Sub-items inside the dropdown menus, individually hideable. Keyed by data-route (unique across the nav).
  var NAV_SUBS = [
    { group: 'Dashboards menu', parent: 'dashboards', items: [
      { k: 'dashboard', label: 'Overview' }, { k: 'assets', label: 'Asset Inventory' }, { k: 'remediations', label: 'Remediations' },
      { k: 'sbom', label: 'Licenses & SBOM' }, { k: 'agent-coverage', label: 'Agent Coverage' }, { k: 'coverage', label: 'Scanner Coverage' },
      { k: 'tvd', label: 'Tenable' }, { k: 'qualys', label: 'Qualys' }, { k: 'rapid7', label: 'Rapid7' }, { k: 'crowdstrike', label: 'CrowdStrike' }, { k: 'wiz', label: 'Wiz' }
    ] },
    { group: 'Tools menu', parent: 'tools', items: [
      { k: 'tenable', label: 'Tenable Analyzer' }, { k: 'prompt-scanner', label: 'AI Prompt Scanner' }, { k: 'nasl', label: 'NASL Viewer' },
      { k: 'search', label: 'CVE Search' }, { k: 'exploited', label: 'Exploited' }, { k: 'stats', label: 'CVE Statistics' },
      { k: 'browse', label: 'Browse the corpus' }, { k: 'latest', label: 'Latest CVEs' }, { k: 'triage', label: 'Triage' }, { k: 'eol', label: 'End of Life' }
    ] }
  ];
  function applyNavHidden() {
    var hidden = STATE.cfg.navHidden || [];
    NAV_ITEMS.forEach(function (it) { var el = document.querySelector('nav.top ' + it.sel); if (el) el.style.display = hidden.indexOf(it.k) > -1 ? 'none' : ''; });
    NAV_SUBS.forEach(function (g) { g.items.forEach(function (it) { var el = document.querySelector('nav.top .navmenu-list a[data-route="' + it.k + '"]'); if (el) el.style.display = hidden.indexOf(it.k) > -1 ? 'none' : ''; }); });
  }
  function applyBrand() {
    var name = (STATE.cfg.brand || '').trim() || DEFAULT_BRAND;
    window.VM_BRAND = name;   // read by the CVE-shell views (About, footer, diagram, ledes)
    var el = document.querySelector('nav.top .brand');
    if (el) {
      // Stack the brand: all but the last word on line 1, the last word on line 2 (shrunk to fit).
      var w = name.split(/\s+/).filter(Boolean);
      if (w.length > 1) { var last = w.pop(); el.innerHTML = '<span class="brand-l1">' + esc(w.join(' ')) + '</span><span class="brand-l2">' + esc(last) + '</span>'; el.classList.add('two-line'); }
      else { el.textContent = name; el.classList.remove('two-line'); }
    }
    [].forEach.call(document.querySelectorAll('.brandname'), function (s) { s.textContent = name; });
    try { document.title = name; } catch (e) {}
    var mono = ((STATE.cfg.brandIcon || '').trim() || brandInitials(name)).slice(0, 3);
    var col = (STATE.cfg.brandIconColor || '').trim() || DEFAULT_ICON_COLOR;
    var link = document.getElementById('favicon');
    if (link) { var nw = link.cloneNode(false); nw.setAttribute('href', faviconURI(mono, col)); link.parentNode.replaceChild(nw, link); }
    applyNavHidden();
  }
  applyBrand();   // vmops.js loads after the nav, so the brand element already exists

  function keyOf(f) { return f.cve + '|' + norm(f.host); }
  function ovOf(f) { return STATE.ov[keyOf(f)] || {}; }
  function statusOf(f) { return ovOf(f).status || 'new'; }
  function isOpen(f) { return OPEN_STATES.indexOf(statusOf(f)) !== -1; }
  function slaWindow(f) { return STATE.cfg.sla[f.severity] != null ? STATE.cfg.sla[f.severity] : null; }
  function dueDate(f) { var w = slaWindow(f); return w == null ? null : addDays(f.firstSeen, w); }
  function dueIn(f) { var dd = dueDate(f); return dd == null ? null : -daysSince(dd); } // days remaining (neg = overdue)
  function slaState(f) {
    if (!isOpen(f)) return 'done';
    var di = dueIn(f); if (di == null) return 'ok';
    if (di < 0) return 'overdue'; if (di <= 3) return 'soon'; return 'ok';
  }
  // ---------- CVE exploitation intel (reuses the app's own KEV + exploited datasets) ----------
  var INTEL = { kev: null, expl: null, loaded: false, loading: null };
  function ensureIntel() {
    if (INTEL.loaded) return Promise.resolve();
    if (INTEL.loading) return INTEL.loading;
    INTEL.loading = Promise.all([
      fetch('data/kev.json').then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }),
      fetch('data/exploited.json').then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }),
      fetch('data/epss.json.gz').then(function (r) { return r.ok ? new Response(r.body.pipeThrough(new DecompressionStream('gzip'))).json() : null; }).catch(function () { return null; })
    ]).then(function (r) {
      INTEL.kev = {}; (((r[0] || {}).entries) || []).forEach(function (e) { INTEL.kev[e.id] = { added: e.added, due: e.due, ransomware: !!e.ransomware }; });
      INTEL.expl = {}; (((r[1] || {}).cves) || []).forEach(function (c) { INTEL.expl[c.cve] = { sources: c.sources || [], tte: c.tte, date: c.exploit_date }; });
      INTEL.epss = (r[2] && r[2].scores) || {};
      INTEL.loaded = true;
    });
    return INTEL.loading;
  }
  function cveIntel(cve) {
    var k = INTEL.kev && INTEL.kev[cve], x = INTEL.expl && INTEL.expl[cve];
    var e = INTEL.epss && INTEL.epss[cve];
    return { kev: !!k, ransomware: !!(k && k.ransomware), kevDue: k && k.due, exploit: !!x, sources: (x && x.sources) || [], exploitDate: x && x.date, epss: (e != null ? e : null) };
  }
  // Priority verdict: confirmed/likely exploitation drives P1, else severity tiers (mirrors CVE Explorer).
  function priorityOf(f) {
    if (!isOpen(f)) return null;
    var it = cveIntel(f.cve), sev = f.severity;
    if (it.kev || it.ransomware || (it.exploit && (sev === 'Critical' || sev === 'High'))) return 'P1';
    if (it.exploit || sev === 'Critical' || sev === 'High') return 'P2';
    return 'P3';
  }
  // ---------- Asset register: per-host business context that feeds the risk score ----------
  // Criticality tiers and the 0..1 fraction each contributes to the asset risk component.
  var ASSET_CRITS = [
    { k: 'critical', l: 'Critical', frac: 1 }, { k: 'high', l: 'High', frac: 0.7 },
    { k: 'medium', l: 'Medium', frac: 0.4 }, { k: 'low', l: 'Low', frac: 0.15 }
  ];
  function assetOf(host) { var h = norm(host); return STATE.assets[h] || null; }
  function assetCrit(host) { var a = assetOf(host); return a && a.crit ? a.crit : ''; }        // '' = unset
  function assetFrac(host) { var c = assetCrit(host); if (!c) return 0.4; for (var i = 0; i < ASSET_CRITS.length; i++) if (ASSET_CRITS[i].k === c) return ASSET_CRITS[i].frac; return 0.4; }
  function setAsset(host, patch) { var h = norm(host); var a = STATE.assets[h] || {}; Object.assign(a, patch); if (!a.crit && !a.owner && !(a.tags && a.tags.length)) delete STATE.assets[h]; else STATE.assets[h] = a; save('vmops-assets', STATE.assets); }

  // ---------- Risk model: a transparent weighted blend the user can tune (Settings) ----------
  // Each signal contributes raw(0..1) * budget * weight. Budgets set the model's default shape;
  // weights (cfg.riskWeights, 1 = default) let the user re-balance without it being a black box.
  var RISK_BUDGET = { cvss: 300, epss: 300, kev: 600, lev: 300, ssvc: 300, asset: 300 };
  var SEV_FRAC = { Critical: 1, High: 0.75, Medium: 0.5, Low: 0.25 };
  function levCached(cve) { var y = (String(cve).match(/CVE-(\d{4})-/) || [])[1]; var m = y && LEV_CACHE[y]; return (m && m[cve] != null) ? m[cve] : null; }
  // Raw 0..1 value per signal for a finding.
  function riskRaw(f) {
    var it = cveIntel(f.cve);
    var lev = levCached(f.cve);
    return {
      cvss: f.cvss != null ? Math.max(0, Math.min(1, f.cvss / 10)) : (SEV_FRAC[f.severity] != null ? SEV_FRAC[f.severity] : 0.5),
      epss: it.epss != null ? it.epss : 0,
      kev: it.kev ? 1 : it.ransomware ? 0.85 : it.exploit ? 0.6 : 0,
      lev: lev != null ? lev : 0,
      ssvc: (function () { var v = ssvcVerdict(it.kev, it.exploit, f.cvss).v; return v === 'Act' ? 1 : v === 'Attend' ? 0.5 : 0; })(),
      asset: assetFrac(f.host)
    };
  }
  var RISK_LABEL = { cvss: 'CVSS / severity', epss: 'EPSS', kev: 'Exploitation (KEV)', lev: 'LEV', ssvc: 'SSVC', asset: 'Asset criticality' };
  // Per-signal point contributions (after weights) — powers the drawer breakdown + transparency.
  function riskComponents(f) {
    var raw = riskRaw(f), w = (STATE.cfg && STATE.cfg.riskWeights) || DEFAULT_WEIGHTS, out = [];
    ['cvss', 'epss', 'kev', 'lev', 'ssvc', 'asset'].forEach(function (k) {
      out.push({ key: k, label: RISK_LABEL[k], raw: raw[k], weight: w[k] != null ? w[k] : 1, pts: Math.round(raw[k] * RISK_BUDGET[k] * (w[k] != null ? w[k] : 1)) });
    });
    return out;
  }
  function riskBreakdownHtml(f) {
    var comps = riskComponents(f), max = Math.max.apply(null, comps.map(function (c) { return c.pts; }).concat([1]));
    return '<div class="rbk">' + comps.map(function (c) {
      return '<div class="rbk-row"><span>' + esc(c.label) + (c.weight !== 1 ? ' <span class="muted" style="font-size:10px">×' + c.weight + '</span>' : '') + '</span>' +
        '<span class="rbk-bar"><span class="rbk-fill" style="width:' + (max ? Math.round(c.pts / max * 100) : 0) + '%"></span></span>' +
        '<span class="rbk-pts">' + c.pts + '</span></div>';
    }).join('') + '</div>';
  }
  function riskScore(f) { // weighted model (riskComponents) + SLA pressure + age; resolved sinks below open
    var s = 0; riskComponents(f).forEach(function (c) { s += c.pts; });
    var di = dueIn(f); if (di != null && isOpen(f)) s += di < 0 ? 60 + Math.min(40, -di) : Math.max(0, 30 - di);
    s += Math.min(20, (daysSince(f.firstSeen) || 0) / 10);
    if (!isOpen(f)) s -= 4000;   // resolved/accepted always rank below anything open
    return s;
  }
  // Preload the local LEV feed for every CVE-year present in the findings so the LEV signal
  // participates in scoring/sorting immediately (otherwise it only loads lazily in the drawer).
  function preloadLev() {
    var years = {}; STATE.findings.forEach(function (f) { var y = (String(f.cve).match(/CVE-(\d{4})-/) || [])[1]; if (y) years[y] = 1; });
    var ys = Object.keys(years).filter(function (y) { return !LEV_CACHE[y]; });
    if (!ys.length) return;
    Promise.all(ys.map(function (y) { return fetch('data/lev/' + y + '.json').then(function (r) { return r.ok ? r.json() : {}; }).catch(function () { return {}; }).then(function (m) { LEV_CACHE[y] = m || {}; }); }))
      .then(function () { try { window.dispatchEvent(new Event('hashchange')); } catch (e) {} });
  }
  // ---------- Root-cause grouping: a "fix key" so one remediation rolls up its findings ----------
  // Derive the product/package a fix targets from the finding name (strip versions, parentheticals,
  // trailing qualifiers), so multiple CVEs in the same product collapse to one remediation.
  function fixLabel(f) {
    var raw = String(f.name || f.cve || '');
    var n = raw.replace(/\s*\([^)]*\)\s*/g, ' ').trim();                        // drop "(Log4Shell)", "(Rapid7)"
    // When the name is just a CVE id (e.g. multi-scanner rows), there is no product to derive —
    // group by the CVE itself so each fix is one row, not one giant bucket.
    if (/^CVE-\d/i.test(n) || n === '') return String(f.cve || raw).toUpperCase().replace(/\s*\([^)]*\)\s*/g, '').trim();
    n = n.replace(/\b\d+(\.\d+)*(\.x)?\b/g, '').replace(/\bv\d+\b/gi, '');       // drop version tokens
    n = n.replace(/\b(remote code execution|rce|sqli|path traversal|overflow|elevation|ssrf|dos|enum(eration)?|bypass)\b/gi, '');
    n = n.replace(/\s{2,}/g, ' ').trim();
    return n || raw.trim();
  }
  function fixKey(f) { return fixLabel(f).toLowerCase(); }
  // ---------- the other prioritization models, per CVE (for the drawer): EPSS, NIST LEV, SSVC ----------
  // Same sources the CVE detail page uses: EPSS from the bundled local feed, LEV from the local data/lev/<year>.json,
  // SSVC the simplified Act/Attend/Track derived from exploitation + impact (CISA's authoritative SSVC is on the detail page).
  function pct(x) { return Math.round((x || 0) * 100) + '%'; }
  function isHigh(cvss) { return cvss != null && !isNaN(cvss) && cvss >= 7; }
  function epssVerdict(e) { if (e == null) return { v: 'No data', why: '' }; if (e >= 0.5) return { v: 'High', why: pct(e) + ' chance in 30 days' }; if (e >= 0.1) return { v: 'Elevated', why: pct(e) + ' chance in 30 days' }; return { v: 'Low', why: pct(e) + ' chance in 30 days' }; }
  function levVerdict(l) { if (l == null) return { v: 'No data', why: '' }; if (l >= 0.5) return { v: 'Likely exploited', why: pct(l) + ' lower-bound it was already exploited' }; if (l >= 0.1) return { v: 'Possibly', why: pct(l) + ' lower-bound' }; return { v: 'Unlikely', why: pct(l) + ' lower-bound' }; }
  function ssvcVerdict(kev, exploit, cvss) { var a = kev || exploit, t = isHigh(cvss); if (a && t) return { v: 'Act', why: 'active exploitation · high impact' }; if (a) return { v: 'Attend', why: 'active exploitation' }; if (t) return { v: 'Attend', why: 'high impact' }; return { v: 'Track', why: 'no active exploitation · limited impact' }; }
  // Live EPSS lookup from FIRST.org, used ONLY when the user opts in (Settings, off by default) for a CVE
  // missing from the bundled local feed. Sends just the CVE id to a third party; see the Settings explanation.
  function epssFor(cve) { return fetch('https://api.first.org/data/v1/epss?cve=' + encodeURIComponent(cve)).then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }).then(function (d) { var r = d && d.data && d.data[0]; return r ? parseFloat(r.epss) : null; }); }
  var LEV_CACHE = {};
  function levFor(cve) {
    var y = (cve.match(/CVE-(\d{4})-/) || [])[1]; if (!y) return Promise.resolve(null);
    if (LEV_CACHE[y]) return Promise.resolve(LEV_CACHE[y][cve] != null ? LEV_CACHE[y][cve] : null);
    return fetch('data/lev/' + y + '.json').then(function (r) { return r.ok ? r.json() : {}; }).catch(function () { return {}; })
      .then(function (m) { LEV_CACHE[y] = m || {}; return LEV_CACHE[y][cve] != null ? LEV_CACHE[y][cve] : null; });
  }
  function setOverride(f, patch) {
    var k = keyOf(f), o = STATE.ov[k] || {};
    Object.assign(o, patch, { updated: new Date().toISOString() });
    STATE.ov[k] = o; save('vmops-overrides', STATE.ov);
  }
  // Append-only status-update log per finding (dated entries, newest first).
  function updatesOf(f) { return ovOf(f).updates || []; }
  function addUpdate(f, text) {
    text = (text || '').trim(); if (!text) return;
    var k = keyOf(f), o = STATE.ov[k] || {};
    o.updates = o.updates || []; o.updates.unshift({ at: new Date().toISOString(), text: text }); o.updated = new Date().toISOString();
    STATE.ov[k] = o; save('vmops-overrides', STATE.ov);
  }
  function renderUpdates(f) {
    var u = updatesOf(f);
    if (!u.length) return '<div class="muted" style="font-size:12.5px">No updates yet.</div>';
    return u.map(function (x) {
      var d = new Date(x.at), ds = isNaN(d) ? x.at : (d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
      return '<div style="border-left:2px solid var(--line);padding:1px 0 6px 10px;margin-bottom:7px"><div style="font-size:11px;color:var(--faint)">' + esc(ds) + '</div><div style="font-size:13px">' + esc(x.text) + '</div></div>';
    }).join('');
  }
  function owners() { var s = {}; STATE.findings.forEach(function (f) { var o = ovOf(f).owner; if (o) s[o] = 1; }); return Object.keys(s).sort(); }
  function repoOf(f) { return (ovOf(f).repo || f.repo || ''); }
  function repos() { var s = {}; STATE.findings.forEach(function (f) { var r = repoOf(f); if (r) s[r] = 1; }); return Object.keys(s).sort(); }

  // ---------- filtering / sorting ----------
  function visibleFindings() {
    var f = STATE.filt;
    var list = STATE.findings.filter(function (x) {
      if (f.open && !isOpen(x)) return false;
      if (f.status && statusOf(x) !== f.status) return false;
      if (f.sev && x.severity !== f.sev) return false;
      if (f.owner && (ovOf(x).owner || '') !== f.owner) return false;
      if (f.repo && repoOf(x) !== f.repo) return false;
      if (f.overdue && slaState(x) !== 'overdue') return false;
      if (f.exploited) { var it = cveIntel(x.cve); if (!it.kev && !it.exploit) return false; }
      if (f.epssHi) { var ee = cveIntel(x.cve).epss; if (ee == null || ee < 0.5) return false; }
      if (f.noTicket) { if (ticketOf(x)) return false; if (!isOpen(x)) return false; }
      if (f.noowner) { if (ovOf(x).owner) return false; if (!isOpen(x)) return false; }
      if (f.recurring && !isRecurring(x)) return false;
      if (f.fresh && !isNewKey(keyOf(x))) return false;
      if (f.seen) { var _ds = daysSince(x.firstSeen); if (_ds == null || _ds > +f.seen) return false; }
      if (f.q) { var q = f.q.toLowerCase(); if ((x.cve + ' ' + x.host + ' ' + (x.name || '') + ' ' + (x.desc || '') + ' ' + repoOf(x) + ' ' + (ovOf(x).owner || '')).toLowerCase().indexOf(q) === -1) return false; }
      if (f.colf) { for (var _cid in f.colf) { if (f.colf[_cid] && String(colfVal(_cid, x)).toLowerCase().indexOf(f.colf[_cid].toLowerCase()) < 0) return false; } }
      return true;
    });
    var c = STATE.sort.col, d = STATE.sort.dir;
    // risk/epss/vpr read naturally (a then b) and default to descending via STATE.sort.dir, so the header
    // arrow matches the real order. Risk is scored once per row here rather than on every comparison.
    var rsk = null; if (c === 'risk') { rsk = {}; list.forEach(function (f) { rsk[keyOf(f)] = riskScore(f); }); }
    list.sort(function (a, b) {
      var va, vb;
      if (c === 'risk') { va = rsk[keyOf(a)]; vb = rsk[keyOf(b)]; }
      else if (c === 'sev') { va = SEV_ORDER[a.severity]; vb = SEV_ORDER[b.severity]; }
      else if (c === 'due') { va = dueIn(a); vb = dueIn(b); va = va == null ? 1e9 : va; vb = vb == null ? 1e9 : vb; }
      else if (c === 'status') { va = ST_ORDER[statusOf(a)]; vb = ST_ORDER[statusOf(b)]; }
      else if (c === 'age') { va = daysSince(a.firstSeen) || 0; vb = daysSince(b.firstSeen) || 0; }
      else if (c === 'epss') { va = cveIntel(a.cve).epss || 0; vb = cveIntel(b.cve).epss || 0; }
      else if (c === 'vpr') { va = a.vpr || 0; vb = b.vpr || 0; }
      else if (c === 'ticket') { va = (ticketOf(a) && ticketOf(a).key) || '~'; vb = (ticketOf(b) && ticketOf(b).key) || '~'; }   // linked first, no-ticket last
      else if (c === 'owner') { va = (ovOf(a).owner || '~'); vb = (ovOf(b).owner || '~'); }
      else if (c === 'repo') { va = (repoOf(a) || '~'); vb = (repoOf(b) || '~'); }
      else { va = (a[c] || ''); vb = (b[c] || ''); }
      if (va < vb) return -d; if (va > vb) return d; return 0;
    });
    return list;
  }

  // ---------- KPIs ----------
  function kpis() {
    var open = STATE.findings.filter(isOpen);
    var overdue = open.filter(function (f) { return slaState(f) === 'overdue'; });
    var withSla = open.filter(function (f) { return slaWindow(f) != null; });
    var inSla = withSla.filter(function (f) { return slaState(f) !== 'overdue'; });
    var comp = withSla.length ? Math.round(inSla.length / withSla.length * 100) : 100;
    var crit = open.filter(function (f) { return f.severity === 'Critical'; });
    var exploited = open.filter(function (f) { var it = cveIntel(f.cve); return it.kev || it.exploit; });
    var epssHi = open.filter(function (f) { var e = cveIntel(f.cve).epss; return e != null && e >= 0.5; });
    var newScan = STATE.findings.filter(function (f) { return isNewKey(keyOf(f)); });
    // MTTR: mean days from first-seen to resolution, across resolved findings
    var mttrVals = STATE.findings.filter(function (f) { return statusOf(f) === 'resolved'; }).map(function (f) {
      var ups = updatesOf(f), r = null;
      for (var i = 0; i < ups.length; i++) { if (/resolv/i.test(ups[i].text || '')) { r = ups[i].at; break; } }
      r = r || ovOf(f).updated; if (!f.firstSeen || !r) return null;
      var d = (new Date(r) - new Date(f.firstSeen)) / 86400000; return d >= 0 ? d : null;
    }).filter(function (v) { return v != null; });
    var mttr = mttrVals.length ? Math.round(mttrVals.reduce(function (a, b) { return a + b; }, 0) / mttrVals.length) : null;
    return { total: STATE.findings.length, open: open.length, overdue: overdue.length, comp: comp, crit: crit.length, assets: assetCount(), unassigned: open.filter(function (f) { return !ovOf(f).owner; }).length, noTicket: open.filter(function (f) { return !ticketOf(f); }).length, exploited: exploited.length, epssHi: epssHi.length, newScan: newScan.length, recurring: STATE.findings.filter(isRecurring).length, mttr: mttr };
  }
  function assetCount() { var s = {}; STATE.findings.forEach(function (f) { s[norm(f.host)] = 1; }); return Object.keys(s).length; }
  // Rank systems (by normalized short hostname) with the most OPEN findings, for the dashboard.
  function topHosts(limit) {
    var m = {};
    STATE.findings.filter(isOpen).forEach(function (f) {
      var k = norm(f.host); if (!k) return;
      var e = m[k] || (m[k] = { host: k, n: 0, crit: 0, risk: -1e9 });
      e.n++; if (f.severity === 'Critical') e.crit++;
      var r = riskScore(f); if (r > e.risk) e.risk = r;
    });
    return Object.keys(m).map(function (k) { return m[k]; })
      .sort(function (a, b) { return b.n - a.n || b.crit - a.crit || b.risk - a.risk; })
      .slice(0, limit || 8);
  }

  // ---------- views ----------
  // Mirror the shell's global setActive: reconcile top tabs AND dropdown items + .menu-active,
  // so an intra-VMOPS re-render can't leave a stale CVE-Intelligence/Tools menu highlight.
  function setActive(r) {
    [].forEach.call(document.querySelectorAll('nav.top a.tab, nav.top .navmenu-list a'), function (a) { a.classList.toggle('active', a.getAttribute('data-route') === r); });
    [].forEach.call(document.querySelectorAll('nav.top .navmenu'), function (m) { m.classList.toggle('menu-active', !!m.querySelector('.navmenu-list a.active')); });
  }

  function viewDashboard() {
    setActive('dashboard');
    if (!STATE.findings.length) return viewEmpty('dashboard'); preloadLev();
    var k = kpis();
    var bySev = ['Critical', 'High', 'Medium', 'Low'].map(function (s) { return { s: s, n: STATE.findings.filter(function (f) { return f.severity === s && isOpen(f); }).length }; });
    var byStatus = STATUS.map(function (st) { return { l: st.l, k: st.k, n: STATE.findings.filter(function (f) { return statusOf(f) === st.k; }).length }; });
    var top = STATE.findings.filter(isOpen).slice().sort(function (a, b) { return riskScore(b) - riskScore(a); }).slice(0, 8);
    var hosts = topHosts(8);
    app.innerHTML =
      '<header class="view"><div class="overline">Operations dashboard</div><h1>Where the program stands</h1>' +
      '<p class="lede wide">Live read-out over your imported scan findings — status, SLA pressure, and the highest-risk open work.</p></header>' +
      workflowStrip(k) +
      privSlim() +
      '<div class="kpis">' +
      kpiL('Open findings', k.open, k.total + ' total', '', '#/findings?open=1') +
      kpiL('Overdue (SLA)', k.overdue, 'past remediation window', k.overdue ? 'crit' : 'ok', '#/findings?overdue=1') +
      kpiL('KEV / exploited', k.exploited, 'actively exploited, open', k.exploited ? 'crit' : 'ok', '#/findings?exploited=1&open=1') +
      kpiL('EPSS ≥ 50%', k.epssHi, 'high exploit probability', k.epssHi ? '' : 'ok', '#/findings?epssHi=1&open=1') +
      kpiL('Open critical', k.crit, 'severity = Critical', k.crit ? 'crit' : '', '#/findings?sev=Critical&open=1') +
      kpiL('New this scan', k.newScan, 'added since last import', '', '#/findings?fresh=1') +
      kpiL('Recurring', k.recurring, 'reopened after a fix', k.recurring ? 'warn' : 'ok', '#/findings?recurring=1') +
      kpi('MTTR', k.mttr == null ? '—' : k.mttr + 'd', 'avg days to remediate') +
      kpi('SLA compliance', k.comp + '%', 'open findings within window', k.comp >= 90 ? 'ok' : '') +
      kpiL('Unassigned', k.unassigned, 'no owner set', '', '#/findings?noowner=1') +
      kpiL('No ticket', k.noTicket, 'open findings, none linked', k.noTicket ? '' : 'ok', '#/findings?noTicket=1') +
      kpi('Assets', k.assets, 'distinct hosts') +
      '</div>' +
      dashCampaigns() +
      '<h2>Open by severity</h2>' + barRows(bySev.map(function (x) { return { l: x.s, n: x.n, cls: x.s.toLowerCase(), href: '#/findings?sev=' + x.s + '&open=1' }; })) +
      '<h2>By status</h2>' + barRows(byStatus.map(function (x) { return { l: x.l, n: x.n, color: 'var(--' + (STATUS_BAR_COLOR[x.k] || 'accent') + ')', href: '#/findings?status=' + x.k }; })) +
      '<h2>Highest-risk open findings</h2>' +
      (top.length ? '<div style="overflow-x:auto">' + gridTable(top) + '</div>' : '<div class="empty">Nothing open.</div>') +
      '<h2>Systems with the most open findings</h2>' +
      (hosts.length ? barRows(hosts.map(function (h) { return { l: h.host + (h.crit ? '  ·  ' + h.crit + ' crit' : ''), title: h.host + ' — ' + h.n + ' open' + (h.crit ? ', ' + h.crit + ' critical' : ''), n: h.n, color: h.crit ? 'var(--crit)' : 'var(--accent)', href: '#/findings?q=' + encodeURIComponent(h.host) + '&open=1' }; })) : '<div class="empty">Nothing open.</div>');
    wireGrid();
    var wfT = document.getElementById('wfToggle');
    if (wfT) wfT.addEventListener('click', function () { save('vmops-wfstrip', !load('vmops-wfstrip', false)); viewDashboard(); });
    var wfTour = document.getElementById('wfTour');
    if (wfTour) wfTour.addEventListener('click', function () { if (window.startTour) window.startTour(); });
    // KEV / EPSS KPIs need the exploitation intel; load it and re-render once ready.
    if (!INTEL.loaded) ensureIntel().then(function () { if ((location.hash || '').indexOf('#/dashboard') === 0) viewDashboard(); });
  }

  function kpi(label, num, sub, cls) { return '<div class="kpi ' + (cls || '') + '"><div class="label">' + esc(label) + '</div><div class="num">' + esc(num) + '</div><div class="sub">' + esc(sub || '') + '</div></div>'; }
  function kpiL(label, num, sub, cls, href) { var c = kpi(label, num, sub, cls); return href ? '<a class="kpilink" href="' + href + '">' + c + '</a>' : c; }

  // "Start here" — the vulnerability-management program as a horizontal stage strip on the
  // dashboard. Each stage links into its view; the counts are live off STATE. Collapsible
  // (persisted in localStorage 'vmops-wfstrip'), so it can fold to a one-line header.
  function wfComma(n) { return (n == null ? '—' : ('' + n).replace(/\B(?=(\d{3})+(?!\d))/g, ',')); }
  function workflowStrip(k) {
    var collapsed = load('vmops-wfstrip', false);
    var camps = loadCampaigns().filter(function (c) { return c.status !== 'completed' && c.status !== 'cancelled'; }).length;
    var inRem = STATE.findings.filter(function (f) { return statusOf(f) === 'in_remediation'; }).length;
    var stages = [
      { n: 1, l: 'Inventory', num: wfComma(k.assets), sub: 'assets', href: '#/import' },
      { n: 2, l: 'Findings', num: wfComma(k.open), sub: 'open', href: '#/findings' },
      { n: 3, l: 'Triage', num: wfComma(k.unassigned), sub: 'need owner', href: '#/findings?noowner=1', cls: k.unassigned ? 'warn' : 'ok' },
      { n: 4, l: 'Campaign', num: wfComma(camps), sub: 'active', href: '#/campaigns' },
      { n: 5, l: 'Remediate', num: wfComma(inRem), sub: 'in progress', href: '#/findings?status=in_remediation' },
      { n: 6, l: 'Report', num: k.comp + '%', sub: 'SLA met', href: '#/report', cls: k.comp >= 90 ? 'ok' : '' }
    ];
    return '<div class="wfstrip' + (collapsed ? ' collapsed' : '') + '">' +
      '<div class="wfstrip-hd"><span class="wfstrip-title">Start here — the vulnerability-management workflow</span>' +
      '<span class="wfstrip-actions"><button class="wfstrip-x" id="wfTour">Take a tour</button>' +
      '<button class="wfstrip-x" id="wfToggle" aria-expanded="' + (!collapsed) + '">' + (collapsed ? 'Show' : 'Hide') + '</button></span></div>' +
      (collapsed ? '' :
        '<div class="wfstrip-row">' +
        stages.map(function (s, i) {
          return (i ? '<span class="wfarrow" aria-hidden="true">›</span>' : '') +
            '<a class="wfstage" data-wf="' + s.n + '" href="' + s.href + '">' +
            '<span class="wfstage-top"><span class="wfstage-n">' + s.n + '</span><span class="wfstage-l">' + esc(s.l) + '</span></span>' +
            '<span class="wfstage-num ' + (s.cls || '') + '">' + s.num + '</span>' +
            '<span class="wfstage-sub">' + esc(s.sub) + '</span></a>';
        }).join('') +
        '</div>');
  }
  // per-status bar colours (mirror the status pill colours)
  var STATUS_BAR_COLOR = { new: 'st-new', triaged: 'st-triaged', in_remediation: 'st-rem', resolved: 'st-res', risk_accepted: 'st-risk', false_positive: 'st-fp' };
  function barRows(rows) {
    var max = Math.max.apply(null, rows.map(function (r) { return r.n; }).concat([1]));
    return '<div class="card" style="padding:14px 18px">' + rows.map(function (r) {
      var w = Math.round(r.n / max * 100);
      var color = r.color ? r.color : (r.cls ? 'var(--' + (r.cls === 'critical' ? 'crit' : r.cls === 'high' ? 'high' : r.cls === 'medium' ? 'med' : r.cls === 'low' ? 'low' : 'accent') + ')' : 'var(--accent)');
      var inner = '<div class="barlabel" style="width:150px;flex:none;color:var(--soft);white-space:nowrap;overflow:hidden;text-overflow:ellipsis"' + (r.title ? ' title="' + esc(r.title) + '"' : '') + '>' + esc(r.l) + '</div>' +
        '<div style="flex:1;background:color-mix(in srgb,var(--line) 60%,transparent);border-radius:6px;height:18px"><div class="barfill" style="width:' + w + '%;min-width:2px;height:100%;background:' + color + ';border-radius:6px"></div></div>' +
        '<div style="width:48px;text-align:right;font-family:var(--mono);font-size:12.5px">' + r.n + '</div>';
      var style = 'display:flex;align-items:center;gap:12px;margin:7px 0;font-size:13.5px';
      return r.href
        ? '<a class="barrow" href="' + r.href + '" title="View these findings" style="' + style + ';text-decoration:none;color:inherit">' + inner + '</a>'
        : '<div style="' + style + '">' + inner + '</div>';
    }).join('') + '</div>';
  }

  // Re-render whichever ops view is active (grid/drawer handlers call this after
  // mutating state). Dispatches by route so it works from any VMOPS page.
  function currentView() {
    var h = (location.hash || '').split('?')[0];
    if (h.indexOf('#/dashboard') === 0) return viewDashboard();
    if (h.indexOf('#/campaigns') === 0) return viewCampaigns();
    if (h.indexOf('#/settings') === 0) return viewSettings();
    if (h.indexOf('#/import') === 0) return viewImport();
    return viewFindings();
  }

  // ---------- drilldown "back" affordance ----------
  // Remember where we came from so a deep-linked (drilldown) Findings view can offer a way back.
  // HashChangeEvent.oldURL is captured before the router re-renders, so it's order-independent.
  var _prevHash = '';
  window.addEventListener('hashchange', function (e) {
    try { var i = (e.oldURL || '').indexOf('#'); _prevHash = i >= 0 ? e.oldURL.substring(i) : ''; } catch (_) { _prevHash = ''; }
  });
  function routeLabel(hash) {
    var h = (hash || '').split('?')[0];
    var map = { '#/dashboard': 'the Dashboard', '#/findings': 'Findings', '#/campaigns': 'Campaigns', '#/report': 'the Morning Report', '#/import': 'Data import', '#/settings': 'Settings' };
    if (map[h]) return map[h];
    if (h.indexOf('#/campaigns/') === 0) return 'the campaign';
    if (h.indexOf('#/cve/') === 0) return 'the CVE detail';
    return 'the previous page';
  }
  // A "← Back to …" link, shown only when the current view was reached via a deep-link query
  // (i.e. a drilldown). Returns to the exact previous page when known, else the dashboard.
  function backLink() {
    var cur = location.hash || '';
    if ((cur.split('?')[1] || '') === '') return '';   // no query → arrived normally, no back link
    var prev = (_prevHash && _prevHash !== cur) ? _prevHash : '#/dashboard';
    return '<a class="backlink" href="' + esc(prev) + '">&larr; Back to ' + esc(routeLabel(prev)) + '</a>';
  }

  // ---------- bulk selection (Findings) ----------
  var selKeys = {};                       // set of selected finding keys (keyOf)
  function selectedFindings() { return Object.keys(selKeys).map(findByKey).filter(Boolean); }
  function updateBulkBar() {
    var bar = document.getElementById('bulkBar'); if (!bar) return;
    var n = selectedFindings().length;    // prune-safe count (ignores stale keys)
    bar.hidden = n === 0;
    var nb = document.getElementById('bulkN'); if (nb) nb.textContent = n;
    var boxes = document.querySelectorAll('table.grid .rowsel');
    var checked = [].filter.call(boxes, function (b) { return b.checked; }).length;
    var sa = document.getElementById('selAll');
    if (sa) { sa.checked = boxes.length > 0 && checked === boxes.length; sa.indeterminate = checked > 0 && checked < boxes.length; }
  }

  // ---------- saved + preset views (one-click filter sets) ----------
  function defaultFilt() { return { q: '', status: '', sev: '', owner: '', repo: '', open: false, overdue: false, seen: '', exploited: false, fresh: false, epssHi: false, noTicket: false, noowner: false, recurring: false, colf: {}, group: '' }; }
  var PRESET_VIEWS = [
    { id: 'exploited', name: 'Exploited (KEV / PoC)', filt: { exploited: true } },
    { id: 'epsshi', name: 'EPSS ≥ 50%', filt: { epssHi: true } },
    { id: 'overdue', name: 'Overdue', filt: { overdue: true } },
    { id: 'overduecrit', name: 'Overdue critical', filt: { sev: 'Critical', overdue: true } },
    { id: 'newscan', name: 'New this scan', filt: { fresh: true } },
    { id: 'bypatch', name: 'Group by product / fix', filt: { group: 'product' } }
  ];
  function loadViews() { try { return JSON.parse(localStorage.getItem('vmops-views') || '[]') || []; } catch (e) { return []; } }
  function saveViews(v) { try { localStorage.setItem('vmops-views', JSON.stringify(v)); } catch (e) {} }
  function applyView(filt) { STATE.filt = Object.assign(defaultFilt(), filt || {}); STATE._viewSig = JSON.stringify(STATE.filt); }
  // True when any finding filter is set (so the toolbar can offer "Clear filters").
  function filtActive() {
    var f = STATE.filt, d = defaultFilt();
    var keys = ['q', 'status', 'sev', 'owner', 'repo', 'open', 'overdue', 'seen', 'exploited', 'fresh', 'epssHi', 'noTicket', 'noowner', 'recurring', 'group'];
    for (var i = 0; i < keys.length; i++) { if (f[keys[i]] !== d[keys[i]]) return true; }
    return !!(f.colf && Object.keys(f.colf).length);
  }
  function viewFindings() {
    setActive('findings');
    // Apply a deep-link query (e.g. Ask AI -> #/findings?sev=Critical&overdue=1) ONLY when it actually
    // changes — otherwise the in-page filter handlers (which re-call viewFindings without touching the
    // hash) would re-parse the stale query every render and clobber the user's selection.
    (function(){ var q=(location.hash.split('?')[1]||''); if(q===STATE._findingsQuery) return; STATE._findingsQuery=q; if(!q) return; var p={}; q.split('&').forEach(function(kv){var a=kv.split('=');p[a[0]]=safeDecode(a[1]||'');}); STATE.filt={ q:p.q||'', status:p.status||'', sev:p.sev||'', owner:p.owner||'', repo:p.repo||'', open:p.open==='1', overdue:p.overdue==='1', seen:p.seen||'', exploited:p.exploited==='1', fresh:p.fresh==='1', epssHi:p.epssHi==='1', noTicket:p.noTicket==='1', noowner:p.noowner==='1', recurring:p.recurring==='1', colf:{}, group:STATE.filt.group||'' }; })();
    if (!STATE.findings.length) return viewEmpty('findings'); preloadLev();
    var list = visibleFindings();
    var statusOpts = '<option value="">All statuses</option>' + STATUS.map(function (s) { return '<option value="' + s.k + '"' + (STATE.filt.status === s.k ? ' selected' : '') + '>' + s.l + '</option>'; }).join('');
    var sevOpts = '<option value="">All severities</option>' + ['Critical', 'High', 'Medium', 'Low'].map(function (s) { return '<option' + (STATE.filt.sev === s ? ' selected' : '') + '>' + s + '</option>'; }).join('');
    var ownerOpts = '<option value="">All owners</option>' + owners().map(function (o) { return '<option' + (STATE.filt.owner === o ? ' selected' : '') + '>' + esc(o) + '</option>'; }).join('');
    var repoList = repos();
    var repoOpts = '<option value="">All repos</option>' + repoList.map(function (o) { return '<option' + (STATE.filt.repo === o ? ' selected' : '') + '>' + esc(o) + '</option>'; }).join('');
    var seenOpts = [['', 'Any age'], ['1', 'First seen ≤ 24h'], ['7', 'First seen ≤ 7d'], ['30', 'First seen ≤ 30d']].map(function (o) { return '<option value="' + o[0] + '"' + (STATE.filt.seen === o[0] ? ' selected' : '') + '>' + o[1] + '</option>'; }).join('');
    var savedViews = loadViews();
    var activeView = (STATE._view && JSON.stringify(STATE.filt) === STATE._viewSig) ? STATE._view : '';
    var viewOpts = '<option value="">Views…</option><optgroup label="Presets">' +
      PRESET_VIEWS.map(function (v) { return '<option value="preset:' + v.id + '"' + (activeView === 'preset:' + v.id ? ' selected' : '') + '>' + esc(v.name) + '</option>'; }).join('') + '</optgroup>' +
      (savedViews.length ? '<optgroup label="Saved">' + savedViews.map(function (v) { return '<option value="saved:' + esc(v.name) + '"' + (activeView === 'saved:' + v.name ? ' selected' : '') + '>' + esc(v.name) + '</option>'; }).join('') + '</optgroup>' : '');
    app.innerHTML =
      backLink() +
      '<header class="view"><div class="overline">Findings workbench</div><h1>Vulnerability Findings</h1>' +
      '<p class="lede">Triage your imported scan findings by status, owner, SLA, and recency — keep per-finding notes and a dated status log, and open Jira or ServiceNow tickets. Everything stays in your browser.</p></header>' +
      privSlim() +
      '<div class="toolbar">' +
      '<input type="text" id="fq" placeholder="Search CVE, host, description, repo, owner…" value="' + esc(STATE.filt.q) + '">' +
      '<select id="fStatus">' + statusOpts + '</select>' +
      '<select id="fSev">' + sevOpts + '</select>' +
      '<select id="fSeen">' + seenOpts + '</select>' +
      '<select id="fOwner">' + ownerOpts + '</select>' +
      (repoList.length ? '<select id="fRepo">' + repoOpts + '</select>' : '') +
      '<button class="btn sm" id="fOpen" style="' + (STATE.filt.open ? 'border-color:var(--accent);color:var(--accent)' : '') + '" title="Only open findings (excludes resolved, risk-accepted, and false-positive)">Open only</button>' +
      '<button class="btn sm" id="fOverdue" style="' + (STATE.filt.overdue ? 'border-color:var(--crit);color:var(--crit)' : '') + '">Overdue only</button>' +
      '<button class="btn sm" id="fExploit" style="' + (STATE.filt.exploited ? 'border-color:var(--crit);color:var(--crit)' : '') + '" title="KEV-listed or with a public exploit">Exploited only</button>' +
      '<button class="btn sm" id="fEpssHi" style="' + (STATE.filt.epssHi ? 'border-color:var(--crit);color:var(--crit)' : '') + '" title="EPSS ≥ 50% (high near-term exploitation probability)">EPSS ≥ 50%</button>' +
      '<button class="btn sm" id="fNoTicket" style="' + (STATE.filt.noTicket ? 'border-color:var(--high);color:var(--high)' : '') + '" title="Open findings with no linked ticket — needs a ticket">No ticket</button>' +
      (Object.keys(STATE._newKeys || {}).length ? '<button class="btn sm" id="fFresh" style="' + (STATE.filt.fresh ? 'border-color:var(--accent);color:var(--accent)' : '') + '" title="Added in the most recent scan">New only</button>' : '') +
      '<button class="btn sm" id="fRecur" style="' + (STATE.filt.recurring ? 'border-color:var(--high);color:var(--high)' : '') + '" title="Findings that were resolved and came back (recurring / flapping)">Recurring</button>' +
      '<select id="fGroup" title="Group findings"><option value="">No grouping</option><option value="cve"' + (STATE.filt.group === 'cve' ? ' selected' : '') + '>Group by CVE</option><option value="product"' + (STATE.filt.group === 'product' ? ' selected' : '') + '>Group by product / fix</option><option value="host"' + (STATE.filt.group === 'host' ? ' selected' : '') + '>Group by host</option></select>' +
      '<select id="fView" title="Saved & preset views">' + viewOpts + '</select>' +
      '<button class="btn sm" id="fViewSave" title="Save the current filters as a view">Save view</button>' +
      '<button class="btn sm" id="fCamp" title="Start a remediation campaign from the current filters">+ Campaign</button>' +
      '<details class="colmenu"><summary class="btn sm" title="Show / hide columns">Columns &#9662;</summary><div class="colmenu-pop">' +
      COL_DEFS.filter(function (c) { return c.id !== 'sel' && c.id !== 'act'; }).map(function (c) { var lbl = (typeof c.label === 'string' ? c.label.replace(/<[^>]+>/g, '') : c.id) || c.id; return '<label><input type="checkbox" class="coltoggle" data-col="' + c.id + '"' + (STATE._colHidden[c.id] ? '' : ' checked') + '> ' + esc(lbl) + '</label>'; }).join('') +
      '</div></details>' +
      '<button class="btn sm" id="fViewDel" title="Delete the active saved view"' + (activeView.indexOf('saved:') === 0 ? '' : ' style="display:none"') + '>Delete view</button>' +
      '<span class="spacer"></span>' +
      (filtActive() ? '<button class="btn sm" id="fClear" title="Clear all active filters">Clear filters</button>' : '') +
      '<span class="muted" style="font-size:12.5px">' + list.length + ' of ' + STATE.findings.length + '</span>' +
      '<button class="btn sm" id="fExport">Export CSV</button>' +
      '</div>' +
      statusLegend() +
      '<div class="bulkbar" id="bulkBar" hidden>' +
      '<span class="bulkcount"><b id="bulkN">0</b> selected</span>' +
      '<input type="text" id="bulkText" placeholder="Note / status update to apply to all selected…">' +
      '<button class="btn sm" id="bulkNote">Append note</button>' +
      '<button class="btn sm" id="bulkUpd">Add status update</button>' +
      '<select id="bulkStatus" class="status" data-s=""><option value="">Set status…</option>' + STATUS.map(function (s) { return '<option value="' + s.k + '">' + s.l + '</option>'; }).join('') + '</select>' +
      '<button class="btn sm" id="bulkOwner" title="Assign an owner to all selected">Set owner…</button>' +
      '<button class="btn sm" id="bulkJira" title="One Jira ticket covering all selected">Jira ticket</button>' +
      '<button class="btn sm" id="bulkSnow" title="One ServiceNow incident covering all selected">SNOW ticket</button>' +
      '<button class="btn sm" id="bulkTicket" title="Link one ticket key to all selected findings">Link ticket…</button>' +
      '<button class="btn sm" id="bulkCamp" title="Create a campaign scoped to the selected findings">Create campaign</button>' +
      '<select id="bulkAddCamp" title="Add the selected findings to an existing static campaign"><option value="">Add to campaign…</option>' + loadCampaigns().filter(function (c) { return c.scope && c.scope.dynamic === false; }).map(function (c) { return '<option value="' + esc(c.id) + '">' + esc(c.name) + '</option>'; }).join('') + '</select>' +
      '<button class="btn sm" id="bulkExport" title="Export the selected findings to CSV">Export CSV</button>' +
      '<button class="btn sm" id="bulkRemed" title="Copy one combined remediation script for all selected">Copy remediation</button>' +
      '<span class="spacer"></span>' +
      '<button class="btn sm" id="bulkClear">Clear selection</button>' +
      '</div>' +
      '<div class="gridwrap">' + gridOrEmpty(list) + '</div>';
    document.getElementById('fq').addEventListener('input', function () { STATE.filt.q = this.value; rerenderGridOnly(); });
    document.getElementById('fStatus').addEventListener('change', function () { STATE.filt.status = this.value; viewFindings(); });
    document.getElementById('fSev').addEventListener('change', function () { STATE.filt.sev = this.value; viewFindings(); });
    document.getElementById('fSeen').addEventListener('change', function () { STATE.filt.seen = this.value; viewFindings(); });
    document.getElementById('fOwner').addEventListener('change', function () { STATE.filt.owner = this.value; viewFindings(); });
    var fRepo = document.getElementById('fRepo'); if (fRepo) fRepo.addEventListener('change', function () { STATE.filt.repo = this.value; viewFindings(); });
    document.getElementById('fOpen').addEventListener('click', function () { STATE.filt.open = !STATE.filt.open; viewFindings(); });
    (function () { var fc = document.getElementById('fClear'); if (!fc) return; fc.addEventListener('click', function () {
      STATE.filt = defaultFilt(); STATE._view = ''; STATE._viewSig = '';
      if ((location.hash || '').indexOf('?') > -1) { STATE._findingsQuery = ''; location.hash = '#/findings'; } else viewFindings();
    }); })();
    document.getElementById('fOverdue').addEventListener('click', function () { STATE.filt.overdue = !STATE.filt.overdue; viewFindings(); });
    document.getElementById('fExploit').addEventListener('click', function () { STATE.filt.exploited = !STATE.filt.exploited; viewFindings(); });
    document.getElementById('fEpssHi').addEventListener('click', function () { STATE.filt.epssHi = !STATE.filt.epssHi; viewFindings(); });
    document.getElementById('fNoTicket').addEventListener('click', function () { STATE.filt.noTicket = !STATE.filt.noTicket; viewFindings(); });
    var fFresh = document.getElementById('fFresh'); if (fFresh) fFresh.addEventListener('click', function () { STATE.filt.fresh = !STATE.filt.fresh; viewFindings(); });
    var fRecur = document.getElementById('fRecur'); if (fRecur) fRecur.addEventListener('click', function () { STATE.filt.recurring = !STATE.filt.recurring; viewFindings(); });
    document.getElementById('fGroup').addEventListener('change', function () { STATE.filt.group = this.value; viewFindings(); });
    document.getElementById('fView').addEventListener('change', function () {
      var v = this.value; if (!v) return;
      if (v.indexOf('preset:') === 0) { var p = PRESET_VIEWS.filter(function (x) { return 'preset:' + x.id === v; })[0]; if (p) applyView(p.filt); }
      else if (v.indexOf('saved:') === 0) { var sv = loadViews().filter(function (x) { return 'saved:' + x.name === v; })[0]; if (sv) applyView(sv.filt); }
      STATE._view = v; STATE._viewSig = JSON.stringify(STATE.filt); viewFindings();
    });
    document.getElementById('fViewSave').addEventListener('click', function () {
      var nm = (prompt('Save the current filters as a view named:') || '').trim(); if (!nm) return;
      var vs = loadViews().filter(function (x) { return x.name !== nm; }); vs.push({ name: nm, filt: Object.assign({}, STATE.filt) }); saveViews(vs);
      STATE._view = 'saved:' + nm; STATE._viewSig = JSON.stringify(STATE.filt); toast('Saved view “' + nm + '”'); viewFindings();
    });
    var fcb = document.getElementById('fCamp'); if (fcb) fcb.addEventListener('click', function () {
      _campSeed = { dynamic: true, filt: { sev: STATE.filt.sev || '', status: STATE.filt.status || '', q: STATE.filt.q || '', exploited: !!STATE.filt.exploited, overdue: !!STATE.filt.overdue } };
      location.hash = '#/campaigns';
    });
    [].forEach.call(document.querySelectorAll('.coltoggle'), function (cb) {
      cb.addEventListener('change', function () {
        var id = cb.getAttribute('data-col'); if (cb.checked) delete STATE._colHidden[id]; else STATE._colHidden[id] = 1;
        try { localStorage.setItem('vmops-colhidden', JSON.stringify(STATE._colHidden)); } catch (e) {}
        injectColHide(); var gh = document.getElementById('gridHost'); if (gh) gh.style.width = totalW() + 'px';
      });
    });
    var fvd = document.getElementById('fViewDel'); if (fvd) fvd.addEventListener('click', function () {
      if ((STATE._view || '').indexOf('saved:') !== 0) return; var nm = STATE._view.slice(6);
      if (!confirm('Delete saved view “' + nm + '”?')) return;
      saveViews(loadViews().filter(function (x) { return x.name !== nm; })); STATE._view = ''; toast('Deleted view'); viewFindings();
    });
    document.getElementById('fExport').addEventListener('click', exportCsv);
    wireBulk();
    wireGrid();
    // Enrich with KEV/exploit intel on first visit, then repaint so risk rank + chips are accurate.
    if (!INTEL.loaded) ensureIntel().then(function () { if ((location.hash || '').indexOf('#/findings') === 0) viewFindings(); });
  }
  function wireBulk() {
    function need() { var fs = selectedFindings(); if (!fs.length) { toast('Select findings first'); } return fs; }
    function txtVal() { var el = document.getElementById('bulkText'); return el ? el.value.trim() : ''; }
    function clearTxt() { var el = document.getElementById('bulkText'); if (el) el.value = ''; }
    var bn = document.getElementById('bulkNote');
    if (bn) bn.addEventListener('click', function () {
      var t = txtVal(); if (!t) { toast('Type a note first'); return; }
      var fs = need(); if (!fs.length) return;
      var snap = snapOv(fs);
      fs.forEach(function (f) { var ex = ovOf(f).notes || ''; setOverride(f, { notes: ex ? ex + '\n' + t : t }); });
      clearTxt(); toastUndo('Note appended to ' + fs.length + ' finding' + (fs.length > 1 ? 's' : ''), snap);
    });
    var bu = document.getElementById('bulkUpd');
    if (bu) bu.addEventListener('click', function () {
      var t = txtVal(); if (!t) { toast('Type an update first'); return; }
      var fs = need(); if (!fs.length) return;
      fs.forEach(function (f) { addUpdate(f, t); });
      clearTxt(); toast('Update added to ' + fs.length + ' finding' + (fs.length > 1 ? 's' : ''));
    });
    var btk = document.getElementById('bulkTicket');
    if (btk) btk.addEventListener('click', function () {
      var fs = need(); if (!fs.length) return;
      var key = (prompt('Ticket key to link to ' + fs.length + ' finding' + (fs.length > 1 ? 's' : '') + ' (Jira key or SNOW number):') || '').trim();
      if (!key) return;
      fs.forEach(function (f) { setTicket(f, key); });
      toast('Linked ' + key + ' to ' + fs.length + ' finding' + (fs.length > 1 ? 's' : '')); currentView();
    });
    var bs = document.getElementById('bulkStatus');
    if (bs) bs.addEventListener('change', function () {
      var v = this.value; this.value = ''; if (!v) return;
      var fs = need(); if (!fs.length) return;
      var snap = snapOv(fs);
      fs.forEach(function (f) { setOverride(f, { status: v }); addUpdate(f, 'Status → ' + SLABEL[v]); });
      currentView();
      toastUndo('Status → ' + SLABEL[v] + ' for ' + fs.length + ' finding' + (fs.length > 1 ? 's' : ''), snap);
    });
    var bj = document.getElementById('bulkJira'); if (bj) bj.addEventListener('click', function () { var fs = need(); if (fs.length) ticketGroup('jira', fs); });
    var bsn = document.getElementById('bulkSnow'); if (bsn) bsn.addEventListener('click', function () { var fs = need(); if (fs.length) ticketGroup('snow', fs); });
    var bcp = document.getElementById('bulkCamp'); if (bcp) bcp.addEventListener('click', function () { var fs = need(); if (fs.length) { _campSeed = { dynamic: false, staticKeys: fs.map(keyOf), filt: {} }; location.hash = '#/campaigns'; } });
    var bo = document.getElementById('bulkOwner');
    if (bo) bo.addEventListener('click', function () {
      var fs = need(); if (!fs.length) return;
      var raw = prompt('Assign owner (team or person) to ' + fs.length + ' finding' + (fs.length > 1 ? 's' : '') + ' — blank to clear:'); if (raw === null) return;
      var owner = raw.trim(), snap = snapOv(fs);
      fs.forEach(function (f) { setOverride(f, { owner: owner }); }); currentView();
      toastUndo((owner ? 'Owner → ' + owner : 'Owner cleared') + ' for ' + fs.length + ' finding' + (fs.length > 1 ? 's' : ''), snap);
    });
    var bx = document.getElementById('bulkExport'); if (bx) bx.addEventListener('click', function () { var fs = need(); if (fs.length) exportCsv(fs); });
    var brm = document.getElementById('bulkRemed');
    if (brm) brm.addEventListener('click', function () {
      var fs = need(); if (!fs.length) return;
      ensureRemed().then(function () {
        var parts = fs.map(function (f) { var r = remediationFor(f); return r ? '# ===== ' + f.cve + ' · ' + (f.name || f.host) + ' · ' + f.host + '  [' + r.lang + '] =====\n' + r.script : null; }).filter(Boolean);
        if (!parts.length) { toast('No remediation samples matched the selection'); return; }
        copyText('# Combined remediation — ' + parts.length + ' of ' + fs.length + ' selected finding(s).\n# Review & test in a pilot ring before running; scripts run elevated.\n\n' + parts.join('\n\n'));
      });
    });
    var bac = document.getElementById('bulkAddCamp');
    if (bac) bac.addEventListener('change', function () {
      var id = this.value; this.value = ''; if (!id) return;
      var fs = need(); if (!fs.length) return;
      var camps = loadCampaigns(), c = camps.filter(function (x) { return x.id === id; })[0];
      if (!c || !c.scope || c.scope.dynamic !== false) { toast('Pick a static campaign'); return; }
      c.scope.staticKeys = c.scope.staticKeys || [];
      var set = {}; c.scope.staticKeys.forEach(function (k) { set[k] = 1; });
      var added = 0; fs.forEach(function (f) { var k = keyOf(f); if (!set[k]) { c.scope.staticKeys.push(k); set[k] = 1; added++; } });
      saveCampaigns(camps);
      toast('Added ' + added + ' finding' + (added !== 1 ? 's' : '') + ' to “' + c.name + '”');
    });
    var bc = document.getElementById('bulkClear');
    if (bc) bc.addEventListener('click', function () { selKeys = {}; currentView(); });
  }
  function gridOrEmpty(list) {
    if (list.length) return renderGrid(list);
    // keep the header + filter row so column filters can still be adjusted/cleared when nothing matches
    return '<table class="grid resizable" id="gridHost" style="width:' + totalW() + 'px">' + gridHead() + '<tbody><tr><td colspan="' + COL_DEFS.length + '" class="empty" style="padding:18px">No findings match these filters.</td></tr></tbody></table>';
  }
  function rerenderGridOnly() {
    var list = visibleFindings(); var host = document.querySelector('#gridHost');
    if (host) { host.outerHTML = gridOrEmpty(list); wireGrid(); }
  }

  function sevBadge(sev) { return '<span class="badge ' + (['crit', 'high', 'med', 'low'][SEV_ORDER[sev]] || 'low') + '">' + esc(sev) + '</span>'; }
  function isNewKey(k) { return !!(STATE._newKeys && STATE._newKeys[k]); }
  // Column definitions drive the header, default widths, and resizing. id = width key (persisted).
  var COL_DEFS = [
    { id: 'sel', w: 36, label: '<input type="checkbox" id="selAll" title="Select all shown" aria-label="Select all shown">', cls: 'selcol' },
    { id: 'cve', w: 165, label: 'CVE', sort: 'cve', resize: true },
    { id: 'host', w: 150, label: 'Host', sort: 'host', resize: true },
    { id: 'desc', w: 300, label: 'Description', sort: 'desc', resize: true },
    { id: 'sev', w: 95, label: 'Sev', sort: 'sev', resize: true },
    { id: 'pri', w: 85, label: 'Priority', sort: 'risk', resize: true },
    { id: 'epss', w: 80, label: 'EPSS', sort: 'epss', resize: true },
    { id: 'vpr', w: 70, label: 'VPR', sort: 'vpr', resize: true },
    { id: 'status', w: 140, label: 'Status', sort: 'status', resize: true },
    { id: 'ticket', w: 110, label: 'Ticket', sort: 'ticket', resize: true },
    { id: 'sla', w: 85, label: 'SLA', sort: 'due', resize: true },
    { id: 'owner', w: 120, label: 'Owner', sort: 'owner', resize: true },
    { id: 'repo', w: 120, label: 'Repo', sort: 'repo', resize: true },
    { id: 'age', w: 110, label: 'First seen', sort: 'age', resize: true },
    { id: 'act', w: 72, label: '' }
  ];
  function colW(c) { var v = STATE._colW && STATE._colW[c.id]; return (v && +v) || c.w; }
  function totalW() { return COL_DEFS.reduce(function (s, c) { return s + (STATE._colHidden[c.id] ? 0 : colW(c)); }, 0); }
  // Column show/hide: inject nth-child display:none for hidden columns (rows are positional).
  function injectColHide() {
    var st = document.getElementById('colHideStyle'); if (!st) { st = document.createElement('style'); st.id = 'colHideStyle'; document.head.appendChild(st); }
    // Grouped view emits colspan'd header rows, so positional nth-child hiding misaligns them — skip while grouped.
    if (STATE.filt.group) { st.textContent = ''; return; }
    var sel = COL_DEFS.map(function (c, i) { return STATE._colHidden[c.id] ? ('#gridHost th:nth-child(' + (i + 1) + '),#gridHost td:nth-child(' + (i + 1) + ')') : null; }).filter(Boolean).join(',');
    st.textContent = sel ? (sel + '{display:none!important}') : '';
  }
  // Per-column filter: which columns get a filter box, and the text value each is matched against.
  var COLF_COLS = { cve: 1, host: 1, desc: 1, sev: 1, pri: 1, epss: 1, vpr: 1, status: 1, ticket: 1, sla: 1, owner: 1, repo: 1, age: 1 };
  function colfVal(cid, f) {
    switch (cid) {
      case 'cve': return f.cve || '';
      case 'host': return f.host || '';
      case 'desc': return f.desc || f.name || '';
      case 'sev': return f.severity || '';
      case 'pri': return priorityOf(f) || '';
      case 'epss': var e = cveIntel(f.cve).epss; return e == null ? '' : (Math.round(e * 100) + '%');
      case 'vpr': return f.vpr == null ? '' : f.vpr.toFixed(1);
      case 'status': return SLABEL[statusOf(f)] || statusOf(f) || '';
      case 'ticket': var t = ticketOf(f); return (t && t.key) ? t.key : '';
      case 'sla': var di = dueIn(f); return di == null ? '' : (di < 0 ? (Math.abs(di) + 'd over') : (di + 'd left'));
      case 'owner': return ovOf(f).owner || '';
      case 'repo': return repoOf(f) || '';
      case 'age': return f.firstSeen || '';
      default: return '';
    }
  }
  function gridHead() {
    return '<thead><tr>' + COL_DEFS.map(function (c) {
      var arr = c.sort && STATE.sort.col === c.sort ? (STATE.sort.dir === 1 ? ' <span class="sortarrow">▲</span>' : ' <span class="sortarrow">▼</span>') : '';
      var rsz = c.resize ? '<span class="col-resize" aria-hidden="true"></span>' : '';
      return '<th data-cw="' + c.id + '" style="width:' + colW(c) + 'px"' + (c.sort ? ' data-col="' + c.sort + '"' : '') + (c.cls ? ' class="' + c.cls + '"' : '') + '>' + c.label + arr + rsz + '</th>';
    }).join('') + '</tr>' + gridFilterRow() + '</thead>';
  }
  function gridFilterRow() {
    var cf = (STATE.filt && STATE.filt.colf) || {};
    return '<tr class="grid-filterrow">' + COL_DEFS.map(function (c) {
      if (COLF_COLS[c.id]) return '<th class="cfcell"><input type="text" class="colf" data-cf="' + c.id + '" placeholder="filter" value="' + esc(cf[c.id] || '') + '" aria-label="Filter ' + (typeof c.label === 'string' ? c.label.replace(/<[^>]+>/g, '') : c.id) + '"></th>';
      return '<th' + (c.cls ? ' class="' + c.cls + '"' : '') + '></th>';
    }).join('') + '</tr>';
  }
  function findingRow(f, gid) {
    var st = statusOf(f), ss = slaState(f), di = dueIn(f);
    var dueTxt = di == null ? '—' : (di < 0 ? Math.abs(di) + 'd over' : di + 'd left');
    var attrs = 'data-key="' + esc(keyOf(f)) + '"' + (gid ? ' data-g="' + gid + '" class="childrow" style="display:none"' : '');
    return '<tr ' + attrs + '>' +
      '<td class="selcol"><input type="checkbox" class="rowsel" aria-label="Select finding"' + (selKeys[keyOf(f)] ? ' checked' : '') + '></td>' +
      '<td class="cid"><a href="' + CVE_DETAIL + esc(f.cve) + '" title="Open CVE detail">' + esc(f.cve) + '</a>' + (isNewKey(keyOf(f)) ? '<span class="ichip new" title="New since last scan">NEW</span>' : '') + intelChips(f.cve) + recurChip(f) + '</td>' +
      '<td class="host">' + esc(f.host) + '</td>' +
      '<td class="dcell" title="' + esc(f.desc || f.name || '') + '">' + (f.desc || f.name ? esc(f.desc || f.name) : '<span class="muted">—</span>') + '</td>' +
      '<td>' + sevBadge(f.severity) + '</td>' +
      '<td>' + priChip(f) + '</td>' +
      '<td>' + epssCell(f) + '</td>' +
      '<td>' + vprCell(f) + '</td>' +
      '<td>' + statusSelect(f, st) + '</td>' +
      '<td>' + ticketCell(f) + '</td>' +
      '<td><span class="pill-sla ' + ss + '">' + dueTxt + '</span></td>' +
      '<td>' + (ovOf(f).owner ? esc(ovOf(f).owner) : '<span class="muted">—</span>') + '</td>' +
      '<td>' + (repoOf(f) ? esc(repoOf(f)) : '<span class="muted">—</span>') + '</td>' +
      '<td class="muted" style="font-size:12px">' + esc(f.firstSeen) + '</td>' +
      '<td><button class="btn sm act-detail">Open</button></td></tr>';
  }
  function gridTable(list) {
    return '<table class="grid resizable" id="gridHost" style="width:' + totalW() + 'px">' + gridHead() + '<tbody>' + list.map(function (f) { return findingRow(f); }).join('') + '</tbody></table>';
  }
  // Collapse the list by what you fix once: CVE (patch one, clear N hosts), product/vuln, or host.
  function groupFindings(list, by) {
    var keyFn = by === 'cve' ? function (f) { return f.cve; } : by === 'host' ? function (f) { return f.host; } : function (f) { return f.name || f.cve; };
    var map = {}, order = [];
    list.forEach(function (f) { var k = keyFn(f) || '—'; if (!map[k]) { map[k] = { id: 'g' + order.length, label: k, items: [] }; order.push(k); } map[k].items.push(f); });
    var groups = order.map(function (k) {
      var g = map[k], its = g.items, hosts = {};
      its.forEach(function (f) { hosts[f.host] = 1; });
      g.count = its.length; g.openCount = its.filter(isOpen).length; g.hostCount = Object.keys(hosts).length;
      g.maxSev = its.map(function (f) { return f.severity; }).sort(function (a, b) { return SEV_ORDER[a] - SEV_ORDER[b]; })[0];
      g.risk = its.reduce(function (m, f) { return Math.max(m, riskScore(f)); }, -1e9);
      g.kev = its.some(function (f) { return cveIntel(f.cve).kev; });
      g.ransomware = its.some(function (f) { return cveIntel(f.cve).ransomware; });
      g.exploit = its.some(function (f) { return cveIntel(f.cve).exploit; });
      g.pri = its.map(priorityOf).filter(Boolean).sort()[0] || null;
      return g;
    });
    groups.sort(function (a, b) { return b.risk - a.risk; });
    return groups;
  }
  function groupedTable(list, by) {
    var body = groupFindings(list, by).map(function (g) {
      var chips = (g.kev ? '<span class="ichip kev">KEV</span>' : '') + (g.ransomware ? '<span class="ichip rw">RW</span>' : '') + (!g.kev && g.exploit ? '<span class="ichip poc">PoC</span>' : '');
      var unit = by === 'host' ? (g.count + ' finding' + (g.count > 1 ? 's' : '')) : (g.count + ' finding' + (g.count > 1 ? 's' : '') + ' · ' + g.hostCount + ' host' + (g.hostCount > 1 ? 's' : ''));
      var head = '<tr class="grouprow" data-g="' + g.id + '">' +
        '<td class="selcol"><input type="checkbox" class="gsel" aria-label="Select all in group"></td>' +
        '<td colspan="3"><span class="gcaret">▸</span> <b>' + esc(g.label) + '</b> <span class="muted" style="font-size:12px">' + unit + '</span>' + (chips ? ' ' + chips : '') + '</td>' +
        '<td>' + sevBadge(g.maxSev) + '</td>' +
        '<td>' + (g.pri ? '<span class="pri ' + g.pri.toLowerCase() + '">' + g.pri + '</span>' : '<span class="muted">—</span>') + '</td>' +
        '<td colspan="8" class="muted" style="font-size:12px">' + g.openCount + ' open / ' + g.count + '</td><td></td></tr>';
      return head + g.items.map(function (f) { return findingRow(f, g.id); }).join('');
    }).join('');
    return '<table class="grid resizable" id="gridHost" style="width:' + totalW() + 'px">' + gridHead() + '<tbody>' + body + '</tbody></table>';
  }
  function renderGrid(list) { return STATE.filt.group ? groupedTable(list, STATE.filt.group) : gridTable(list); }
  function intelChips(cve) {
    var it = cveIntel(cve), c = '';
    if (it.kev) c += '<span class="ichip kev" title="CISA Known Exploited Vulnerability' + (it.kevDue ? ' — remediate by ' + esc(it.kevDue) : '') + '">KEV</span>';
    if (it.ransomware) c += '<span class="ichip rw" title="Known ransomware campaign use">RW</span>';
    if (!it.kev && it.exploit) c += '<span class="ichip poc" title="Public exploit / PoC available">PoC</span>';
    return c ? ' ' + c : '';
  }
  function priChip(f) { var p = priorityOf(f); return p ? '<span class="pri ' + p.toLowerCase() + '">' + p + '</span>' : '<span class="muted">—</span>'; }
  // Recurrence / flapping: how many times this finding has been reopened after being resolved (from the override store).
  function recurCount(f) { return ovOf(f).reopens || 0; }
  function isRecurring(f) { return recurCount(f) >= Math.max(1, (STATE.cfg && STATE.cfg.recurThreshold) || 1); }
  function recurChip(f) { var n = recurCount(f); return n < 1 ? '' : ' <span class="ichip recur" title="Reopened ' + n + ' time' + (n > 1 ? 's' : '') + ' after being resolved (recurring / flapping finding)">↻ ' + n + '</span>'; }
  function epssCell(f) { var e = cveIntel(f.cve).epss; if (e == null) return '<span class="muted">—</span>'; return '<span class="epss ' + (e >= 0.5 ? 'hi' : e >= 0.1 ? 'mid' : '') + '">' + Math.round(e * 100) + '%</span>'; }
  function vprBand(v) { return v >= 9 ? 'crit' : v >= 7 ? 'hi' : v >= 4 ? 'mid' : ''; }
  function vprCell(f) { var v = f.vpr; if (v == null) return '<span class="muted">—</span>'; return '<span class="vpr ' + vprBand(v) + '" title="Tenable VPR">' + v.toFixed(1) + '</span>'; }
  function drawerIntel(f) {
    var it = cveIntel(f.cve), p = priorityOf(f), parts = [];
    if (p) parts.push('<span class="pri ' + p.toLowerCase() + '">' + p + '</span>');
    if (it.kev) parts.push('KEV' + (it.kevDue ? ' (due ' + esc(it.kevDue) + ')' : ''));
    if (it.ransomware) parts.push('ransomware');
    if (it.exploit) parts.push('public exploit' + (it.exploitDate ? ' (' + esc(it.exploitDate) + ')' : ''));
    return parts.length ? parts.join(' · ') : '<span class="muted">no known exploitation</span>';
  }
  function statusSelect(f, st) {
    return '<select class="status act-status" data-s="' + st + '" title="Triage status — see “What do the statuses mean?” on the Findings page">' + STATUS.map(function (s) { return '<option value="' + s.k + '" title="' + esc(s.d || '') + '"' + (s.k === st ? ' selected' : '') + '>' + s.l + '</option>'; }).join('') + '</select>';
  }
  function statusLegend() {
    return '<details class="statuskey"><summary>What do the statuses mean?</summary>' +
      '<div class="statuskey-grid">' + STATUS.map(function (s) {
        return '<div class="statuskey-item"><span class="st-dot" style="background:var(--' + (STATUS_BAR_COLOR[s.k] || 'accent') + ')"></span>' +
          '<div><b>' + s.l + '</b> <span class="st-oc">' + (s.open ? 'open' : 'closed') + '</span><div class="muted statuskey-d">' + esc(s.d) + '</div></div></div>';
      }).join('') + '</div>' +
      '<div class="muted statuskey-note"><b>Open</b> (New · Triaged · In Remediation) = active work — the SLA clock runs and they rank highest. <b>Closed</b> (Resolved · Risk Accepted · False Positive) = off the worklist — no SLA, ranked last.</div></details>';
  }
  function findByKey(k) { for (var i = 0; i < STATE.findings.length; i++) if (keyOf(STATE.findings[i]) === k) return STATE.findings[i]; return null; }

  // ---------- Findings keyboard nav (j/k move · Enter open · x select · Esc close) ----------
  var _focusKey = null;
  function _visRows() { return [].filter.call(document.querySelectorAll('#gridHost tbody tr[data-key]'), function (tr) { return tr.offsetParent !== null; }); }
  function _paintFocus() { _visRows().forEach(function (tr) { tr.classList.toggle('rowfocus', tr.getAttribute('data-key') === _focusKey); }); }
  function _moveFocus(delta) {
    var rows = _visRows(); if (!rows.length) return;
    var idx = -1; for (var i = 0; i < rows.length; i++) { if (rows[i].getAttribute('data-key') === _focusKey) { idx = i; break; } }
    idx = idx < 0 ? (delta > 0 ? 0 : rows.length - 1) : Math.max(0, Math.min(rows.length - 1, idx + delta));
    _focusKey = rows[idx].getAttribute('data-key'); _paintFocus(); rows[idx].scrollIntoView({ block: 'nearest' });
  }
  document.addEventListener('keydown', function (e) {
    if ((location.hash || '').indexOf('#/findings') !== 0) return;
    var t = e.target; if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
    if (document.querySelector('.cmdk-overlay.show')) return;
    var dr = document.getElementById('drawer'), drawerOpen = dr && dr.classList.contains('open');
    if (e.key === 'Escape') { if (drawerOpen) { var bg = document.getElementById('drawerBg'); if (bg) bg.classList.remove('open'); dr.classList.remove('open'); hideDrawerHandle(); } return; }
    if (drawerOpen) return;
    if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); _moveFocus(1); }
    else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); _moveFocus(-1); }
    else if (e.key === 'Enter' || e.key === 'o') { var f = _focusKey && findByKey(_focusKey); if (f) { e.preventDefault(); openDrawer(f); } }
    else if (e.key === 'x') { var f2 = _focusKey && findByKey(_focusKey); if (f2) { e.preventDefault(); var k = keyOf(f2); if (selKeys[k]) delete selKeys[k]; else selKeys[k] = 1; currentView(); _paintFocus(); } }
  });
  // Drag-to-resize columns; widths persist (STATE._colW + localStorage) across re-renders.
  function wireResizers() {
    var tbl = document.getElementById('gridHost'); if (!tbl) return;
    function recalc() { var s = 0; [].forEach.call(tbl.querySelectorAll('thead th'), function (th) { s += th.offsetWidth; }); tbl.style.width = s + 'px'; }
    [].forEach.call(tbl.querySelectorAll('th .col-resize'), function (h) {
      h.addEventListener('click', function (e) { e.stopPropagation(); });
      h.addEventListener('mousedown', function (e) {
        e.preventDefault(); e.stopPropagation();
        var th = h.parentNode, id = th.getAttribute('data-cw'), startX = e.clientX, startW = th.offsetWidth;
        function mm(ev) { th.style.width = Math.max(48, startW + (ev.clientX - startX)) + 'px'; recalc(); }
        function mu() {
          document.removeEventListener('mousemove', mm); document.removeEventListener('mouseup', mu);
          document.body.style.cursor = ''; document.body.style.userSelect = '';
          STATE._colW = STATE._colW || {}; STATE._colW[id] = th.offsetWidth;
          try { localStorage.setItem('vmops-colw', JSON.stringify(STATE._colW)); } catch (e) {}
        }
        document.addEventListener('mousemove', mm); document.addEventListener('mouseup', mu);
        document.body.style.cursor = 'col-resize'; document.body.style.userSelect = 'none';
      });
    });
  }
  function wireGrid() {
    injectColHide();
    [].forEach.call(document.querySelectorAll('table.grid thead input.colf'), function (inp) {
      inp.addEventListener('click', function (e) { e.stopPropagation(); });
      inp.addEventListener('input', function () {
        STATE.filt.colf = STATE.filt.colf || {};
        STATE.filt.colf[this.getAttribute('data-cf')] = this.value;
        var cid = this.getAttribute('data-cf'), pos = this.selectionStart;
        rerenderGridOnly();
        var again = document.querySelector('table.grid thead input.colf[data-cf="' + cid + '"]');
        if (again) { again.focus(); try { again.setSelectionRange(pos, pos); } catch (e) {} }
      });
    });
    [].forEach.call(document.querySelectorAll('table.grid thead th[data-col]'), function (th) {
      th.addEventListener('click', function (e) { if (e.target.closest('.col-resize')) return; var c = th.getAttribute('data-col'); if (STATE.sort.col === c) STATE.sort.dir *= -1; else { STATE.sort.col = c; STATE.sort.dir = (c === 'risk' || c === 'epss' || c === 'vpr') ? -1 : 1; } currentView(); });
    });
    wireResizers();
    var selAll = document.getElementById('selAll');
    if (selAll) selAll.addEventListener('change', function () {
      var on = this.checked;
      [].forEach.call(document.querySelectorAll('table.grid tbody tr'), function (tr) {
        var k = tr.getAttribute('data-key'), cb = tr.querySelector('.rowsel');
        if (!cb) return;   // skip group-header rows (no row checkbox)
        if (on) selKeys[k] = true; else delete selKeys[k];
        cb.checked = on;
      });
      updateBulkBar();
    });
    // grouped view: expand/collapse a group, and select all its members
    [].forEach.call(document.querySelectorAll('table.grid tr.grouprow'), function (gr) {
      var gid = gr.getAttribute('data-g');
      gr.addEventListener('click', function (e) {
        if (e.target.closest('.gsel')) return;
        var open = gr.classList.toggle('open');
        var car = gr.querySelector('.gcaret'); if (car) car.textContent = open ? '▾' : '▸';
        [].forEach.call(document.querySelectorAll('table.grid tr.childrow[data-g="' + gid + '"]'), function (cr) { cr.style.display = open ? '' : 'none'; });
      });
      var gs = gr.querySelector('.gsel');
      if (gs) gs.addEventListener('click', function (e) {
        e.stopPropagation(); var on = this.checked;
        [].forEach.call(document.querySelectorAll('table.grid tr.childrow[data-g="' + gid + '"]'), function (cr) {
          var k = cr.getAttribute('data-key'), cb = cr.querySelector('.rowsel');
          if (on) selKeys[k] = true; else delete selKeys[k];
          if (cb) cb.checked = on;
        });
        updateBulkBar();
      });
    });
    var byKey = {}; STATE.findings.forEach(function (f) { byKey[keyOf(f)] = f; });   // index once so per-row wiring is O(n), not O(n^2) via findByKey
    [].forEach.call(document.querySelectorAll('table.grid tbody tr'), function (tr) {
      var f = byKey[tr.getAttribute('data-key')];
      var cb = tr.querySelector('.rowsel');
      if (cb) cb.addEventListener('change', function (e) { e.stopPropagation(); var k = tr.getAttribute('data-key'); if (this.checked) selKeys[k] = true; else delete selKeys[k]; updateBulkBar(); });
      var sel = tr.querySelector('.act-status');
      if (sel) sel.addEventListener('change', function (e) { e.stopPropagation(); setOverride(f, { status: this.value }); toast('Status → ' + SLABEL[this.value]); currentView(); });
      var btn = tr.querySelector('.act-detail');
      if (btn) btn.addEventListener('click', function (e) { e.stopPropagation(); openDrawer(f); });
      tr.addEventListener('click', function (e) { if (e.target.closest('select,a,button,input,.selcol')) return; openDrawer(f); });
    });
    updateBulkBar();
  }

  // ---------- remediation script samples (shipped data/remediation.json + user-added) ----------
  var PLAYBOOK_BASE = 'https://github.com/cloudanimal/remediation-playbooks/tree/main/';
  var REMED = { shipped: null, data: null, loading: null };
  function remedUser() { var u = load('vmops-remediation', null) || {}; return { cve: u.cve || {}, class: u.class || [] }; }
  function remedMerge(shipped, user) {
    shipped = shipped || { cve: {}, class: [], generic: null };
    return {
      cve: Object.assign({}, shipped.cve, user.cve),          // user CVE entries win
      class: (user.class || []).concat(shipped.class || []),  // user classes are checked first
      generic: shipped.generic
    };
  }
  function remedReload() { if (REMED.shipped) REMED.data = remedMerge(REMED.shipped, remedUser()); return REMED.data; }
  function ensureRemed() {
    if (REMED.data) return Promise.resolve(REMED.data);
    if (REMED.loading) return REMED.loading;
    REMED.loading = fetch('data/remediation.json').then(function (r) { return r.ok ? r.json() : null; })
      .catch(function () { return null; })
      .then(function (d) { REMED.shipped = d || { cve: {}, class: [], generic: null }; REMED.data = remedMerge(REMED.shipped, remedUser()); return REMED.data; });
    return REMED.loading;
  }
  // Guess the platform from the finding text, to pick the right generic fallback.
  function osOf(f) {
    var hay = ((f.name || '') + ' ' + (f.desc || '') + ' ' + (f.cve || '')).toLowerCase();
    if (/citrix|netscaler|fortios|fortinet|fortigate|forti|palo alto|pan-os|\bf5\b|big-ip|sonicwall|\badc\b|ios xe|junos|appliance|firmware/.test(hay)) return 'appliance';
    if (/linux|unix|ubuntu|debian|red ?hat|rhel|centos|rocky|alma|suse|\bsudo\b|openssh|apache|nginx|glibc|\bkernel\b|systemd|\bbash\b|samba/.test(hay)) return 'linux';
    return 'windows';
  }
  // Optional per-entry constraints: an entry only applies if its OS and severity conditions are met.
  function remedMatches(entry, f) {
    if (entry.os && entry.os !== 'any' && osOf(f) !== entry.os) return false;
    if (entry.sev && entry.sev !== 'any' && (f.severity || '') !== entry.sev) return false;
    return true;
  }
  // Match a finding to a sample script: exact CVE → keyword class → per-OS generic fallback.
  function remediationFor(f) {
    var d = REMED.data; if (!d) return null;
    var hit = null, generic = false;
    var cveHit = d.cve && d.cve[f.cve];
    if (cveHit && remedMatches(cveHit, f)) hit = cveHit;
    if (!hit) {
      var hay = ((f.name || '') + ' ' + (f.desc || '') + ' ' + (f.cve || '')).toLowerCase();
      for (var i = 0; i < (d.class || []).length; i++) {
        var c = d.class[i], reOk = true;
        if (c.match) { try { reOk = new RegExp(c.match, 'i').test(hay); } catch (e) { reOk = false; } }
        if (reOk && remedMatches(c, f)) { hit = c; break; }
      }
    }
    if (!hit) { var g = d.generic || {}; hit = g[osOf(f)] || g.windows; generic = true; }
    if (!hit) return null;
    var script = (Array.isArray(hit.script) ? hit.script.join('\n') : (hit.script || ''))
      .replace(/\{CVE\}/g, f.cve || '').replace(/\{HOST\}/g, f.host || 'this host').replace(/\{NAME\}/g, f.name || 'this vulnerability');
    return { title: hit.title || 'Remediation', script: script, lang: hit.lang || 'PowerShell', generic: generic, playbook: hit.playbook ? PLAYBOOK_BASE + hit.playbook : null };
  }

  // ---------- resizable drawer ----------
  // A left-edge drag handle lets the user widen/narrow the finding drawer; the width persists
  // (localStorage 'vmops-drawer-w'). The handle is a body-level fixed element pinned to the
  // drawer's left edge, so it doesn't scroll away with the drawer's own content. Double-click resets.
  var _drH = null, DRAWER_MINW = 360;
  function drawerMaxW() { return Math.max(DRAWER_MINW, window.innerWidth - 40); }
  // The drawer is right-anchored, so its left edge = viewport - width. Deriving from offsetWidth
  // (layout width, unaffected by the open slide transform) is reliable even mid-transition.
  function positionDrawerHandle() { var dr = document.getElementById('drawer'); if (_drH && dr) _drH.style.left = (window.innerWidth - dr.offsetWidth) + 'px'; }
  function ensureDrawerHandle() {
    if (_drH) return _drH;
    var dr = document.getElementById('drawer'); if (!dr) return null;
    var h = document.createElement('div'); h.className = 'drawer-resize'; h.title = 'Drag to resize · double-click to reset';
    h.setAttribute('role', 'separator'); h.setAttribute('aria-orientation', 'vertical'); h.setAttribute('aria-label', 'Resize panel');
    document.body.appendChild(h);
    h.addEventListener('pointerdown', function (e) {
      e.preventDefault(); try { h.setPointerCapture(e.pointerId); } catch (_) {}
      h.classList.add('dragging'); document.body.style.userSelect = 'none'; dr.style.transition = 'none';
      function move(ev) { dr.style.width = Math.min(Math.max(window.innerWidth - ev.clientX, DRAWER_MINW), drawerMaxW()) + 'px'; positionDrawerHandle(); }
      function up() { h.classList.remove('dragging'); h.removeEventListener('pointermove', move); h.removeEventListener('pointerup', up); document.body.style.userSelect = ''; dr.style.transition = ''; var w = parseInt(dr.style.width, 10); if (w) save('vmops-drawer-w', w); }
      h.addEventListener('pointermove', move); h.addEventListener('pointerup', up);
    });
    h.addEventListener('dblclick', function () { dr.style.width = ''; save('vmops-drawer-w', 0); positionDrawerHandle(); });
    _drH = h; return h;
  }
  function showDrawerHandle() {
    var dr = document.getElementById('drawer'); if (!dr) return;
    var w = parseInt(load('vmops-drawer-w', 0), 10) || 0;
    dr.style.width = w ? (Math.min(Math.max(w, DRAWER_MINW), drawerMaxW()) + 'px') : '';   // '' → CSS default
    var h = ensureDrawerHandle(); if (h) { h.classList.add('open'); positionDrawerHandle(); }
  }
  function hideDrawerHandle() { if (_drH) _drH.classList.remove('open'); }
  window.addEventListener('resize', function () {
    var dr = document.getElementById('drawer'); if (!dr || !dr.classList.contains('open')) return;
    var w = parseInt(dr.style.width, 10); if (w && w > drawerMaxW()) dr.style.width = drawerMaxW() + 'px';
    positionDrawerHandle();
  });

  // ---------- finding drawer ----------
  function openDrawer(f) {
    var bg = document.getElementById('drawerBg'), dr = document.getElementById('drawer');
    var st = statusOf(f), o = ovOf(f), dd = dueDate(f), ss = slaState(f), di = dueIn(f);
    dr.innerHTML =
      '<button class="x" id="drClose">×</button>' +
      '<div class="overline">Finding</div><h3>' + esc(f.cve) + '</h3>' +
      '<div class="muted" style="font-size:13px;margin:2px 0 14px">' + esc(f.desc || f.name || 'Vulnerability') + '</div>' +
      '<div class="row"><span class="k">Host</span><span class="host">' + esc(f.host) + '</span></div>' +
      '<div class="row"><span class="k">Severity</span><span><span class="badge ' + (['crit', 'high', 'med', 'low'][SEV_ORDER[f.severity]] || 'low') + '">' + esc(f.severity) + '</span></span></div>' +
      '<div class="row"><span class="k">Exploitation</span><span>' + drawerIntel(f) + '</span></div>' +
      '<div class="row"><span class="k">CVSS</span><span>' + (f.cvss != null ? esc(f.cvss) : '—') + '</span></div>' +
      '<div class="row"><span class="k">VPR <span class="muted" style="font-weight:400;font-size:11px">Tenable</span></span><span>' + (f.vpr != null ? '<span class="vpr ' + vprBand(f.vpr) + '">' + f.vpr.toFixed(1) + '</span>' : '<span class="muted">—</span>') + '</span></div>' +
      '<div class="row"><span class="k">EPSS</span><span id="drEpss" class="muted">…</span></div>' +
      '<div class="row"><span class="k">NIST LEV</span><span id="drLev" class="muted">…</span></div>' +
      '<div class="row"><span class="k">SSVC</span><span id="drSsvc"></span></div>' +
      '<div class="row"><span class="k">Plugin</span><span>' + (f.plugin ? esc(f.plugin) : '—') + ' · ' + esc(f.source || '') + '</span></div>' +
      '<div class="row"><span class="k">First seen</span><span>' + esc(f.firstSeen) + ' (' + (daysSince(f.firstSeen) || 0) + 'd ago)</span></div>' +
      (isRecurring(f) ? '<div class="row"><span class="k">Recurrence</span><span><span class="ichip recur">↻ ' + recurCount(f) + '</span> reopened after being resolved</span></div>' : '') +
      '<div class="row"><span class="k">SLA due</span><span class="pill-sla ' + ss + '">' + (dd ? esc(dd) + (di == null ? '' : ' · ' + (di < 0 ? Math.abs(di) + 'd overdue' : di + 'd left')) : '—') + '</span></div>' +
      '<div class="row"><span class="k">Asset</span><span>' + (assetCrit(f.host) ? '<span class="badge ' + (assetCrit(f.host) === 'critical' ? 'crit' : assetCrit(f.host) === 'high' ? 'high' : assetCrit(f.host) === 'medium' ? 'med' : 'low') + '">' + esc(assetCrit(f.host).charAt(0).toUpperCase() + assetCrit(f.host).slice(1)) + '</span>' : '<a href="#/assets" class="muted" style="font-size:12px">set criticality ↗</a>') + '</span></div>' +
      '<div class="row"><span class="k">Risk score</span><span><b id="drRisk">' + Math.round(riskScore(f)) + '</b> <a href="#/settings" class="muted" style="font-size:11px">tune weights ↗</a></span></div>' +
      '<div class="row" style="display:block"><span class="k" style="display:block;margin-bottom:5px">Risk breakdown</span><span id="drRbk">' + riskBreakdownHtml(f) + '</span></div>' +
      '<div id="drRemed" class="remed"></div>' +
      '<div style="margin-top:16px"><label style="font-size:12px;font-weight:600;color:var(--soft)">Status</label><br>' + statusSelect(f, st).replace('act-status', 'dr-status') + '</div>' +
      '<div class="field"><label>Owner</label><input type="text" id="drOwner" value="' + esc(o.owner || '') + '" placeholder="team or person" style="max-width:none"></div>' +
      '<div class="field"><label>Repo / application</label><input type="text" id="drRepo" value="' + esc(o.repo || f.repo || '') + '" placeholder="e.g. storefront-web" style="max-width:none"></div>' +
      '<div class="field"><label>Ticket <span class="muted" style="font-weight:400;font-size:11px">Jira key or SNOW number — paste after you create it</span></label><input type="text" id="drTicket" value="' + esc(ticketOf(f) ? ticketOf(f).key : '') + '" placeholder="e.g. VULN-123 or INC0012345" style="max-width:none">' + (function () { var t = ticketOf(f), u = t && ticketLink(t.sys, t.key); return u ? ' <a class="tkt" href="' + esc(u) + '" target="_blank" rel="noopener" style="font-size:12px">open ↗</a>' : ''; })() + '</div>' +
      '<div><label style="font-size:12px;font-weight:600;color:var(--soft)">Notes</label><textarea id="drNotes" placeholder="Triage notes, remediation plan, risk-acceptance justification…">' + esc(o.notes || '') + '</textarea></div>' +
      '<div style="margin-top:14px"><label style="font-size:12px;font-weight:600;color:var(--soft)">Status updates</label>' +
      '<div id="drUpd" style="margin:8px 0">' + renderUpdates(f) + '</div>' +
      '<textarea id="drUpdNew" placeholder="Add a status update… (logged with a timestamp)"></textarea>' +
      '<div style="margin-top:6px"><button class="btn sm" id="drAddUpd">Add update</button></div></div>' +
      '<div class="actions">' +
      '<a class="btn primary" href="' + CVE_DETAIL + esc(f.cve) + '">CVE detail</a>' +
      '<button class="btn" id="drJira">Open Jira story</button>' +
      '<button class="btn" id="drSnow">Open SNOW incident</button>' +
      '</div>' +
      '<div class="actions" style="margin-top:8px">' +
      '<button class="btn sm" id="drJiraQ">Search Jira</button>' +
      '<button class="btn sm" id="drSnowQ">Search ServiceNow</button>' +
      '<button class="btn sm" id="drCopy" title="Copy a text summary of this finding">Copy summary</button>' +
      '</div>';
    bg.classList.add('open'); dr.classList.add('open'); showDrawerHandle();
    // Fill the remaining prioritization models: SSVC is derived (instant); EPSS is from the bundled local feed (or an opt-in live FIRST.org lookup, off by default); LEV (local) loads async.
    (function () {
      var it = cveIntel(f.cve), sv = ssvcVerdict(it.kev, it.exploit, f.cvss);
      var se = document.getElementById('drSsvc'); if (se) se.innerHTML = '<b>' + sv.v + '</b>' + (sv.why ? ' · ' + esc(sv.why) : '');
      var setEpss = function (e) { var el = document.getElementById('drEpss'); if (!el) return; el.className = ''; var v = epssVerdict(e); el.innerHTML = e == null ? '<span class="muted">—</span>' : '<b>' + v.v + '</b> · ' + esc(v.why); };
      // Prefer the bundled local feed. Only when the user has opted in (Settings) do we fall back to a live
      // FIRST.org lookup for a CVE missing locally; by default nothing leaves the browser.
      if (it.epss != null) setEpss(it.epss);
      else if (STATE.cfg.epssLive) epssFor(f.cve).then(setEpss);
      else setEpss(null);
      levFor(f.cve).then(function (l) { var el = document.getElementById('drLev'); if (el) { el.className = ''; var v = levVerdict(l); el.innerHTML = l == null ? '<span class="muted">—</span>' : '<b>' + v.v + '</b> · ' + esc(v.why); }
        // LEV is now cached — refresh the breakdown + score so the LEV row is consistent with it.
        var rb = document.getElementById('drRbk'); if (rb) rb.innerHTML = riskBreakdownHtml(f);
        var rs = document.getElementById('drRisk'); if (rs) rs.textContent = Math.round(riskScore(f)); });
    })();
    // Fill the remediation sample (loads data/remediation.json once, then it's instant).
    ensureRemed().then(function () {
      var el = document.getElementById('drRemed'); if (!el) return;
      var r = remediationFor(f); if (!r) return;
      el.innerHTML =
        '<div class="remed-h"><span class="k">Remediation</span>' +
        '<span class="remed-badge' + (r.generic ? ' gen' : '') + '">' + esc(r.lang) + (r.generic ? ' · generic' : '') + '</span>' +
        '<button class="btn sm remed-copy" type="button">Copy</button></div>' +
        '<div class="remed-title">' + esc(r.title) + '</div>' +
        '<pre class="remed-code">' + esc(r.script) + '</pre>' +
        (r.playbook ? '<div class="remed-note"><a href="' + esc(r.playbook) + '" target="_blank" rel="noopener">Full playbook ↗</a></div>' : '') +
        '<div class="remed-note">Sample for guidance — review &amp; test in a pilot ring before running.</div>';
      var cb = el.querySelector('.remed-copy');
      if (cb) cb.addEventListener('click', function () { copyText(r.script); });
    });
    function close() { bg.classList.remove('open'); dr.classList.remove('open'); hideDrawerHandle(); }
    document.getElementById('drClose').addEventListener('click', close);
    bg.onclick = close;
    dr.querySelector('.dr-status').addEventListener('change', function () { setOverride(f, { status: this.value }); addUpdate(f, 'Status → ' + SLABEL[this.value]); toast('Status → ' + SLABEL[this.value]); currentView(); openDrawer(f); });
    document.getElementById('drAddUpd').addEventListener('click', function () { var ta = document.getElementById('drUpdNew'); var t = ta.value.trim(); if (!t) { toast('Type an update first'); return; } addUpdate(f, t); ta.value = ''; document.getElementById('drUpd').innerHTML = renderUpdates(f); toast('Update added'); });
    document.getElementById('drOwner').addEventListener('change', function () { setOverride(f, { owner: this.value.trim() }); toast('Owner saved'); currentView(); });
    document.getElementById('drRepo').addEventListener('change', function () { setOverride(f, { repo: this.value.trim() }); toast('Repo saved'); currentView(); });
    document.getElementById('drTicket').addEventListener('change', function () { setTicket(f, this.value); toast(this.value.trim() ? 'Ticket linked' : 'Ticket cleared'); currentView(); openDrawer(f); });
    document.getElementById('drNotes').addEventListener('change', function () { setOverride(f, { notes: this.value }); toast('Notes saved'); });
    document.getElementById('drJira').addEventListener('click', function () { openTicket('jira', f); });
    document.getElementById('drSnow').addEventListener('click', function () { openTicket('snow', f); });
    document.getElementById('drJiraQ').addEventListener('click', function () { searchTicket('jira', f); });
    document.getElementById('drSnowQ').addEventListener('click', function () { searchTicket('snow', f); });
    document.getElementById('drCopy').addEventListener('click', function () { copyText(ticketSummary(f) + '\n\n' + ticketBody(f)); });
  }

  // ---------- ticketing deep-links (Path A: pre-filled create, no API/secrets) ----------
  function ticketSummary(f) { return '[' + f.severity + '] ' + f.cve + ' on ' + f.host; }
  function ticketBody(f) {
    return 'Vulnerability: ' + f.cve + '\nHost: ' + f.host + '\nSeverity: ' + f.severity + (f.cvss != null ? ' (CVSS ' + f.cvss + ')' : '') +
      '\nPlugin: ' + (f.plugin || 'n/a') + ' (' + (f.source || 'scan') + ')\nFirst seen: ' + f.firstSeen +
      '\nSLA due: ' + (dueDate(f) || 'n/a') + '\nRisk detail: ' + CVE_DETAIL_ABS + f.cve;
  }
  // Build a pre-filled create-ticket deep-link (shared by single + group/bulk ticketing).
  function ticketUrl(kind, summary, body) {
    var c = STATE.cfg;
    if (kind === 'jira') {
      if (!c.jiraBase) { needSettings('Jira base URL'); return null; }
      if (c.jiraPid && c.jiraType) return c.jiraBase.replace(/\/$/, '') + '/secure/CreateIssueDetails!init.jspa?pid=' + encodeURIComponent(c.jiraPid) + '&issuetype=' + encodeURIComponent(c.jiraType) + '&summary=' + encodeURIComponent(summary) + '&description=' + encodeURIComponent(body);
      toast('Set Jira project + issue-type IDs in Settings to pre-fill'); return c.jiraBase.replace(/\/$/, '') + '/secure/CreateIssue!default.jspa';
    }
    if (!c.snowBase) { needSettings('ServiceNow base URL'); return null; }
    return c.snowBase.replace(/\/$/, '') + '/incident.do?sys_id=-1&sysparm_query=' + encodeURIComponent('short_description=' + summary + '^description=' + body);
  }
  function openTicket(kind, f) { ticketModal(kind, ticketSummary(f), ticketBody(f)); }
  // Practical URL-length bands. Most servers/proxies cap the request URI around 8 KB
  // (Apache LimitRequestLine 8190, Tomcat maxHttpHeaderSize 8192); under ~2 KB is universally safe.
  var URL_SAFE = 2000, URL_MAX = 8000;
  // Pre-edit modal: pre-fills summary + description, lets the user tweak them and watch the deep-link
  // length before it ever reaches Jira/ServiceNow (where the native create form is also fully editable).
  function ticketModal(kind, summary, body) {
    var c = STATE.cfg, isJira = kind === 'jira';
    if (isJira && !c.jiraBase) return needSettings('Jira base URL');
    if (!isJira && !c.snowBase) return needSettings('ServiceNow base URL');
    var prefill = isJira ? (c.jiraPid && c.jiraType) : true;   // Jira needs project + type IDs to pre-fill
    function urlFor(s, b) {
      if (isJira) {
        if (!prefill) return c.jiraBase.replace(/\/$/, '') + '/secure/CreateIssue!default.jspa';
        return c.jiraBase.replace(/\/$/, '') + '/secure/CreateIssueDetails!init.jspa?pid=' + encodeURIComponent(c.jiraPid) + '&issuetype=' + encodeURIComponent(c.jiraType) + '&summary=' + encodeURIComponent(s) + '&description=' + encodeURIComponent(b);
      }
      return c.snowBase.replace(/\/$/, '') + '/incident.do?sys_id=-1&sysparm_query=' + encodeURIComponent('short_description=' + s + '^description=' + b);
    }
    var ov = document.getElementById('ctModal') || (function () { var d = document.createElement('div'); d.id = 'ctModal'; d.className = 'ct-modal vmops'; document.body.appendChild(d); return d; })();
    var target = isJira ? 'Jira' : 'ServiceNow';
    ov.innerHTML = '<div class="ct-mcard"><button class="x" id="tkX">×</button>' +
      '<h3 style="margin:0 0 3px">New ' + target + (isJira ? ' issue' : ' incident') + '</h3>' +
      '<div class="muted" style="font-size:12.5px;margin-bottom:14px">Edit the pre-filled fields, then open the pre-populated ' + target + ' create form. You can still change the ' + (isJira ? 'issue type (Story/Epic), assignee, and any field' : 'fields') + ' in ' + target + ' before you create.</div>' +
      (isJira && !prefill ? '<div class="muted" style="font-size:12px;margin-bottom:12px;color:var(--high)">Set the Jira project + issue-type IDs in <a href="#/settings">Settings</a> to carry these fields into the create form. Without them, ' + target + ' opens a blank create dialog (use Copy description to paste).</div>' : '') +
      '<div class="field"><label>Summary</label><input type="text" id="tkSum" value="' + esc(summary) + '" style="max-width:none"></div>' +
      '<div class="field"><label>Description</label><textarea id="tkBody" style="min-height:150px;font-family:var(--mono);font-size:12.5px">' + esc(body) + '</textarea></div>' +
      '<div id="tkLen" class="tklen"></div>' +
      '<div class="toolbar" style="justify-content:flex-end;margin-top:14px"><button class="btn sm" id="tkCopy">Copy description</button><button class="btn sm" id="tkCancel">Cancel</button><button class="btn primary sm" id="tkGo">Open in ' + target + ' ↗</button></div></div>';
    ov.classList.add('on');
    var sumEl = document.getElementById('tkSum'), bodyEl = document.getElementById('tkBody'), lenEl = document.getElementById('tkLen');
    function refresh() {
      var url = urlFor(sumEl.value, bodyEl.value), n = url.length;
      var band = n <= URL_SAFE ? 'ok' : n <= URL_MAX ? 'warn' : 'bad';
      var hint = !prefill ? 'Fields are not carried without project + issue-type IDs.'
        : band === 'ok' ? 'Well within safe URL length.'
        : band === 'warn' ? 'Long link. Most servers accept up to ~8 KB, but if the create page errors, shorten the description and paste the rest after.'
        : 'Too long. Many servers reject URLs over ~8 KB — shorten the description (use Copy description to move detail into ' + target + ' after creating).';
      lenEl.className = 'tklen ' + band;
      lenEl.innerHTML = '<span class="tklen-n">Link length: ' + n.toLocaleString() + ' chars</span> <span class="tklen-h">' + hint + '</span>';
    }
    sumEl.addEventListener('input', refresh); bodyEl.addEventListener('input', refresh); refresh();
    var close = function () { ov.classList.remove('on'); };
    document.getElementById('tkX').onclick = document.getElementById('tkCancel').onclick = close;
    ov.onclick = function (e) { if (e.target === ov) close(); };
    document.getElementById('tkCopy').onclick = function () { copyText(bodyEl.value); toast('Description copied'); };
    document.getElementById('tkGo').onclick = function () { window.open(urlFor(sumEl.value, bodyEl.value), '_blank', 'noopener'); close(); };
  }
  // One ticket covering a whole selection/group (deep-link → a single ticket listing every host).
  function groupSummary(fs) {
    var cves = {}, hosts = {}; fs.forEach(function (f) { cves[f.cve] = 1; hosts[f.host] = 1; });
    var nc = Object.keys(cves).length, nh = Object.keys(hosts).length;
    return nc === 1 ? ('[' + fs[0].severity + '] ' + fs[0].cve + ' on ' + nh + ' host' + (nh > 1 ? 's' : ''))
      : (nc + ' vulnerabilities across ' + nh + ' host' + (nh > 1 ? 's' : ''));
  }
  function groupBody(fs) {
    var lines = fs.map(function (f) { return '- ' + f.cve + ' | ' + f.host + ' | ' + f.severity + (priorityOf(f) ? ' | ' + priorityOf(f) : '') + (cveIntel(f.cve).kev ? ' | KEV' : ''); });
    return 'Remediation ticket covering ' + fs.length + ' finding(s):\n' + lines.join('\n') + '\n\nGenerated by ' + (window.VM_BRAND || 'Vulnerability Management Console') + '.';
  }
  function ticketGroup(kind, fs) { if (!fs.length) return; ticketModal(kind, groupSummary(fs), groupBody(fs)); }
  function searchTicket(kind, f) {
    var c = STATE.cfg;
    if (kind === 'jira') { if (!c.jiraBase) return needSettings('Jira base URL'); window.open(c.jiraBase.replace(/\/$/, '') + '/issues/?jql=' + encodeURIComponent('text ~ "' + f.cve + '"'), '_blank', 'noopener'); }
    else { if (!c.snowBase) return needSettings('ServiceNow base URL'); window.open(c.snowBase.replace(/\/$/, '') + '/incident_list.do?sysparm_query=' + encodeURIComponent('short_descriptionLIKE' + f.cve + '^ORdescriptionLIKE' + f.cve), '_blank', 'noopener'); }
  }
  // ---------- ticket linkage (capture the created ticket key on the finding; status sync comes later via the proxy) ----------
  function ticketOf(f) { return ovOf(f).ticket || null; }
  function ticketSys(key) { return /^[A-Za-z][A-Za-z0-9]*-\d+$/.test(key) ? 'jira' : 'snow'; }   // ABC-123 = Jira; INC0012345 etc = ServiceNow
  function ticketLink(sys, key) { var c = STATE.cfg; if (sys === 'jira') return c.jiraBase ? c.jiraBase.replace(/\/$/, '') + '/browse/' + encodeURIComponent(key) : null; return c.snowBase ? c.snowBase.replace(/\/$/, '') + '/incident.do?sysparm_query=number=' + encodeURIComponent(key) : null; }
  function setTicket(f, keyRaw) {
    var key = (keyRaw || '').trim();
    if (!key) { setOverride(f, { ticket: null }); return; }
    var sys = ticketSys(key), prev = ticketOf(f) || {};
    setOverride(f, { ticket: { sys: sys, key: key, url: ticketLink(sys, key), status: prev.status || null, synced: prev.synced || null } });
    if (!prev.key || prev.key !== key) addUpdate(f, 'Ticket linked: ' + key + ' (' + sys.toUpperCase() + ')');
  }
  function ticketCell(f) {
    var t = ticketOf(f); if (!t) return '<span class="muted">—</span>';
    var url = ticketLink(t.sys, t.key);   // resolve from current Settings each render (base URL may be set later)
    var tip = (t.sys || '').toUpperCase() + (t.status ? ' · ' + t.status : '');
    return url ? '<a class="tkt" href="' + esc(url) + '" target="_blank" rel="noopener" title="' + esc(tip) + '">' + esc(t.key) + '</a>' : '<span class="tkt" title="' + esc(tip) + '">' + esc(t.key) + '</span>';
  }
  function needSettings(what) { toast('Set your ' + what + ' in Settings first'); location.hash = '#/settings'; }

  // ---------- import (load scan findings into the workbench) ----------
  // Unified importer: one slot per data source, persisted to the shared VMStore so the
  // dashboards can read it. Findings also feed the Findings workbench.
  var IMPORT_GROUPS = [
    { title: 'Findings', open: { route: '#/findings', label: 'Open Findings →' }, items: [
      { id: 'findings', label: 'Scan findings', sub: 'Nessus / Tenable vulnerability CSV → Findings workbench', accept: '.csv,text/csv' },
      { id: 'findings:sarif', label: 'SARIF (code scanning)', sub: 'SAST/SCA SARIF 2.1.0 (CodeQL, Semgrep, Trivy, Grype…) → Findings', accept: '.sarif,.json' },
      { id: 'findings:cdx', label: 'CycloneDX SBOM', sub: 'Components + licenses + vulnerabilities → Licenses & SBOM + Findings', accept: '.json,.cdx' }
    ] },
    { title: 'Agent coverage', open: { route: '#/agent-coverage', label: 'Open Agent Coverage →' }, items: [
      { id: 'acd:ad', label: 'Active Directory (AD)', sub: 'Computer inventory → Agent Coverage denominator', accept: '.json,.csv' },
      { id: 'acd:me', label: 'ManageEngine (ME)', sub: 'Endpoint Central agents → Agent Coverage', accept: '.json,.csv' },
      { id: 'acd:tsc', label: 'Tenable Security Center (.sc)', sub: 'Tenable.sc agents / assets export → Agent Coverage', accept: '.json,.csv' },
      { id: 'acd:tio', label: 'Tenable.io (cloud)', sub: 'Tenable.io agents / assets export → Agent Coverage', accept: '.json,.csv' },
      { id: 'acd:cs', label: 'CrowdStrike (CS)', sub: 'Falcon sensor inventory → Agent Coverage', accept: '.json,.csv' }
    ] },
    { title: 'Tenable vulnerability dashboard', open: { route: '#/tvd', label: 'Open Tenable dashboard →' }, items: [
      { id: 'tvd:cumulative', label: 'Tenable vulns — Cumulative (open)', sub: 'vulndetails export, sourceType=cumulative → Tenable dashboard', accept: '.csv,.json' },
      { id: 'tvd:mitigated', label: 'Tenable vulns — Mitigated', sub: 'vulndetails export, sourceType=patched → Tenable dashboard', accept: '.csv,.json' }
    ] }
  ];
  var IMPORT_SOON = [
    { label: 'Wiz', sub: 'CNAPP cloud findings' },
    { label: 'ManageEngine patch report', sub: 'Endpoint Central Detail-View patch status' }
  ];
  var IMPORT_SOURCES = IMPORT_GROUPS.reduce(function (a, g) { return a.concat(g.items); }, []);
  function stId(id) { return 'st-' + id.replace(/[^a-z0-9]/gi, '-'); }
  function importCard(s) {
    return '<div class="card import-src">' +
      '<div class="src-title">' + esc(s.label) + '</div>' +
      '<div class="muted src-sub">' + esc(s.sub) + '</div>' +
      '<div class="src-status muted" id="' + stId(s.id) + '">…</div>' +
      '<div class="toolbar" style="margin:0;gap:7px">' +
      '<button class="btn sm src-pick" data-id="' + s.id + '">Choose file</button>' +
      '<button class="btn sm src-clear" data-id="' + s.id + '">Clear</button>' +
      '<input type="file" class="src-file" data-id="' + s.id + '" accept="' + s.accept + '" hidden>' +
      '</div></div>';
  }
  function viewImport() {
    setActive('settings');
    app.innerHTML =
      '<header class="view"><div class="overline">Settings · Data Import</div><h1>Data import</h1>' +
      '<p class="lede">Bring in each data source once, here. Files are parsed in your browser and cached locally (IndexedDB) — nothing is uploaded. Imported sources feed the matching dashboard; scan findings feed the Findings workbench. Re-importing findings merges and preserves your status, owner, and notes.</p></header>' +
      privSlim() +
      '<div class="toolbar"><a class="btn sm" href="#/settings">← Settings</a><span class="spacer"></span><button class="btn sm" id="loadSample">Load sample findings</button><button class="btn sm" id="loadMultiScan" title="Also load Qualys, Rapid7, CrowdStrike, and Wiz sample findings so the workbench reflects every source">Load multi-scanner sample</button></div>' +
      IMPORT_GROUPS.map(function (g) {
        return '<div class="import-grouprow"><h2 class="import-grouphdr">' + esc(g.title) + '</h2>' +
          (g.open ? '<a class="btn sm import-open" href="' + g.open.route + '">' + esc(g.open.label) + '</a>' : '') +
          '</div><div class="importgrid">' + g.items.map(importCard).join('') + '</div>';
      }).join('') +
      '<h2 class="import-grouphdr">Coming soon</h2><div class="importgrid">' +
      IMPORT_SOON.map(function (s) { return '<div class="card import-src soon"><div class="src-title">' + esc(s.label) + '</div><div class="muted src-sub">' + esc(s.sub) + '</div><div class="src-status muted">Coming soon</div></div>'; }).join('') +
      '</div>';
    document.getElementById('loadSample').addEventListener('click', function () { var _s = SAMPLE(); mergeFindings(_s); seedSampleOverrides(_s); if (window.VMStore) VMStore.put({ id: 'findings', name: 'sample (built-in)', text: '', kind: 'sample' }); toast('Loaded sample findings'); goDash(); });
    document.getElementById('loadMultiScan').addEventListener('click', function () {
      var _s = SAMPLE(); mergeFindings(_s); seedSampleOverrides(_s);   // Tenable baseline
      var extra = (window.VMSCAN ? VMSCAN.scannerFindings() : []);      // Qualys/Rapid7/CrowdStrike/Wiz
      mergeFindings(extra);
      if (window.VMStore) VMStore.put({ id: 'findings', name: 'multi-scanner sample', text: '', kind: 'sample' });
      toast('Loaded findings from 5 scanners (' + STATE.findings.length + ' total)'); goDash();
    });
    [].forEach.call(document.querySelectorAll('.src-pick'), function (b) { b.addEventListener('click', function () { document.querySelector('.src-file[data-id="' + b.getAttribute('data-id') + '"]').click(); }); });
    [].forEach.call(document.querySelectorAll('.src-file'), function (inp) { inp.addEventListener('change', function () { if (inp.files[0]) handleSourceFile(inp.getAttribute('data-id'), inp.files[0]); inp.value = ''; }); });
    [].forEach.call(document.querySelectorAll('.src-clear'), function (b) { b.addEventListener('click', function () { clearSource(b.getAttribute('data-id')); }); });
    IMPORT_SOURCES.forEach(function (s) { refreshSourceStatus(s.id); });
  }
  function refreshSourceStatus(id) {
    var el = document.getElementById(stId(id)); if (!el) return;
    if (id === 'findings') { el.innerHTML = STATE.findings.length ? '<span class="ok-txt">✓ ' + STATE.findings.length + ' findings loaded</span>' : 'Not imported yet.'; return; }
    if (id === 'findings:cdx' && STATE.sbom && STATE.sbom.components) { el.innerHTML = '<span class="ok-txt">✓ ' + STATE.sbom.components.length + ' components</span> · <a href="#/sbom">view</a>'; return; }
    if (!window.VMStore) { el.textContent = 'Browser storage unavailable.'; return; }
    VMStore.get(id).then(function (rec) { el.innerHTML = rec ? '<span class="ok-txt">✓ ' + esc(rec.name) + '</span> · ' + esc(new Date(rec.importedAt).toLocaleString()) : 'Not imported yet.'; }).catch(function () { el.textContent = 'Not imported yet.'; });
  }
  function handleSourceFile(id, file) {
    var r = new FileReader();
    r.onload = function () {
      var text = String(r.result || '');
      var kind = (/\.json$/i.test(file.name) || /^\s*[\[{]/.test(text)) ? 'json' : 'csv';
      if (id === 'findings:sarif') {
        var sf; try { sf = parseSarif(text); } catch (e) { return toast('SARIF parse error: ' + e.message); }
        if (!sf.length) return toast('No results found in that SARIF file');
        mergeFindings(sf);   // additive: a code scan does not reconcile your scanner findings
        if (window.VMStore) VMStore.put({ id: id, name: file.name, text: text, kind: 'sarif' });
        toast('Imported ' + sf.length + ' SARIF result' + (sf.length > 1 ? 's' : '') + ' into Findings'); refreshSourceStatus(id); return;
      }
      if (id === 'findings:cdx') {
        var cdx; try { cdx = parseCycloneDX(text); } catch (e) { return toast('CycloneDX parse error: ' + e.message); }
        if (!cdx.components.length && !cdx.findings.length) return toast('No components or vulnerabilities in that BOM');
        STATE.sbom = { name: file.name, at: Date.now(), components: cdx.components }; save('vmops-sbom', STATE.sbom);
        if (cdx.findings.length) mergeFindings(cdx.findings);
        if (window.VMStore) VMStore.put({ id: id, name: file.name, text: text, kind: 'cdx' });
        toast('Imported SBOM: ' + cdx.components.length + ' components' + (cdx.findings.length ? ' · ' + cdx.findings.length + ' vulnerabilities → Findings' : '')); refreshSourceStatus(id);
        location.hash = '#/sbom'; return;
      }
      if (id === 'findings') {
        var fs; try { fs = parseCsv(text); } catch (e) { return toast('Parse error: ' + e.message); }
        if (!fs.length) return toast('No CVE rows found in that CSV');
        var sum = importScan(fs);
        if (window.VMStore) VMStore.put({ id: 'findings', name: file.name, text: text, kind: 'csv' });
        if (!sum.saved) { toast('Heads up: browser storage is full. Findings are loaded for this session only and were not saved.'); }
        else { toast(sum.reimport ? ('Rescan: ' + sum.total + ' findings · ' + sum.added + ' new · ' + sum.fixed + ' auto-resolved' + (sum.reopened ? ' · ' + sum.reopened + ' reopened' : '')) : ('Imported ' + sum.total + ' findings')); }
        refreshSourceStatus(id);
      } else if (window.VMStore) {
        var dest = id.indexOf('tvd:') === 0 ? 'the Tenable dashboard' : 'Agent Coverage';
        VMStore.put({ id: id, name: file.name, text: text, kind: kind }).then(function () { toast(file.name + ' imported — open ' + dest + ' to view'); refreshSourceStatus(id); });
      } else { toast('Browser storage unavailable'); }
    };
    r.readAsText(file);
  }
  function clearSource(id) {
    if (id === 'findings') { if (!confirm('Clear all findings, status, owners, and notes from this browser?')) return; STATE.findings = []; STATE.ov = {}; save('vmops-findings', []); save('vmops-overrides', {}); }
    if (id === 'findings:cdx') { STATE.sbom = null; save('vmops-sbom', null); }
    if (window.VMStore) VMStore.remove(id);
    toast('Cleared'); refreshSourceStatus(id);
  }
  function mergeFindings(incoming) {
    var idx = {}; STATE.findings.forEach(function (f, i) { idx[keyOf(f)] = i; });
    incoming.forEach(function (f) {
      var k = keyOf(f);
      if (idx[k] != null) { var old = STATE.findings[idx[k]]; if (old.firstSeen && (!f.firstSeen || old.firstSeen < f.firstSeen)) f.firstSeen = old.firstSeen; STATE.findings[idx[k]] = f; }
      else { STATE.findings.push(f); idx[k] = STATE.findings.length - 1; }
    });
    return save('vmops-findings', STATE.findings);
  }
  // A re-import is a fresh scan. It reconciles the current set both by PRESENCE (a finding that is gone is
  // resolved) and, when the export carries a Tenable "State" column, by STATE (a still-listed row marked
  // Fixed is resolved; a still-active row that was resolved reopens and its recurrence count is bumped, so a
  // live vuln never hides behind a stale "Resolved" and a chronic flapper is visible). No State column keeps
  // the older presence-only behavior, so plain CVE exports still work.
  function importScan(incoming) {
    var reimport = STATE.findings.length > 0;
    var incByKey = {}, existing = {};
    incoming.forEach(function (f) { incByKey[keyOf(f)] = f; });
    STATE.findings.forEach(function (f) { existing[keyOf(f)] = 1; });
    var added = 0; incoming.forEach(function (f) { if (!existing[keyOf(f)]) added++; });
    var fixed = 0, reopened = 0;
    STATE.findings.forEach(function (f) {
      var inc = incByKey[keyOf(f)], inScan = !!inc, incState = inc ? (inc.state || '') : '';
      if (isOpen(f) && !inScan) {
        setOverride(f, { status: 'resolved' }); addUpdate(f, 'Rescan: no longer detected, auto-resolved'); fixed++;
      } else if (isOpen(f) && inScan && incState === 'fixed') {
        setOverride(f, { status: 'resolved' }); addUpdate(f, 'Rescan: Tenable state Fixed, auto-resolved'); fixed++;
      } else if (inScan && incState !== 'fixed' && statusOf(f) === 'resolved') {
        // Was resolved, now still active in the scan: reopen and record the recurrence (flap).
        var flaps = (ovOf(f).reopens || 0) + 1;
        setOverride(f, { status: 'new', reopens: flaps });
        addUpdate(f, 'Rescan: detected again' + (incState === 'reopened' ? ' (Tenable state Reopened)' : '') + ', reopened (recurrence #' + flaps + ')');
        reopened++;
      }
      // Note: a resolved finding that reappears marked Fixed stays resolved (e.g. a Tenable mitigated export).
      // Deliberate closures (risk-accepted, false-positive) are left untouched.
    });
    // A brand-new row Tenable already marks Fixed comes in as resolved, not open.
    incoming.forEach(function (f) { if (!existing[keyOf(f)] && f.state === 'fixed') { setOverride(f, { status: 'resolved' }); addUpdate(f, 'Imported as resolved (Tenable state Fixed)'); fixed++; } });
    STATE._newKeys = {}; if (reimport) incoming.forEach(function (f) { var k = keyOf(f); if (!existing[k] && f.state !== 'fixed') STATE._newKeys[k] = 1; });
    try { localStorage.setItem('vmops-newkeys', JSON.stringify(Object.keys(STATE._newKeys))); } catch (e) {}
    var today = todayISO();
    var saved = mergeFindings(incoming.map(function (f) { f.lastSeen = today; return f; }));
    return { added: added, fixed: fixed, reopened: reopened, total: incoming.length, reimport: reimport, saved: saved };
  }

  // Normalize a Tenable "State" / "Vulnerability State" value to a canonical token.
  // Covers Tenable.io (OPEN / REOPENED / FIXED) and Tenable.sc (New / Active / Fixed / Reopened / Mitigated).
  function normState(s) {
    s = String(s || '').trim().toLowerCase();
    if (!s) return '';
    if (s.indexOf('fixed') > -1 || s.indexOf('mitigat') > -1 || s.indexOf('patched') > -1) return 'fixed';
    if (s.indexOf('reopen') > -1) return 'reopened';
    if (s.indexOf('active') > -1 || s.indexOf('open') > -1) return 'active';
    if (s.indexOf('new') > -1) return 'new';
    return '';
  }
  // ---------- SARIF (code-scanning) + CycloneDX (SBOM) import parsers ----------
  function sevFromScore(n) { return n == null || isNaN(n) ? '' : n >= 9 ? 'Critical' : n >= 7 ? 'High' : n >= 4 ? 'Medium' : n > 0 ? 'Low' : 'Low'; }
  function firstCve(s) { var m = String(s || '').match(/CVE-\d{4}-\d+/i); return m ? m[0].toUpperCase() : null; }
  // SARIF 2.1.0 — one finding per result. Host = file:line; CVE from ruleId/message when present,
  // else the ruleId is used as the identifier. security-severity (a CVSS-like number) sets severity.
  function parseSarif(text) {
    var doc = JSON.parse(text); var out = [];
    (doc.runs || []).forEach(function (run) {
      var tool = ((run.tool || {}).driver || {}).name || 'SARIF';
      var rules = {}; (((run.tool || {}).driver || {}).rules || []).forEach(function (r) { rules[r.id] = r; });
      (run.results || []).forEach(function (res) {
        var rid = res.ruleId || (res.rule && res.rule.id) || 'finding';
        var rule = rules[rid] || {};
        var props = res.properties || {}, rprops = rule.properties || {};
        var ss = parseFloat(props['security-severity'] != null ? props['security-severity'] : rprops['security-severity']);
        var level = res.level || (rule.defaultConfiguration || {}).level || 'warning';
        var sev = !isNaN(ss) ? sevFromScore(ss) : level === 'error' ? 'High' : level === 'note' || level === 'none' ? 'Low' : 'Medium';
        var loc = ((((res.locations || [])[0] || {}).physicalLocation) || {});
        var uri = ((loc.artifactLocation || {}).uri) || '';
        var line = ((loc.region || {}).startLine);
        var host = uri ? (uri + (line ? ':' + line : '')) : (tool + ' finding');
        var msg = (res.message && res.message.text) || (rule.shortDescription && rule.shortDescription.text) || rid;
        var name = (rule.name || (rule.shortDescription && rule.shortDescription.text) || rid);
        out.push({ cve: firstCve(rid) || firstCve(msg) || rid, host: host, severity: sev, cvss: !isNaN(ss) ? ss : null, vpr: null,
          plugin: rid, name: String(name).slice(0, 120), desc: String(msg).slice(0, 400), repo: '', source: tool, firstSeen: todayISO(), state: '' });
      });
    });
    return out;
  }
  // CycloneDX BOM (JSON) — returns {findings, components}. Findings come from bom.vulnerabilities;
  // components + licenses power the Licenses & SBOM view.
  function cdxLicense(comp) {
    var ls = comp.licenses || [];
    var names = ls.map(function (l) { return (l.license && (l.license.id || l.license.name)) || l.expression || ''; }).filter(Boolean);
    return names.join(', ') || '';
  }
  function parseCycloneDX(text) {
    var doc = JSON.parse(text);
    var comps = (doc.components || []).map(function (c) {
      return { name: c.name || '(unnamed)', version: c.version || '', type: c.type || 'library', purl: c.purl || '', ref: c['bom-ref'] || c.purl || (c.name + '@' + (c.version || '')), license: cdxLicense(c), vulns: 0 };
    });
    var byRef = {}; comps.forEach(function (c) { byRef[c.ref] = c; });
    var findings = [];
    (doc.vulnerabilities || []).forEach(function (v) {
      var id = v.id || '';
      var ratings = v.ratings || [];
      var score = null, sevStr = '';
      ratings.forEach(function (r) { if (score == null && r.score != null) score = parseFloat(r.score); if (!sevStr && r.severity) sevStr = r.severity; });
      var sev = normSev(sevStr, score);
      (v.affects && v.affects.length ? v.affects : [{ ref: '' }]).forEach(function (a) {
        var comp = byRef[a.ref]; if (comp) comp.vulns++;
        var host = comp ? (comp.name + (comp.version ? '@' + comp.version : '')) : (a.ref || 'component');
        findings.push({ cve: firstCve(id) || id || 'VULN', host: host, severity: sev, cvss: score, vpr: null,
          plugin: (v.source && v.source.name) || 'CycloneDX', name: String((v.description || id)).slice(0, 120),
          desc: String(v.description || id).slice(0, 400), repo: '', source: 'CycloneDX', firstSeen: todayISO(), state: '' });
      });
    });
    return { findings: findings, components: comps };
  }
  // License risk buckets for the SBOM view.
  function licenseClass(lic) {
    var s = String(lic || '').toUpperCase();
    if (!s) return 'unknown';
    if (/AGPL|GPL|LGPL|MPL|EPL|CDDL|EUPL|OSL|CPL/.test(s)) return 'copyleft';
    if (/MIT|APACHE|BSD|ISC|ZLIB|UNLICENSE|WTFPL|BSL|0BSD|PYTHON|PSF/.test(s)) return 'permissive';
    return 'other';
  }

  function parseCsv(text) {
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
    var rows = [], row = [], fld = '', q = false;
    for (var i = 0; i < text.length; i++) { var c = text[i];
      if (q) { if (c === '"') { if (text[i + 1] === '"') { fld += '"'; i++; } else q = false; } else fld += c; }
      else if (c === '"') q = true; else if (c === ',') { row.push(fld); fld = ''; }
      else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(fld); rows.push(row); row = []; fld = ''; }
      else fld += c; }
    if (fld.length || row.length) { row.push(fld); rows.push(row); }
    if (!rows.length) return [];
    var head = rows.shift().map(function (h) { return h.trim(); });
    function col(pats) { for (var p = 0; p < pats.length; p++) for (var j = 0; j < head.length; j++) if (pats[p].test(head[j])) return j; return -1; }
    var iCve = col([/^cve$/i, /\bcve\b/i]), iSev = col([/^severity$/i, /^risk$/i, /severity/i]), iCvss = col([/cvss.*base/i, /cvss/i]),
      iHost = col([/dns\s*name/i, /^host$/i, /hostname/i, /^name$/i, /ip\s*address/i]), iName = col([/plugin\s*name/i, /^name$/i, /synopsis/i]),
      iDesc = col([/^description$/i, /\bdescription\b/i, /synopsis/i]),
      iRepo = col([/^repo(sitory)?$/i, /\brepositor/i, /application/i, /\bapp\b/i]),
      iPid = col([/plugin\s*id/i]), iSeen = col([/first\s*(discovered|seen)/i, /plugin\s*publication/i, /discovered/i]),
      iVpr = col([/vpr.*score/i, /\bvpr\b/i]),
      iState = col([/vulnerabilit\w*\s*state/i, /^state$/i]);
    if (iName === iHost) iName = col([/plugin\s*name/i, /synopsis/i]);   // a bare "Name" column must not be claimed as both host and plugin name
    if (iCve === -1) return [];
    var out = [];
    rows.forEach(function (r) {
      var raw = (r[iCve] || '').trim(); if (!raw) return;
      var cves = raw.split(/[\s,;]+/).filter(function (x) { return /^CVE-\d{4}-\d+$/i.test(x); });
      if (!cves.length) return;
      var host = iHost > -1 ? (r[iHost] || '').trim() : 'unknown';
      var sev = normSev(iSev > -1 ? r[iSev] : '', iCvss > -1 ? parseFloat(r[iCvss]) : null);
      var cvss = iCvss > -1 && r[iCvss] ? parseFloat(r[iCvss]) : null;
      var vpr = iVpr > -1 && r[iVpr] ? parseFloat(r[iVpr]) : null;
      var seen = iSeen > -1 && r[iSeen] ? toISO(r[iSeen]) : todayISO();
      var nm = iName > -1 ? (r[iName] || '').trim() : '';
      var ds = iDesc > -1 ? (r[iDesc] || '').trim() : '';
      var rp = iRepo > -1 ? (r[iRepo] || '').trim() : '';
      var vstate = normState(iState > -1 ? r[iState] : '');
      cves.forEach(function (cve) { out.push({ cve: cve.toUpperCase(), host: host || 'unknown', severity: sev, cvss: isNaN(cvss) ? null : cvss, vpr: (vpr == null || isNaN(vpr)) ? null : vpr, plugin: iPid > -1 ? (r[iPid] || '').trim() : '', name: nm, desc: ds || nm, repo: rp, source: 'Tenable', firstSeen: seen, state: vstate }); });
    });
    return out;
  }
  function normSev(s, cvss) {
    s = String(s || '').trim().toLowerCase();
    if (s.indexOf('crit') === 0 || s === '4') return 'Critical';
    if (s.indexOf('high') === 0 || s === '3') return 'High';
    if (s.indexOf('med') === 0 || s === '2') return 'Medium';
    if (s.indexOf('low') === 0 || s === '1') return 'Low';
    if (cvss != null && !isNaN(cvss)) return cvss >= 9 ? 'Critical' : cvss >= 7 ? 'High' : cvss >= 4 ? 'Medium' : 'Low';
    return 'Medium';
  }
  function toISO(s) { var d = new Date(s); if (isNaN(d)) return todayISO(); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); }

  function exportCsv(list) {
    list = (list && list.length) ? list : visibleFindings();
    var head = ['CVE', 'Host', 'Description', 'Severity', 'CVSS', 'VPR', 'EPSS', 'Status', 'Ticket', 'Owner', 'Repo', 'FirstSeen', 'LastSeen', 'SLA_Due', 'Days_To_Due', 'Plugin', 'Source', 'Notes', 'Updates'];
    var lines = [head.join(',')].concat(list.map(function (f) {
      var o = ovOf(f), ep = cveIntel(f.cve).epss;
      var ups = updatesOf(f).map(function (u) { return (u.at || '').slice(0, 10) + ' ' + (u.text || '').replace(/\s+/g, ' '); }).join(' | ');
      return [f.cve, f.host, f.desc || f.name || '', f.severity, f.cvss == null ? '' : f.cvss, f.vpr == null ? '' : f.vpr, ep == null ? '' : ep, SLABEL[statusOf(f)], (ticketOf(f) ? ticketOf(f).key : ''), o.owner || '', repoOf(f), f.firstSeen, f.lastSeen || '', dueDate(f) || '', dueIn(f) == null ? '' : dueIn(f), f.plugin || '', f.source || '', (o.notes || '').replace(/\s+/g, ' '), ups]
        .map(function (v) { v = String(v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }).join(',');
    }));
    var blob = new Blob([lines.join('\n')], { type: 'text/csv' }), a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = 'vm-findings-' + todayISO() + '.csv'; a.click(); URL.revokeObjectURL(a.href); toast('Exported ' + list.length + ' findings');
  }

  // ---------- settings ----------
  // Settings → Remediation samples: list + add/edit/delete + export/import (localStorage 'vmops-remediation').
  var remedEditing = null;
  function remedFormReset() {
    remedEditing = null;
    var a = document.getElementById('remAdd'); if (a) a.textContent = 'Add sample';
    var c = document.getElementById('remCancelEdit'); if (c) c.style.display = 'none';
    ['remMatch', 'remTitle', 'remLang', 'remScript'].forEach(function (id) { var el = document.getElementById(id); if (el) el.value = ''; });
    var os = document.getElementById('remOs'); if (os) os.value = 'any';
    var sv = document.getElementById('remSev'); if (sv) sv.value = 'any';
  }
  function fillRemedForm(kind, key) {
    var u = remedUser(), e = kind === 'cve' ? u.cve[key] : u.class[parseInt(key, 10)];
    if (!e) return;
    var typeSel = document.getElementById('remType');
    typeSel.value = kind === 'cve' ? 'cve' : 'class';
    typeSel.dispatchEvent(new Event('change'));
    document.getElementById('remMatch').value = kind === 'cve' ? key : (e.match || '');
    document.getElementById('remTitle').value = e.title || '';
    document.getElementById('remLang').value = e.lang || '';
    document.getElementById('remScript').value = (e.script || []).join('\n');
    document.getElementById('remOs').value = e.os || 'any';
    document.getElementById('remSev').value = e.sev || 'any';
    remedEditing = { kind: kind, key: key };
    document.getElementById('remAdd').textContent = 'Update sample';
    document.getElementById('remCancelEdit').style.display = '';
    document.getElementById('remMatch').focus();
  }
  function renderRemedList() {
    var el = document.getElementById('remedList'); if (!el) return;
    var u = remedUser(), items = [];
    Object.keys(u.cve).forEach(function (k) { items.push({ kind: 'cve', key: k, e: u.cve[k] }); });
    u.class.forEach(function (c, i) { items.push({ kind: 'class', key: String(i), e: c }); });
    if (!items.length) { el.innerHTML = '<div class="muted" style="font-size:12.5px;margin-bottom:10px">No custom samples yet — add one below.</div>'; return; }
    el.innerHTML = items.map(function (it) {
      var e = it.e, scope = [it.kind === 'cve' ? it.key : 'match: ' + (e.match || '(any)')];
      if (e.os && e.os !== 'any') scope.push('OS: ' + e.os);
      if (e.sev && e.sev !== 'any') scope.push(e.sev);
      return '<div class="remed-row"><span class="remed-badge">' + esc(e.lang || 'PowerShell') + '</span> <b>' + esc(e.title || '(untitled)') + '</b> ' +
        '<span class="muted" style="font-size:12px">' + esc(scope.join(' · ')) + '</span>' +
        '<span class="remed-acts"><button class="btn sm remed-edit" data-kind="' + it.kind + '" data-key="' + esc(it.key) + '">Edit</button>' +
        '<button class="btn sm remed-del" data-kind="' + it.kind + '" data-key="' + esc(it.key) + '">Delete</button></span></div>';
    }).join('');
    [].forEach.call(el.querySelectorAll('.remed-edit'), function (b) {
      b.addEventListener('click', function () { fillRemedForm(b.getAttribute('data-kind'), b.getAttribute('data-key')); });
    });
    [].forEach.call(el.querySelectorAll('.remed-del'), function (b) {
      b.addEventListener('click', function () {
        var kind = b.getAttribute('data-kind'), key = b.getAttribute('data-key'), u = remedUser();
        if (kind === 'cve') { delete u.cve[key]; } else { u.class.splice(parseInt(key, 10), 1); }
        if (remedEditing && remedEditing.kind === kind && remedEditing.key === key) remedFormReset();
        save('vmops-remediation', u); remedReload(); renderRemedList(); toast('Sample removed');
      });
    });
  }
  function wireRemedSettings() {
    var typeSel = document.getElementById('remType'); if (!typeSel) return;
    remedEditing = null;   // fresh Settings render always starts in add-mode (not stale edit-mode)
    var lbl = document.getElementById('remMatchLabel'), matchInp = document.getElementById('remMatch');
    typeSel.addEventListener('change', function () {
      if (this.value === 'cve') { lbl.textContent = 'CVE ID'; matchInp.placeholder = 'CVE-2024-1234'; }
      else { lbl.textContent = 'Keyword pattern (regex)'; matchInp.placeholder = 'e.g. acme|acme agent'; }
    });
    document.getElementById('remAdd').addEventListener('click', function () {
      var type = typeSel.value, match = matchInp.value.trim(),
          title = document.getElementById('remTitle').value.trim(),
          lang = document.getElementById('remLang').value.trim() || 'PowerShell',
          scriptText = document.getElementById('remScript').value,
          os = document.getElementById('remOs').value, sev = document.getElementById('remSev').value;
      if (type === 'cve' && !match) { toast('Enter a CVE ID'); return; }
      if (type === 'class' && !match && os === 'any' && sev === 'any') { toast('Enter a keyword pattern, or set an OS / severity'); return; }
      if (!scriptText.trim()) { toast('Enter a script'); return; }
      if (type === 'class' && match) { try { new RegExp(match, 'i'); } catch (e) { toast('Invalid regex pattern'); return; } }
      var entry = { title: title, lang: lang, script: scriptText.replace(/\r/g, '').split('\n') };
      if (os !== 'any') entry.os = os;
      if (sev !== 'any') entry.sev = sev;
      var u = remedUser();
      if (remedEditing) { if (remedEditing.kind === 'cve') delete u.cve[remedEditing.key]; else u.class.splice(parseInt(remedEditing.key, 10), 1); }
      if (type === 'cve') { u.cve[match.toUpperCase()] = entry; } else { if (match) entry.match = match; u.class.push(entry); }
      if (!save('vmops-remediation', u)) { toast('Could not save — browser storage may be full'); return; }
      remedReload();
      var wasEditing = !!remedEditing; remedFormReset();
      renderRemedList(); toast(wasEditing ? 'Sample updated' : 'Sample added — open a matching finding to see it');
    });
    document.getElementById('remCancelEdit').addEventListener('click', function () { remedFormReset(); });
    document.getElementById('remExport').addEventListener('click', function () {
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([JSON.stringify(remedUser(), null, 2)], { type: 'application/json' }));
      a.download = 'remediation-custom.json';
      document.body.appendChild(a); a.click(); document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(a.href); }, 0);
    });
    var fileInp = document.getElementById('remFile');
    document.getElementById('remImport').addEventListener('click', function () { fileInp.click(); });
    fileInp.addEventListener('change', function () {
      var f = fileInp.files && fileInp.files[0]; if (!f) return;
      var rd = new FileReader();
      rd.onload = function () {
        try {
          var inc = JSON.parse(rd.result), u = remedUser();
          u.cve = Object.assign({}, u.cve, inc.cve || {});
          u.class = u.class.concat(inc.class || []);
          var seen = {};   // drop exact-duplicate keyword samples so re-import doesn't pile up
          u.class = u.class.filter(function (c) { var s = JSON.stringify([c.match || '', c.os || '', c.sev || '', c.title || '', c.script || []]); if (seen[s]) return false; seen[s] = 1; return true; });
          if (!save('vmops-remediation', u)) { toast('Could not save — browser storage may be full'); return; }
          remedReload(); renderRemedList();
          toast('Imported ' + (Object.keys(inc.cve || {}).length + (inc.class || []).length) + ' sample(s)');
        } catch (e) { toast('Import failed — invalid JSON'); }
        fileInp.value = '';
      };
      rd.readAsText(f);
    });
    document.getElementById('remReset').addEventListener('click', function () {
      if (!confirm('Remove all your custom remediation samples? The built-in samples stay in place.')) return;
      try { localStorage.removeItem('vmops-remediation'); } catch (e) {}
      remedReload(); remedFormReset(); renderRemedList(); toast('Custom samples cleared — built-ins restored');
    });
    renderRemedList();
  }

  // Settings backup / transfer. API keys and secrets are NEVER exported; on import, this browser's own
  // secrets are preserved (the file has none to overwrite them with).
  var SETTINGS_SECRET_KEYS = ['tioAccess', 'tioSecret', 'meClientId', 'meClientSecret'];
  function exportSettings() {
    var cfg = {}; Object.keys(STATE.cfg).forEach(function (k) { if (SETTINGS_SECRET_KEYS.indexOf(k) < 0) cfg[k] = STATE.cfg[k]; });
    var payload = { _type: 'vmops-settings', _app: 'vm-ops-console', _version: (window.APP_VERSION || ''), _exported: new Date().toISOString(), config: cfg, views: loadViews() };
    var blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }), a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = 'vmops-settings-' + todayISO() + '.json'; a.click(); URL.revokeObjectURL(a.href);
    toast('Settings exported (API keys excluded)');
  }
  function importSettings(text) {
    var data; try { data = JSON.parse(text); } catch (e) { return toast('Import failed: not valid JSON'); }
    if (!data || data._type !== 'vmops-settings' || !data.config) return toast('Import failed: not a VM Ops settings file');
    var keep = {}; SETTINGS_SECRET_KEYS.forEach(function (k) { keep[k] = STATE.cfg[k]; });   // never let an import wipe this browser's own keys
    var incoming = {}; Object.keys(data.config).forEach(function (k) { if (SETTINGS_SECRET_KEYS.indexOf(k) < 0 && k !== 'sla') incoming[k] = data.config[k]; });
    STATE.cfg = Object.assign({}, DEFAULT_CFG, incoming, keep);
    STATE.cfg.sla = Object.assign({}, DEFAULT_CFG.sla, (data.config.sla || {}));
    save('vmops-config', STATE.cfg);
    var addedViews = 0;
    if (Array.isArray(data.views)) {
      var byName = {}; loadViews().forEach(function (v) { if (v && v.name) byName[v.name] = v; });
      data.views.forEach(function (v) { if (v && v.name) { if (!(v.name in byName)) addedViews++; byName[v.name] = v; } });
      saveViews(Object.keys(byName).map(function (n) { return byName[n]; }));
    }
    applyBrand(); toast('Settings imported' + (addedViews ? ' (' + addedViews + ' new view' + (addedViews > 1 ? 's' : '') + ')' : '')); viewSettings();
  }
  function viewSettings() {
    setActive('settings');
    var c = STATE.cfg;
    app.innerHTML =
      '<header class="view"><div class="overline">Settings</div><h1>Configuration</h1>' +
      '<p class="lede">Branding, SLA windows, ticketing endpoints, and Tenable API keys are stored in this browser only.</p></header>' +
      privSlim() +
      '<h2>Branding</h2><div class="card">' +
      '<div class="field"><label>App name</label><input type="text" id="brandName" value="' + esc(c.brand || '') + '" placeholder="' + esc(DEFAULT_BRAND) + '"></div>' +
      '<div class="grid2"><div class="field"><label>Icon monogram</label><input type="text" id="brandIcon" maxlength="3" value="' + esc(c.brandIcon || '') + '" placeholder="' + esc(brandInitials((c.brand || '').trim() || DEFAULT_BRAND)) + '"></div>' +
      '<div class="field"><label>Icon color</label><input type="color" id="brandIconColor" value="' + esc((c.brandIconColor || '').trim() || DEFAULT_ICON_COLOR) + '" style="width:60px;padding:3px;height:38px"></div></div>' +
      '<div class="muted" style="font-size:12.5px">Sets the name in the top nav, the browser tab, and the page icon (favicon; 1 to 3 letters on a colored tile). A multi-word name stacks onto two lines in the nav (the last word drops to the second line). Leave the name blank to use “' + esc(DEFAULT_BRAND) + '”; leave the monogram blank to derive it from the name.</div></div>' +
      '<h2>Navigation</h2><div class="card">' +
      '<div class="muted" style="font-size:12.5px;margin-bottom:12px">Choose which items appear in the top menu bar and inside each dropdown. Unchecking hides an item from the nav; you can still reach it by a direct link, and Settings always stays visible.</div>' +
      (function () {
        var vis = function (k) { return (c.navHidden || []).indexOf(k) < 0; };
        var box = function (k, label) { return '<label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer"><input type="checkbox" class="navtoggle" data-nav="' + k + '" style="flex:none;width:16px;height:16px"' + (vis(k) ? ' checked' : '') + '> ' + esc(label) + '</label>'; };
        var grid = function (items) { return '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:8px 16px">' + items.join('') + '</div>'; };
        var html = '<div class="navcfg-h">Top-level menu</div>' + grid(NAV_ITEMS.map(function (it) { return box(it.k, it.label); }));
        NAV_SUBS.forEach(function (g) { html += '<div class="navcfg-h">' + esc(g.group) + '</div>' + grid(g.items.map(function (it) { return box(it.k, it.label); })); });
        return html;
      })() + '</div>' +
      '<h2>Data import</h2><div class="card">' +
      '<div class="muted" style="font-size:13px;margin-bottom:12px">Bring in each data source — Active Directory, ManageEngine, Tenable.io, CrowdStrike, and scan findings. Files are parsed and cached in your browser and feed the dashboards.</div>' +
      '<a class="btn primary" href="#/import">Open Data Import →</a></div>' +
      '<h2>Privacy</h2><div class="card">' +
      '<label style="display:flex;align-items:center;gap:9px;font-size:13.5px;cursor:pointer"><input type="checkbox" id="epssLive" style="flex:none;width:16px;height:16px"' + (c.epssLive ? ' checked' : '') + '> Live EPSS lookup (FIRST.org) for CVEs missing from the local feed</label>' +
      '<div class="muted" style="font-size:12.5px;margin-top:9px">This console is local-first: your findings, scan data, and settings stay in this browser, and the bundled EPSS feed already covers almost every CVE. Leave this <b>off</b> and a finding with no local EPSS score simply shows a dash. Turn it <b>on</b> and, for those rare CVEs, opening a finding fetches the score from <code>api.first.org</code>, which sends the CVE id you are viewing to a third party. The id itself is public, but the lookups reveal which vulnerabilities you are examining, so it stays off by default.</div></div>' +
      '<h2>Remediation SLA windows (days)</h2><div class="card"><div class="grid2">' +
      ['Critical', 'High', 'Medium', 'Low'].map(function (s) { return '<div class="field"><label>' + s + '</label><input type="number" min="0" data-sla="' + s + '" value="' + esc(c.sla[s]) + '"></div>'; }).join('') +
      '</div><div class="muted" style="font-size:12.5px">SLA due = first-seen date + window. Drives overdue flags and SLA compliance.</div></div>' +
      '<h2>Risk weighting</h2><div class="card">' +
      '<div class="muted" style="font-size:12.5px;margin-bottom:12px">The risk score is a transparent blend of six signals, not a black box. Set how much each one counts: <b>1.0</b> is the default, <b>0</b> removes a signal, <b>2.0</b> doubles it. Changes apply everywhere the score is used (sorting, dashboards, asset and remediation risk).</div>' +
      RW_SIGNALS.map(function (sg) { var v = (c.riskWeights && c.riskWeights[sg.k] != null) ? c.riskWeights[sg.k] : 1; return '<div class="rw-row"><span>' + esc(sg.l) + '</span><input type="range" class="rw" data-w="' + sg.k + '" min="0" max="2" step="0.1" value="' + v + '"><span class="rw-val" id="rwv-' + sg.k + '">' + Number(v).toFixed(1) + '</span></div>'; }).join('') +
      '<div class="toolbar" style="margin-top:10px"><button class="btn sm" id="rwReset">Reset to defaults</button></div></div>' +
      '<h2>Backup &amp; transfer</h2><div class="card">' +
      '<div class="muted" style="font-size:12.5px;margin-bottom:12px">Export your settings and saved views to a JSON file, for backup (in case this browser gets cleared) or to move them to another browser or a teammate. <b>API keys and secrets are never included</b>, and importing never overwrites this browser\'s own keys. Everything stays local.</div>' +
      '<div class="toolbar"><button class="btn" id="cfgExport">Export settings</button><button class="btn" id="cfgImport">Import settings</button><input type="file" id="cfgFile" accept="application/json,.json" hidden></div></div>' +
      '<h2>Recurrence</h2><div class="card">' +
      '<div class="field" style="max-width:340px"><label>Flag as recurring after N reopens</label><input type="number" min="1" id="recurThreshold" value="' + esc(c.recurThreshold || 1) + '"></div>' +
      '<div class="muted" style="font-size:12.5px">A finding is marked recurring / flapping once it has been reopened (after being resolved) at least this many times. Drives the ↻ chip, the Recurring filter, and the dashboard KPI. Default 1.</div></div>' +
      '<h2>Jira</h2><div class="card">' +
      '<div class="field"><label>Base URL</label><input type="text" id="jiraBase" value="' + esc(c.jiraBase) + '" placeholder="https://yourorg.atlassian.net"></div>' +
      '<div class="grid2"><div class="field"><label>Project ID (pid, numeric)</label><input type="text" id="jiraPid" value="' + esc(c.jiraPid) + '" placeholder="10001"></div>' +
      '<div class="field"><label>Issue type ID</label><input type="text" id="jiraType" value="' + esc(c.jiraType) + '" placeholder="10002"></div></div>' +
      '<div class="muted" style="font-size:12.5px">With project + issue-type IDs set, "Open Jira story" pre-fills summary & description. Without them it opens the create dialog. (Path A: deep-link only — no API token, nothing leaves the browser.)</div></div>' +
      '<h2>ServiceNow</h2><div class="card">' +
      '<div class="field"><label>Base URL</label><input type="text" id="snowBase" value="' + esc(c.snowBase) + '" placeholder="https://yourorg.service-now.com"></div>' +
      '<div class="muted" style="font-size:12.5px">"Open SNOW incident" opens a new incident pre-filled with the finding. "Search ServiceNow" queries existing incidents for the CVE.</div></div>' +
      '<h2>Tenable.io API keys</h2><div class="card">' +
      '<div class="muted" style="font-size:12.5px;margin-bottom:12px">Stored in <b>this browser only</b> — never uploaded. Tenable.io (cloud.tenable.com) blocks direct in-browser API calls (CORS), so these aren\'t used for live pulls yet; they\'re saved for a future local connector. To bring data in today, use <a href="#/import">Import</a> with a Tenable.io export.</div>' +
      '<div class="grid2"><div class="field"><label>Access key</label><input type="password" id="tioAccess" autocomplete="off" value="' + esc(c.tioAccess) + '" placeholder="access key"></div>' +
      '<div class="field"><label>Secret key</label><input type="password" id="tioSecret" autocomplete="off" value="' + esc(c.tioSecret) + '" placeholder="secret key"></div></div></div>' +
      '<h2>ManageEngine API</h2><div class="card">' +
      '<div class="muted" style="font-size:12.5px;margin-bottom:12px">Endpoint Central / Vulnerability Manager Plus uses <b>OAuth2</b> (Zoho self-client). Stored in <b>this browser only</b>. Like Tenable.io / CrowdStrike, ManageEngine doesn\'t send CORS headers to a static origin, so these aren\'t used for live in-browser pulls yet — they\'re saved for a future local connector. To bring data in today, use <a href="#/import">Import</a> with a ManageEngine export.</div>' +
      '<div class="field"><label>Server URL</label><input type="text" id="meUrl" value="' + esc(c.meUrl) + '" placeholder="https://endpoint-central.yourorg.com"></div>' +
      '<div class="grid2"><div class="field"><label>Client ID</label><input type="password" id="meClientId" autocomplete="off" value="' + esc(c.meClientId) + '" placeholder="client ID"></div>' +
      '<div class="field"><label>Client Secret</label><input type="password" id="meClientSecret" autocomplete="off" value="' + esc(c.meClientSecret) + '" placeholder="client secret"></div></div></div>' +
      '<h2>Guided tour</h2><div class="card">' +
      '<label style="display:flex;align-items:center;gap:9px;font-size:13.5px;cursor:pointer"><input type="checkbox" id="tourAuto" style="flex:none;width:16px;height:16px"' + (load('vmops-tour-auto', false) ? ' checked' : '') + '> Show the guided tour automatically on first visit</label>' +
      '<div class="muted" style="font-size:12.5px;margin:9px 0 12px">A quick coachmark walkthrough of the workflow — the dashboard strip, findings, campaigns, and reporting. Replay it anytime from the “Take a tour” button on the Dashboard, or with ⌘K / Ctrl-K → “Guided tour”.</div>' +
      '<button class="btn" id="tourStart">Start tour now</button></div>' +
      '<h2>Remediation samples</h2><div class="card">' +
      '<div class="muted" style="font-size:12.5px;margin-bottom:12px">Add your own remediation scripts — they appear in the finding drawer and CVE detail under “Remediation”. Saved in <b>this browser only</b> and merged with the built-in samples (yours take priority). Match a <b>specific CVE</b>, or a <b>keyword pattern</b> tested against the finding name/description. Placeholders <code>{CVE}</code> <code>{HOST}</code> <code>{NAME}</code> are substituted. <b>Export</b> gives you a JSON blob to fold into the shipped set.</div>' +
      '<div id="remedList"></div>' +
      '<div class="grid2"><div class="field"><label>Match by</label><select id="remType"><option value="cve">Specific CVE</option><option value="class">Keyword pattern</option></select></div>' +
      '<div class="field"><label id="remMatchLabel">CVE ID</label><input type="text" id="remMatch" placeholder="CVE-2024-1234"></div></div>' +
      '<div class="grid2"><div class="field"><label>Title</label><input type="text" id="remTitle" placeholder="e.g. Update Acme Agent"></div>' +
      '<div class="field"><label>Language (badge)</label><input type="text" id="remLang" placeholder="PowerShell"></div></div>' +
      '<div class="grid2"><div class="field"><label>Applies to OS <span class="muted" style="font-weight:400;font-size:11px">(optional)</span></label><select id="remOs"><option value="any">Any OS</option><option value="windows">Windows</option><option value="linux">Linux</option><option value="appliance">Appliance</option></select></div>' +
      '<div class="field"><label>Only for severity <span class="muted" style="font-weight:400;font-size:11px">(optional)</span></label><select id="remSev"><option value="any">Any severity</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option></select></div></div>' +
      '<div class="muted" style="font-size:11.5px;margin:-4px 0 4px">Tip: set an OS/severity with <b>no keyword</b> to match broadly (e.g. every Critical finding). Broad samples take priority over the built-ins for those findings.</div>' +
      '<div class="field"><label>Script <span class="muted" style="font-weight:400;font-size:11px">— one line per row</span></label><textarea id="remScript" rows="8" placeholder="#Requires -RunAsAdministrator&#10;# {CVE} - {NAME} on {HOST}&#10;winget upgrade --id Acme.Agent --silent"></textarea></div>' +
      '<div class="toolbar"><button class="btn primary" id="remAdd">Add sample</button><button class="btn" id="remCancelEdit" style="display:none">Cancel edit</button><button class="btn" id="remExport">Export JSON</button><button class="btn" id="remImport">Import JSON</button><button class="btn" id="remReset">Reset to built-ins</button><input type="file" id="remFile" accept="application/json,.json" hidden></div></div>' +
      '<div class="toolbar"><button class="btn primary" id="saveCfg">Save settings</button><button class="btn" id="resetSla">Reset SLA to defaults</button></div>';
    document.getElementById('saveCfg').addEventListener('click', function () {
      STATE.cfg.brand = document.getElementById('brandName').value.trim();
      STATE.cfg.brandIcon = document.getElementById('brandIcon').value.trim();
      STATE.cfg.brandIconColor = document.getElementById('brandIconColor').value.trim();
      [].forEach.call(document.querySelectorAll('[data-sla]'), function (i) { var v = parseInt(i.value, 10); if (!isNaN(v)) STATE.cfg.sla[i.getAttribute('data-sla')] = Math.max(0, v); });
      STATE.cfg.jiraBase = document.getElementById('jiraBase').value.trim();
      STATE.cfg.jiraPid = document.getElementById('jiraPid').value.trim();
      STATE.cfg.jiraType = document.getElementById('jiraType').value.trim();
      STATE.cfg.snowBase = document.getElementById('snowBase').value.trim();
      STATE.cfg.tioAccess = document.getElementById('tioAccess').value.trim();
      STATE.cfg.tioSecret = document.getElementById('tioSecret').value.trim();
      STATE.cfg.meUrl = document.getElementById('meUrl').value.trim();
      STATE.cfg.meClientId = document.getElementById('meClientId').value.trim();
      STATE.cfg.meClientSecret = document.getElementById('meClientSecret').value.trim();
      STATE.cfg.epssLive = document.getElementById('epssLive').checked;
      STATE.cfg.recurThreshold = Math.max(1, parseInt(document.getElementById('recurThreshold').value, 10) || 1);
      var nh = []; [].forEach.call(document.querySelectorAll('.navtoggle'), function (cb) { if (!cb.checked) nh.push(cb.getAttribute('data-nav')); }); STATE.cfg.navHidden = nh;
      var rw = {}; [].forEach.call(document.querySelectorAll('.rw'), function (s) { rw[s.getAttribute('data-w')] = Math.max(0, Math.min(2, parseFloat(s.value) || 0)); }); STATE.cfg.riskWeights = Object.assign({}, DEFAULT_WEIGHTS, rw);
      save('vmops-config', STATE.cfg); applyBrand(); toast('Settings saved');
    });
    [].forEach.call(document.querySelectorAll('.rw'), function (s) { s.addEventListener('input', function () { var el = document.getElementById('rwv-' + s.getAttribute('data-w')); if (el) el.textContent = Number(s.value).toFixed(1); }); });
    var rwR = document.getElementById('rwReset'); if (rwR) rwR.addEventListener('click', function () { STATE.cfg.riskWeights = Object.assign({}, DEFAULT_WEIGHTS); save('vmops-config', STATE.cfg); viewSettings(); toast('Risk weights reset'); });
    document.getElementById('resetSla').addEventListener('click', function () { STATE.cfg.sla = Object.assign({}, DEFAULT_CFG.sla); save('vmops-config', STATE.cfg); viewSettings(); toast('SLA windows reset'); });
    document.getElementById('cfgExport').addEventListener('click', exportSettings);
    document.getElementById('cfgImport').addEventListener('click', function () { document.getElementById('cfgFile').click(); });
    document.getElementById('cfgFile').addEventListener('change', function (e) { var f = e.target.files[0]; if (!f) return; var r = new FileReader(); r.onload = function () { importSettings(String(r.result || '')); }; r.readAsText(f); e.target.value = ''; });
    var ta = document.getElementById('tourAuto');
    if (ta) ta.addEventListener('change', function () { save('vmops-tour-auto', ta.checked); toast(ta.checked ? 'Tour will show on first visit' : 'Auto tour turned off'); });
    var tstart = document.getElementById('tourStart');
    if (tstart) tstart.addEventListener('click', function () { if (window.startTour) window.startTour(); });
    wireRemedSettings();
  }

  // ---------- vendored same-origin sub-apps ----------
  // The Tenable VM Dashboard and Agent Coverage dashboards are native same-origin views
  // (acd.js / tvd.js, rendered into #app on their routes) — no iframes.

  function viewEmpty(active) {
    setActive(active);
    app.innerHTML = '<header class="view"><div class="overline">' + esc(window.VM_BRAND || 'Vulnerability Management Console') + '</div><h1>No findings yet</h1>' +
      '<p class="lede">Import a Tenable / Nessus CSV export, or load the sample data set, to start tracking remediation.</p></header>' +
      '<div class="toolbar"><button class="btn primary" id="goImport">Import findings</button><button class="btn" id="goSample">Load sample data</button></div>';
    document.getElementById('goImport').addEventListener('click', function () { location.hash = '#/import'; });
    document.getElementById('goSample').addEventListener('click', function () { var _s = SAMPLE(); mergeFindings(_s); seedSampleOverrides(_s); toast('Loaded sample findings'); goDash(); });
  }

  // ---------- sample data ----------
  // A timestamp `days` ago, with a varied (deterministic) time-of-day for realism.
  function agoISO(days, seed) {
    var d = new Date(); d.setDate(d.getDate() - days);
    d.setHours(9 + (seed % 8), (seed * 7) % 60, 0, 0);
    return d.toISOString();
  }
  // Seed realistic triage overrides (status, owner, notes, dated status-update log) onto
  // a spread of the sample findings, so the demo shows a populated workbench. Each scenario's
  // updates are authored newest-first; never clobbers a finding that already has real triage.
  function seedSampleOverrides(list) {
    var scenarios = [
      null,  // bucket 0 → left as "New" (untouched)
      { status: 'triaged', owner: 'SecOps',
        notes: 'Confirmed reachable from the DMZ segment; vendor advisory reviewed. Assigned for patching this sprint.',
        upd: [[2, 'Triaged — owner assigned, targeting this sprint'], [3, 'Status → Triaged']] },
      { status: 'in_remediation', owner: 'Platform Team',
        notes: 'Vendor patch identified. Change request CHG-004821 raised; deploying in the next maintenance window.',
        upd: [[1, 'Patch scheduled for Saturday maintenance window'], [4, 'Status → In Remediation'], [6, 'Status → Triaged']] },
      { status: 'resolved', owner: 'Platform Team',
        notes: 'Patched across all affected hosts and confirmed clean on rescan. Closing.',
        upd: [[1, 'Status → Resolved'], [2, 'Rescan clean — no longer detected'], [5, 'Patch deployed to all affected hosts'], [9, 'Status → In Remediation'], [11, 'Status → Triaged']] },
      { status: 'risk_accepted', owner: 'AppSec (Jane)',
        notes: 'Not internet-facing; mitigated by network segmentation and a WAF rule. Risk accepted through Q3 — revisit at renewal.',
        upd: [[3, 'Risk accepted — compensating controls documented (segmentation + WAF)'], [4, 'Status → Risk Accepted'], [7, 'Status → Triaged']] },
      { status: 'false_positive', owner: 'AppSec (Jane)',
        notes: 'Plugin flags the package version, but the vulnerable code path is not compiled into our build. Confirmed against the vendor advisory.',
        upd: [[2, 'Confirmed false positive — vulnerable module not present'], [2, 'Status → False Positive']] },
      { status: 'in_remediation', owner: 'Network Eng',
        notes: 'Interim ACL mitigation applied as a stopgap; firmware upgrade tracked under NET-1182.',
        upd: [[1, 'Interim ACL mitigation deployed; firmware upgrade pending'], [3, 'Status → In Remediation'], [5, 'Status → Triaged']] }
    ];
    list.forEach(function (f, i) {
      var k = keyOf(f), cur = STATE.ov[k];
      if (cur && (cur.status || cur.notes || (cur.updates && cur.updates.length))) return; // keep real triage
      var sc = scenarios[i % scenarios.length];
      if (!sc) return;
      STATE.ov[k] = {
        status: sc.status, owner: sc.owner, notes: sc.notes,
        updates: sc.upd.map(function (u, j) { return { at: agoISO(u[0], i + j), text: u[1] }; }),
        updated: agoISO(sc.upd[0][0], i)
      };
    });
    save('vmops-overrides', STATE.ov);
  }

  function SAMPLE() {
    var hosts = ['app01.corp.local', 'app02.corp.local', 'web01.corp.local', 'db01.corp.local', 'dc01.corp.local', 'vpn01.corp.local', 'mail01.corp.local', 'file01.corp.local', 'mft01.corp.local', 'fw01.corp.local'];
    var vulns = [
      ['CVE-2021-44228', 'Apache Log4j (Log4Shell)', 'Critical', 10.0, 'Remote code execution via JNDI lookups in Apache Log4j 2 message logging.'],
      ['CVE-2021-26855', 'MS Exchange ProxyLogon', 'Critical', 9.8, 'Pre-auth server-side request forgery chain enabling remote code execution on Exchange.'],
      ['CVE-2020-1472', 'Netlogon Zerologon', 'Critical', 10.0, 'Netlogon cryptographic flaw allowing unauthenticated domain-controller takeover.'],
      ['CVE-2019-19781', 'Citrix ADC Path Traversal', 'Critical', 9.8, 'Directory traversal in Citrix ADC/Gateway leading to unauthenticated code execution.'],
      ['CVE-2023-34362', 'MOVEit Transfer SQLi', 'Critical', 9.8, 'SQL injection in MOVEit Transfer enabling data theft and remote code execution.'],
      ['CVE-2022-42475', 'FortiOS SSL-VPN', 'Critical', 9.8, 'Heap overflow in FortiOS SSL-VPN allowing unauthenticated remote code execution.'],
      ['CVE-2017-0144', 'MS17-010 EternalBlue', 'High', 8.1, 'SMBv1 remote code execution exploited by WannaCry and NotPetya.'],
      ['CVE-2022-3786', 'OpenSSL 3.0.x', 'High', 7.5, 'Buffer overflow in OpenSSL 3.0 punycode certificate name parsing.'],
      ['CVE-2022-31813', 'Apache HTTP Server', 'Medium', 5.9, 'mod_proxy flaw that can drop X-Forwarded-* headers, bypassing IP-based access control.'],
      ['CVE-2018-15473', 'OpenSSH user enum', 'Medium', 5.3, 'Username enumeration via authentication timing differences in OpenSSH.'],
      ['CVE-2021-3156', 'Sudo Baron Samedit', 'High', 7.8, 'Heap buffer overflow in sudo enabling local privilege escalation to root.'],
      ['CVE-2016-2183', 'SSL/TLS SWEET32', 'Low', 3.7, 'Birthday attack on 64-bit block ciphers (3DES) in TLS/SSL sessions.']
    ];
    var repoList = ['storefront-web', 'data-platform', 'corp-infra', 'network-edge', 'messaging'];
    var out = [], pid = 100000;
    vulns.forEach(function (v, vi) {
      var n = 2 + (vi % 4);
      for (var h = 0; h < n; h++) {
        var age = (vi * 13 + h * 7) % 200; // 0..200 days back -> varied SLA states
        var svpr = Math.round(Math.max(1, Math.min(10, (v[3] || 5) + (((vi * 3 + h) % 7) - 3) * 0.6)) * 10) / 10;
        out.push({ cve: v[0], host: hosts[(vi + h) % hosts.length], severity: v[2], cvss: v[3], vpr: svpr, plugin: String(pid++), name: v[1], desc: v[4], repo: repoList[(vi + h) % repoList.length], source: 'Tenable', firstSeen: addDays(todayISO(), -age) });
      }
    });
    return out;
  }

  function viewWiz() {
    setActive('wiz');
    // The Wiz CNAPP dashboard lives in its own module (wiz.js) so it can be swapped
    // for a live connector feed later without touching this file.
    if (window.WIZ && typeof window.WIZ.open === 'function') { window.WIZ.open(); return; }
    app.innerHTML =
      '<header class="view"><div class="overline">Cloud findings</div><h1>Wiz cloud findings</h1>' +
      '<p class="lede">Cloud (CNAPP) findings from Wiz, alongside your Tenable findings and agent coverage.</p></header>' +
      privSlim() +
      '<div class="card" style="text-align:center;padding:40px 24px">' +
      '<div style="font-family:var(--serif);font-size:20px;margin-bottom:8px">Wiz dashboard did not load</div>' +
      '<div class="muted" style="max-width:560px;margin:0 auto 18px;font-size:14px;line-height:1.6">The Wiz module (wiz.js) is unavailable. Reload the page; if it persists, the script failed to load.</div>' +
      '<a class="btn primary" href="#/import">Open Data Import →</a></div>';
  }

  // ========================= Remediation Campaigns =========================
  // Org-level layer above per-finding triage: group findings (by a saved filter or a static
  // snapshot), give them an owner/due/target, and track them to closure. Stored in localStorage.
  var CAMP_STATUS = [
    { k: 'planning', l: 'Planning' }, { k: 'active', l: 'Active' }, { k: 'paused', l: 'Paused' },
    { k: 'completed', l: 'Completed' }, { k: 'cancelled', l: 'Cancelled' }
  ];
  var CAMP_PRIO = ['P1', 'P2', 'P3', 'P4'];
  var _campSeed = null;   // a Findings filter handed off via the "+ Campaign" button
  function loadCampaigns() { try { return JSON.parse(localStorage.getItem('vmops-campaigns') || '[]') || []; } catch (e) { return []; } }
  function saveCampaigns(list) { return save('vmops-campaigns', list); }
  function campStatusLabel(k) { for (var i = 0; i < CAMP_STATUS.length; i++) if (CAMP_STATUS[i].k === k) return CAMP_STATUS[i].l; return k; }
  function campVal(id) { var e = document.getElementById(id); return e ? e.value : ''; }
  function campOpts(arr, sel) { return arr.map(function (o) { return '<option' + (o === sel ? ' selected' : '') + '>' + esc(o) + '</option>'; }).join(''); }

  // The findings a campaign covers: static snapshot (frozen keys) or dynamic (a saved filter).
  function campaignFindings(c) {
    var s = (c && c.scope) || {};
    if (s.dynamic === false && s.staticKeys) {
      var set = {}; s.staticKeys.forEach(function (k) { set[k] = 1; });
      return STATE.findings.filter(function (x) { return set[keyOf(x)]; });
    }
    var f = s.filt || {};
    return STATE.findings.filter(function (x) {
      if (f.sev && x.severity !== f.sev) return false;
      if (f.status && statusOf(x) !== f.status) return false;
      if (f.overdue && slaState(x) !== 'overdue') return false;
      if (f.exploited) { var it = cveIntel(x.cve); if (!it.kev && !it.exploit) return false; }
      if (f.owner && (ovOf(x).owner || '') !== f.owner) return false;
      if (f.q) { var q = f.q.toLowerCase(); if ((x.cve + ' ' + x.host + ' ' + (x.name || '') + ' ' + (x.desc || '') + ' ' + repoOf(x)).toLowerCase().indexOf(q) === -1) return false; }
      return true;
    });
  }
  function campaignStats(c) {
    var fs = campaignFindings(c), total = fs.length;
    var resolved = fs.filter(function (x) { return !isOpen(x); }).length;
    var overdue = fs.filter(function (x) { return isOpen(x) && slaState(x) === 'overdue'; }).length;
    return { total: total, resolved: resolved, open: total - resolved, overdue: overdue, pct: total ? Math.round(resolved / total * 100) : 0 };
  }
  function campScopeText(c) {
    var s = (c && c.scope) || {};
    if (s.dynamic === false) return 'Static · ' + ((s.staticKeys || []).length) + ' findings';
    var f = s.filt || {}, bits = [];
    if (f.sev) bits.push(f.sev); if (f.status) bits.push(SLABEL[f.status] || f.status);
    if (f.exploited) bits.push('Exploited'); if (f.overdue) bits.push('Overdue'); if (f.q) bits.push('“' + f.q + '”');
    return 'Dynamic' + (bits.length ? ' · ' + bits.join(', ') : ' · all findings');
  }
  function pbar(pct) { return '<span class="pbar"><span class="pbar-fill" style="width:' + pct + '%"></span></span> <span class="pbar-num">' + pct + '%</span>'; }
  // Compact "Active campaigns" section for the Dashboard ('' when there are none).
  function dashCampaigns() {
    var camps = loadCampaigns().filter(function (c) { return c.status !== 'completed' && c.status !== 'cancelled'; });
    if (!camps.length) return '';
    return '<h2>Active campaigns</h2><div class="card" style="padding:0;overflow-x:auto"><table class="grid"><thead><tr><th>Name</th><th>Owner</th><th>Progress</th><th>Overdue</th><th>Due</th><th>Status</th></tr></thead><tbody>' +
      camps.map(function (c) {
        var st = campaignStats(c);
        return '<tr><td><a href="#/campaigns/' + esc(c.id) + '"><b>' + esc(c.name) + '</b></a></td>' +
          '<td>' + esc(c.owner || '—') + '</td>' +
          '<td>' + pbar(st.pct) + ' <span class="muted" style="font-size:11px">' + st.resolved + '/' + st.total + '</span></td>' +
          '<td>' + (st.overdue ? '<span class="badge crit">' + st.overdue + '</span>' : '<span class="muted">—</span>') + '</td>' +
          '<td>' + (c.dueDate ? esc(c.dueDate) : '—') + '</td>' +
          '<td><span class="stbadge st-' + esc(c.status) + '">' + esc(campStatusLabel(c.status)) + '</span></td></tr>';
      }).join('') + '</tbody></table></div>';
  }

  // Risk-tiered target date (CISA BOD 26-04 flavour): exploited/KEV in scope → urgent, else severity SLA.
  function campSuggestDue(fs) {
    var open = fs.filter(isOpen); if (!open.length) return null;
    var kev = open.some(function (f) { var it = cveIntel(f.cve); return it.kev || it.exploit; });
    var rank = Math.min.apply(null, open.map(function (f) { return SEV_ORDER[f.severity]; }));
    var sla = STATE.cfg.sla || {};
    var days = kev ? Math.min(14, sla.Critical || 14) : ([sla.Critical, sla.High, sla.Medium, sla.Low][rank] || sla.Medium || 30);
    return { date: addDays(todayISO(), days), kev: kev, days: days };
  }
  function sparkline(hist) {
    if (!hist || hist.length < 2) return '<span class="muted" style="font-size:12px">Trend appears after a day of history.</span>';
    var w = 200, h = 32, n = hist.length;
    var pts = hist.map(function (p, i) { return ((i / (n - 1)) * w).toFixed(1) + ',' + (h - (Math.max(0, Math.min(100, p.pct)) / 100) * h).toFixed(1); }).join(' ');
    return '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none" style="vertical-align:middle"><polyline fill="none" stroke="var(--accent)" stroke-width="2" points="' + pts + '"/></svg> <span class="muted" style="font-size:11px">' + hist[0].pct + '% → ' + hist[n - 1].pct + '% over ' + n + ' days</span>';
  }

  // A few realistic demo campaigns over the sample findings (parallels "Load sample data").
  function SAMPLE_CAMPAIGNS() {
    var hist = function (pcts) { return pcts.map(function (p, i) { return { d: addDays(todayISO(), -(pcts.length - i)), pct: p }; }); };
    return [
      { id: 'sample-kev', sample: true, name: 'Critical severity remediation — Q3', owner: 'SecOps', team: 'Security', priority: 'P1', status: 'active', dueDate: addDays(todayISO(), 10), ticketRef: 'VULN-1041', created: addDays(todayISO(), -21), notes: 'Board-visible push on the critical backlog. Weekly check-in on Fridays.', scope: { dynamic: true, filt: { sev: 'Critical' } }, history: hist([12, 20, 33, 41]) },
      { id: 'sample-web', sample: true, name: 'Internet-facing web servers', owner: 'Platform Team', team: 'Infrastructure', priority: 'P2', status: 'active', dueDate: addDays(todayISO(), 25), created: addDays(todayISO(), -14), notes: 'Coordinate change windows with the app owners.', scope: { dynamic: true, filt: { q: 'web' } }, history: hist([0, 15, 28]) },
      { id: 'sample-smb', sample: true, name: 'Legacy SMB / EternalBlue eradication', owner: 'Network Eng', team: 'Infrastructure', priority: 'P2', status: 'paused', dueDate: addDays(todayISO(), 30), created: addDays(todayISO(), -30), notes: 'Disable SMBv1 fleet-wide — see the PowerShell remediation samples on each finding.', scope: { dynamic: true, filt: { q: 'smb' } }, history: hist([40, 55, 70]) },
      { id: 'sample-priv', sample: true, name: 'Linux privilege-escalation backlog', owner: 'AppSec (Jane)', team: 'Security', priority: 'P3', status: 'planning', dueDate: addDays(todayISO(), 45), created: addDays(todayISO(), -7), notes: 'Sudo / kernel local privesc across the Linux estate.', scope: { dynamic: true, filt: { q: 'sudo' } }, history: hist([0, 5]) }
    ];
  }
  function loadSampleCampaigns() {
    if (!STATE.findings.length) { var _s = SAMPLE(); mergeFindings(_s); seedSampleOverrides(_s); }
    var camps = loadCampaigns();
    if (camps.some(function (c) { return c.sample; })) { toast('Sample campaigns already loaded'); campaignList(); return; }
    saveCampaigns(camps.concat(SAMPLE_CAMPAIGNS()));
    toast('Loaded sample campaigns'); campaignList();
  }

  function viewCampaigns() {
    setActive('campaigns');
    var parts = (location.hash.replace(/^#/, '') || '').split('/').filter(Boolean); // ['campaigns', id?]
    var go = parts[1] ? function () { campaignDetail(safeDecode(parts[1])); } : campaignList;
    go();
    // "exploited only" scopes depend on the KEV/exploit intel; load it and re-render once ready.
    if (!INTEL.loaded) ensureIntel().then(function () { if ((location.hash || '').indexOf('#/campaigns') === 0) go(); });
  }

  // ===================== Campaign Manager (portfolio layer over all campaigns) =====================
  var CM = { view: 'board', sort: { k: 'name', dir: 1 }, tcol: {}, sel: {} };
  function cmStatusColor(k) { return { planning: 'var(--soft)', active: 'var(--accent)', paused: 'var(--med)', completed: 'var(--ok)', cancelled: 'var(--faint)' }[k] || 'var(--accent)'; }
  function campSetStatus(id, status) {
    var camps = loadCampaigns(), c = camps.filter(function (x) { return x.id === id; })[0];
    if (!c || c.status === status) return; c.status = status; saveCampaigns(camps);
  }
  // A campaign is "at risk" if it's still live and either has findings past SLA or is past its own due date.
  function campAtRisk(c, st) {
    if (c.status === 'completed' || c.status === 'cancelled') return '';
    if (st.overdue > 0) return st.overdue + ' finding' + (st.overdue > 1 ? 's' : '') + ' past SLA';
    if (c.dueDate && c.dueDate < todayISO() && st.pct < 100) return 'past the due date';
    return '';
  }
  function managedKeys() { var s = {}; loadCampaigns().forEach(function (c) { campaignFindings(c).forEach(function (f) { s[keyOf(f)] = 1; }); }); return s; }
  function unmanagedOpen() { var mk = managedKeys(); return STATE.findings.filter(function (f) { return isOpen(f) && !mk[keyOf(f)]; }); }
  function cmPortfolioKpis(camps) {
    var active = 0, totF = 0, resF = 0, overdueCamps = 0, atRisk = 0;
    camps.forEach(function (c) { if (c.status === 'active') active++; var st = campaignStats(c); totF += st.total; resF += st.resolved; if (st.overdue > 0) overdueCamps++; if (campAtRisk(c, st)) atRisk++; });
    var pct = totF ? Math.round(resF / totF * 100) : 0;
    var mk = managedKeys(), openAll = 0, managedOpen = 0;
    STATE.findings.forEach(function (f) { if (isOpen(f)) { openAll++; if (mk[keyOf(f)]) managedOpen++; } });
    var unmanaged = openAll - managedOpen;
    return '<div class="kpis">' +
      kpi('Campaigns', camps.length, active + ' active') +
      kpi('Progress', pct + '%', resF + ' of ' + totF + ' resolved', pct >= 90 ? 'ok' : '') +
      kpi('Overdue', overdueCamps, 'campaigns past SLA', overdueCamps ? 'crit' : 'ok') +
      kpi('At risk', atRisk, 'behind or past due', atRisk ? 'warn' : 'ok') +
      kpi('Under management', managedOpen + ' / ' + openAll, 'open findings in a campaign') +
      kpi('Unmanaged', unmanaged, 'open, in no campaign', unmanaged ? 'warn' : 'ok') +
      '</div>';
  }
  function cmCampCard(c) {
    var st = campaignStats(c), risk = campAtRisk(c, st), sel = CM.sel[c.id];
    return '<div class="cm-card' + (risk ? ' risk' : '') + (sel ? ' sel' : '') + '" draggable="true" data-id="' + esc(c.id) + '">' +
      '<span class="ct-cbox' + (sel ? ' on' : '') + '" data-selid="' + esc(c.id) + '" role="checkbox" aria-checked="' + (sel ? 'true' : 'false') + '">' + (sel ? '✓' : '') + '</span>' +
      '<div class="cm-c1"><a href="#/campaigns/' + esc(c.id) + '">' + esc(c.name) + '</a>' + (c.priority ? ' <span class="pri ' + esc((c.priority || '').toLowerCase()) + '">' + esc(c.priority) + '</span>' : '') + '</div>' +
      '<div class="cm-c2">' + pbar(st.pct) + '</div>' +
      '<div class="cm-c3"><span class="muted">' + esc(c.owner || 'Unassigned') + '</span>' + (st.overdue ? ' <span class="badge crit" title="findings past SLA">' + st.overdue + ' overdue</span>' : '') + (risk ? ' <span class="cm-risk" title="' + esc(risk) + '">at risk</span>' : '') + '</div>' +
      '<div class="cm-c4 muted">' + (c.dueDate ? 'Due ' + esc(c.dueDate) : 'No due date') + ' · ' + st.resolved + '/' + st.total + '</div></div>';
  }
  function cmBoard(camps) {
    return '<div class="ct-board" id="cmBoard">' + CAMP_STATUS.map(function (s) {
      var items = camps.filter(function (c) { return (c.status || 'planning') === s.k; });
      return '<div class="ct-col" data-k="' + s.k + '"><div class="ct-colh"><span class="ct-lbl">' + s.l + '</span><span class="ct-cnt">' + items.length + '</span></div>' +
        '<div class="ct-colb">' + (items.map(cmCampCard).join('') || '<div class="muted" style="font-size:12px;padding:6px 8px">none</div>') + '</div></div>';
    }).join('') + '</div><div class="muted" style="font-size:11.5px;margin-top:8px">Drag a campaign between columns to change its status, or focus a card and use it like the tracker. Click a campaign to open it.</div>';
  }
  var CM_COLS = [['name', 'Name', 'text'], ['scope', 'Scope', 'text'], ['owner', 'Owner', 'text'], ['priority', 'Priority', 'sel'], ['progress', 'Progress', 'num'], ['overdue', 'Overdue', 'num'], ['risk', 'Risk', 'sel'], ['due', 'Due', 'text'], ['status', 'Status', 'sel']];
  function cmFieldVal(c, k, st) {
    if (k === 'name') return c.name || ''; if (k === 'scope') return campScopeText(c); if (k === 'owner') return c.owner || '';
    if (k === 'priority') return c.priority || ''; if (k === 'progress') return st.pct; if (k === 'overdue') return st.overdue;
    if (k === 'risk') return campAtRisk(c, st) ? 'At risk' : ''; if (k === 'due') return c.dueDate || ''; if (k === 'status') return campStatusLabel(c.status);
    return '';
  }
  function cmSelOpts(k) { if (k === 'priority') return CAMP_PRIO; if (k === 'status') return CAMP_STATUS.map(function (s) { return s.l; }); if (k === 'risk') return ['At risk']; return []; }
  function cmFilterActive() { return Object.keys(CM.tcol).some(function (k) { return CM.tcol[k] !== '' && CM.tcol[k] != null; }); }
  function cmFilterCtl(col) {
    var k = col[0], type = col[2], v = CM.tcol[k] || '';
    if (type === 'sel') return '<select data-tc="' + k + '"><option value="">All</option>' + cmSelOpts(k).map(function (o) { return '<option' + (v === o ? ' selected' : '') + '>' + esc(o) + '</option>'; }).join('') + '</select>';
    if (type === 'num') return '<input data-tc="' + k + '" type="number" min="0" placeholder="≥" value="' + esc(v) + '" style="width:64px">';
    return '<input data-tc="' + k + '" type="text" placeholder="filter" value="' + esc(v) + '">';
  }
  function cmPass(c, st) {
    for (var i = 0; i < CM_COLS.length; i++) { var col = CM_COLS[i], v = CM.tcol[col[0]]; if (v === '' || v == null) continue; var fv = cmFieldVal(c, col[0], st);
      if (col[2] === 'num') { if (!(+fv >= parseFloat(v))) return false; }
      else if (col[2] === 'sel') { if (String(fv).toLowerCase() !== String(v).toLowerCase()) return false; }
      else { if (String(fv).toLowerCase().indexOf(String(v).toLowerCase()) < 0) return false; } }
    return true;
  }
  function cmTable() {
    var arrow = function (k) { return CM.sort.k === k ? (CM.sort.dir < 0 ? ' ▾' : ' ▴') : ''; };
    var head = '<tr><th class="selcol"></th>' + CM_COLS.map(function (c) { return '<th data-sk="' + c[0] + '">' + c[1] + arrow(c[0]) + '</th>'; }).join('') + '</tr>' +
      '<tr class="grid-filterrow"><th class="selcol"></th>' + CM_COLS.map(function (c) { return '<th>' + cmFilterCtl(c) + '</th>'; }).join('') + '</tr>';
    return '<div class="ct-tcap"><span id="cmCount"></span>' + (cmFilterActive() ? '<button class="btn sm" id="cmClear">Clear filters</button>' : '') + '</div>' +
      '<div class="gridwrap"><table class="grid" id="cmTable"><thead>' + head + '</thead><tbody id="cmTbody"></tbody></table></div>';
  }
  function cmFillTable(camps) {
    var rows = camps.map(function (c) { return { c: c, st: campaignStats(c) }; }).filter(function (o) { return cmPass(o.c, o.st); });
    var k = CM.sort.k, d = CM.sort.dir, num = (k === 'progress' || k === 'overdue');
    rows.sort(function (a, b) { var va = cmFieldVal(a.c, k, a.st), vb = cmFieldVal(b.c, k, b.st); if (num) { va = +va; vb = +vb; } else { va = String(va).toLowerCase(); vb = String(vb).toLowerCase(); } return va < vb ? -d : va > vb ? d : 0; });
    var tb = document.getElementById('cmTbody'); if (!tb) return;
    tb.innerHTML = rows.length ? rows.map(function (o) { var c = o.c, st = o.st, risk = campAtRisk(c, st);
      return '<tr class="cm-row' + (CM.sel[c.id] ? ' sel' : '') + '" data-id="' + esc(c.id) + '"><td class="selcol"><span class="ct-cbox' + (CM.sel[c.id] ? ' on' : '') + '" data-selid="' + esc(c.id) + '">' + (CM.sel[c.id] ? '✓' : '') + '</span></td><td><a href="#/campaigns/' + esc(c.id) + '"><b>' + esc(c.name) + '</b></a></td>' +
        '<td class="muted" style="font-size:12px">' + esc(campScopeText(c)) + '</td><td>' + esc(c.owner || '—') + '</td>' +
        '<td>' + (c.priority ? '<span class="pri ' + esc((c.priority || '').toLowerCase()) + '">' + esc(c.priority) + '</span>' : '—') + '</td>' +
        '<td>' + pbar(st.pct) + '</td><td>' + (st.overdue ? '<span class="badge crit">' + st.overdue + '</span>' : '<span class="muted">—</span>') + '</td>' +
        '<td>' + (risk ? '<span class="cm-risk" title="' + esc(risk) + '">at risk</span>' : '<span class="muted">—</span>') + '</td>' +
        '<td>' + (c.dueDate ? esc(c.dueDate) : '—') + '</td><td><span class="stbadge st-' + esc(c.status) + '">' + esc(campStatusLabel(c.status)) + '</span></td></tr>';
    }).join('') : '<tr><td colspan="' + (CM_COLS.length + 1) + '" class="muted" style="text-align:center;padding:20px">No campaigns match these filters.</td></tr>';
    var cnt = document.getElementById('cmCount'); if (cnt) cnt.innerHTML = 'Showing <b>' + rows.length + '</b> of ' + camps.length + ' campaigns';
    [].forEach.call(tb.querySelectorAll('.cm-row'), function (r) { r.addEventListener('click', function (e) { if (e.target.closest('a')) return; location.hash = '#/campaigns/' + r.dataset.id; }); });
  }
  function cmWireTable() {
    [].forEach.call(document.querySelectorAll('#cmTable th[data-sk]'), function (th) { th.onclick = function () { var k = th.dataset.sk; if (CM.sort.k === k) CM.sort.dir = -CM.sort.dir; else CM.sort = { k: k, dir: (k === 'progress' || k === 'overdue') ? -1 : 1 }; cmRenderView(); }; });
    [].forEach.call(document.querySelectorAll('#cmTable .grid-filterrow [data-tc]'), function (el) { var ev = el.tagName === 'SELECT' ? 'change' : 'input'; el.addEventListener(ev, function () { CM.tcol[el.dataset.tc] = el.value; cmFillTable(loadCampaigns()); var active = cmFilterActive(), cap = document.querySelector('#cmBody .ct-tcap'), cl = document.getElementById('cmClear'); if (active && !cl && cap) { var bb = document.createElement('button'); bb.className = 'btn sm'; bb.id = 'cmClear'; bb.textContent = 'Clear filters'; bb.onclick = function () { CM.tcol = {}; cmRenderView(); }; cap.appendChild(bb); } else if (!active && cl) cl.remove(); }); });
    var clr = document.getElementById('cmClear'); if (clr) clr.onclick = function () { CM.tcol = {}; cmRenderView(); };
  }
  function cmWireBoard() {
    var dragId = null;
    [].forEach.call(document.querySelectorAll('#cmBoard .cm-card'), function (card) {
      card.addEventListener('dragstart', function (e) { dragId = card.dataset.id; card.classList.add('drag'); e.dataTransfer.effectAllowed = 'move'; });
      card.addEventListener('dragend', function () { card.classList.remove('drag'); });
      card.addEventListener('click', function (e) { if (e.target.closest('a')) return; location.hash = '#/campaigns/' + card.dataset.id; });
    });
    [].forEach.call(document.querySelectorAll('#cmBoard .ct-col'), function (col) {
      col.addEventListener('dragover', function (e) { e.preventDefault(); col.classList.add('drop'); });
      col.addEventListener('dragleave', function () { col.classList.remove('drop'); });
      col.addEventListener('drop', function (e) { e.preventDefault(); col.classList.remove('drop'); if (!dragId) return; var c = loadCampaigns().filter(function (x) { return x.id === dragId; })[0]; if (c && (c.status || 'planning') !== col.dataset.k) { campSetStatus(dragId, col.dataset.k); toast('Campaign moved to ' + campStatusLabel(col.dataset.k)); campaignList(); } });
    });
  }
  function cmCoverageGap() {
    var un = unmanagedOpen();
    if (!un.length) return '<div class="card"><h3 style="margin:0 0 4px;font-size:14px">Coverage</h3><div class="muted" style="font-size:12.5px">Every open finding is covered by a campaign.</div></div>';
    var top = un.slice().sort(function (a, b) { return riskScore(b) - riskScore(a); }).slice(0, 8);
    return '<div class="card cm-gap"><div class="cm-gaphead"><h3 style="margin:0;font-size:14px">Unmanaged open findings <span class="badge warn">' + un.length + '</span></h3>' +
      '<button class="btn sm primary" id="cmScopeGap">Scope a campaign from these</button></div>' +
      '<div class="muted" style="font-size:12px;margin:6px 0 10px">Open findings not covered by any campaign, i.e. un-owned risk. Top by risk:</div>' +
      '<div class="cm-gaplist">' + top.map(function (f) { return '<div class="cm-gapitem"><a class="mono" href="' + CVE_DETAIL + esc(f.cve) + '">' + esc(f.cve) + '</a>' + intelChips(f.cve) + ' ' + sevBadge(f.severity) + ' <span class="host">' + esc(f.host) + '</span></div>'; }).join('') +
      '</div>' + (un.length > 8 ? '<div class="muted" style="font-size:11.5px;margin-top:8px">plus ' + (un.length - 8) + ' more</div>' : '') + '</div>';
  }
  function cmTimeline(camps) {
    var dates = []; camps.forEach(function (c) { if (c.created) dates.push(c.created); if (c.dueDate) dates.push(c.dueDate); }); dates.push(todayISO());
    if (!dates.length) return '<div class="ct-tl"><div class="muted" style="padding:14px">No campaigns.</div></div>';
    var min = dates.reduce(function (a, b) { return a < b ? a : b; }), max = dates.reduce(function (a, b) { return a > b ? a : b; });
    var minT = new Date(min).getTime(), maxT = new Date(max).getTime(), span = Math.max(1, maxT - minT);
    var p = function (d) { return (new Date(d).getTime() - minT) / span * 100; };
    var rows = camps.slice().sort(function (a, b) { return (a.dueDate || '9999') < (b.dueDate || '9999') ? -1 : 1; }).map(function (c) {
      var st = campaignStats(c), s = c.created || c.dueDate || todayISO(), e = c.dueDate || c.created || todayISO(), L = p(s), R = p(e), W = Math.max(2, R - L);
      return '<div class="ct-tlrow" data-id="' + esc(c.id) + '"><div class="ct-tll"><b>' + esc(c.name) + '</b> · ' + esc(c.owner || '—') + '</div>' +
        '<div class="ct-tltrack"><div class="ct-tlnow" style="left:' + p(todayISO()) + '%"></div>' +
        '<div class="ct-tlbar" style="left:' + L + '%;width:' + W + '%;background:' + cmStatusColor(c.status) + (campAtRisk(c, st) ? ';box-shadow:0 0 0 1px var(--crit)' : '') + '"></div></div></div>';
    }).join('');
    return '<div class="ct-tl">' + rows + '<div class="ct-tlaxis"><div>created → due</div><div class="ct-tlticks"><span class="ct-tick" style="left:0%">' + esc(min) + '</span><span class="ct-tick" style="left:' + p(todayISO()) + '%">today</span><span class="ct-tick" style="left:100%">' + esc(max) + '</span></div></div></div>';
  }
  function cmCalendar(camps) {
    var byDay = {}; camps.forEach(function (c) { if (c.dueDate) (byDay[c.dueDate] = byDay[c.dueDate] || []).push(c); });
    var now = new Date(), y = now.getFullYear(), m = now.getMonth(), first = new Date(y, m, 1), start = new Date(y, m, 1 - first.getDay()), today = todayISO(), cells = '';
    for (var i = 0; i < 42; i++) { var cur = new Date(start.getTime() + i * 86400000); var ci = cur.getFullYear() + '-' + String(cur.getMonth() + 1).padStart(2, '0') + '-' + String(cur.getDate()).padStart(2, '0'); var off = cur.getMonth() !== m, evs = byDay[ci] || [];
      cells += '<div class="ct-cell' + (off ? ' off' : '') + (ci === today ? ' today' : '') + '"><span class="ct-dn">' + cur.getDate() + '</span>' + evs.slice(0, 3).map(function (c) { return '<span class="ct-ev" data-id="' + esc(c.id) + '" style="background:' + cmStatusColor(c.status) + '" title="' + esc(c.name) + '">' + esc(c.name) + '</span>'; }).join('') + (evs.length > 3 ? '<span class="muted" style="font-size:10px">+' + (evs.length - 3) + '</span>' : '') + '</div>'; }
    return '<div class="ct-cal"><div class="ct-calh">' + first.toLocaleDateString('en-US', { month: 'long', year: 'numeric' }) + ' <span class="muted" style="font-size:12px">campaigns on their due date</span></div><div class="ct-calg">' + ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(function (d) { return '<div class="ct-dow">' + d + '</div>'; }).join('') + '</div><div class="ct-calg">' + cells + '</div></div>';
  }
  function cmWorkload(camps) {
    var by = {}; camps.forEach(function (c) { var o = c.owner || 'Unassigned'; (by[o] = by[o] || []).push(c); });
    var rows = Object.keys(by).map(function (o) { var cs = by[o], tot = 0, res = 0, overdue = 0; cs.forEach(function (c) { var st = campaignStats(c); tot += st.total; res += st.resolved; overdue += st.overdue; }); return { o: o, n: cs.length, pct: tot ? Math.round(res / tot * 100) : 0, overdue: overdue }; }).sort(function (a, b) { return b.n - a.n; });
    if (!rows.length) return '<div class="ct-wl"><div class="muted" style="padding:14px">No campaigns.</div></div>';
    return '<div class="ct-wl">' + rows.map(function (r) {
      return '<div class="ct-wlrow"><div class="ct-wlwho">' + ctAvatar(r.o) + '<span>' + esc(r.o) + '</span></div><div><div class="ct-wlbar"><span class="ct-wseg" style="width:' + r.pct + '%;background:var(--ok)"></span></div><div class="muted" style="font-size:11px;margin-top:5px">' + r.n + ' campaign' + (r.n > 1 ? 's' : '') + ' · ' + r.pct + '% resolved' + (r.overdue ? ' · ' + r.overdue + ' overdue findings' : '') + '</div></div><div class="ct-wltot">' + r.n + '</div></div>';
    }).join('') + '</div>';
  }
  function cmDashboard(camps) {
    var order = ['active', 'planning', 'paused', 'completed', 'cancelled'], sc = {}; order.forEach(function (k) { sc[k] = 0; }); camps.forEach(function (c) { sc[c.status] = (sc[c.status] || 0) + 1; });
    var tot = camps.length || 1, circ = 2 * Math.PI * 52, acc = 0;
    var arcs = order.map(function (k) { var len = sc[k] / tot * circ, seg = sc[k] ? '<circle r="52" cx="70" cy="70" fill="none" stroke="' + cmStatusColor(k) + '" stroke-width="20" stroke-dasharray="' + len + ' ' + (circ - len) + '" stroke-dashoffset="' + (-acc) + '" transform="rotate(-90 70 70)"/>' : ''; acc += len; return seg; }).join('');
    var donut = '<div class="card"><h3 style="margin:0 0 10px;font-size:13px">Campaigns by status</h3><div style="display:flex;align-items:center;gap:16px"><svg viewBox="0 0 140 140" style="width:126px;height:126px"><circle r="52" cx="70" cy="70" fill="none" stroke="color-mix(in srgb,var(--line) 60%,transparent)" stroke-width="20"/>' + arcs + '<text x="70" y="66" text-anchor="middle" font-size="26" font-weight="700" fill="var(--ink)">' + camps.length + '</text><text x="70" y="84" text-anchor="middle" font-size="10" fill="var(--soft)">total</text></svg><div style="display:flex;flex-direction:column;gap:6px;font-size:12px">' + order.map(function (k) { return '<span><span style="display:inline-block;width:9px;height:9px;border-radius:3px;background:' + cmStatusColor(k) + ';margin-right:6px"></span>' + campStatusLabel(k) + ' <b>' + sc[k] + '</b></span>'; }).join('') + '</div></div></div>';
    var prog = '<div class="card"><h3 style="margin:0 0 10px;font-size:13px">Progress by campaign</h3>' + camps.slice().sort(function (a, b) { return campaignStats(b).pct - campaignStats(a).pct; }).map(function (c) { var st = campaignStats(c); return '<div style="display:grid;grid-template-columns:160px 1fr 40px;gap:10px;align-items:center;font-size:12px;margin-bottom:8px"><a href="#/campaigns/' + esc(c.id) + '" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + esc(c.name) + '</a><span style="height:9px;border-radius:99px;background:color-mix(in srgb,var(--line) 60%,transparent);overflow:hidden;display:block"><span style="display:block;height:100%;width:' + st.pct + '%;background:var(--ok)"></span></span><b style="text-align:right">' + st.pct + '%</b></div>'; }).join('') + '</div>';
    return '<div class="ct-dash"><div class="ct-dgrid">' + donut + prog + '</div></div>';
  }
  function cmBulkBar() {
    var b = document.getElementById('cmBulk'); if (!b) return;
    var ids = Object.keys(CM.sel); if (!ids.length) { b.setAttribute('hidden', ''); return; }
    b.removeAttribute('hidden');
    b.innerHTML = '<span class="bulkcount"><b>' + ids.length + '</b> selected</span>' +
      '<select id="cmbStatus"><option value="">Set status…</option>' + CAMP_STATUS.map(function (s) { return '<option value="' + s.k + '">' + s.l + '</option>'; }).join('') + '</select>' +
      '<select id="cmbPrio"><option value="">Set priority…</option>' + CAMP_PRIO.map(function (p) { return '<option>' + p + '</option>'; }).join('') + '</select>' +
      '<button class="btn sm" id="cmbOwner">Set owner…</button>' +
      '<input type="date" id="cmbDue" title="Due date"><button class="btn sm" id="cmbDueApply">Set due</button>' +
      '<span class="spacer"></span><button class="btn sm" id="cmbClear">Clear</button>';
    var apply = function (patch, msg) { var camps = loadCampaigns(); ids.forEach(function (id) { var c = camps.filter(function (x) { return x.id === id; })[0]; if (c) Object.assign(c, patch); }); saveCampaigns(camps); toast(ids.length + ' campaign' + (ids.length > 1 ? 's' : '') + ' ' + msg); CM.sel = {}; campaignList(); };
    document.getElementById('cmbStatus').onchange = function (e) { if (e.target.value) apply({ status: e.target.value }, 'set to ' + campStatusLabel(e.target.value)); };
    document.getElementById('cmbPrio').onchange = function (e) { if (e.target.value) apply({ priority: e.target.value }, 'set to ' + e.target.value); };
    document.getElementById('cmbOwner').onclick = function () { var o = (prompt('Assign owner to ' + ids.length + ' campaign(s)') || '').trim(); if (o) apply({ owner: o }, 'assigned to ' + o); };
    document.getElementById('cmbDueApply').onclick = function () { var d = document.getElementById('cmbDue').value; if (d) apply({ dueDate: d }, 'due ' + d); };
    document.getElementById('cmbClear').onclick = function () { CM.sel = {}; campaignList(); };
  }
  function cmToggleSel(cb) { var id = cb.dataset.selid; if (CM.sel[id]) delete CM.sel[id]; else CM.sel[id] = 1; cb.classList.toggle('on'); cb.innerHTML = CM.sel[id] ? '✓' : ''; var host = cb.closest('.cm-card') || cb.closest('.cm-row'); if (host) host.classList.toggle('sel'); cmBulkBar(); }
  function cmWireSel() { [].forEach.call(document.querySelectorAll('#cmBody .ct-cbox[data-selid]'), function (cb) { cb.addEventListener('click', function (e) { e.stopPropagation(); cmToggleSel(cb); }); }); }
  function cmWireItems() { [].forEach.call(document.querySelectorAll('#cmBody [data-id]'), function (el) { el.addEventListener('click', function (e) { if (e.target.closest('a') || e.target.closest('.ct-cbox')) return; location.hash = '#/campaigns/' + el.dataset.id; }); }); }
  function cmRenderView() {
    var camps = loadCampaigns(), host = document.getElementById('cmBody'); if (!host) return;
    var fn = { board: cmBoard, timeline: cmTimeline, calendar: cmCalendar, workload: cmWorkload, dashboard: cmDashboard };
    host.innerHTML = CM.view === 'table' ? cmTable() : (fn[CM.view] || cmBoard)(camps);
    if (CM.view === 'table') { cmWireTable(); cmFillTable(camps); cmWireSel(); }
    else if (CM.view === 'board') { cmWireBoard(); cmWireSel(); }
    else cmWireItems();
    cmBulkBar();
  }
  function campaignList() {
    var camps = loadCampaigns();
    var tabs = '<div class="ct-tabs" id="cmTabs">' + [['board', 'Board'], ['table', 'Table'], ['timeline', 'Timeline'], ['calendar', 'Calendar'], ['workload', 'Workload'], ['dashboard', 'Dashboard']].map(function (v) { return '<button class="ct-tab' + (CM.view === v[0] ? ' on' : '') + '" data-v="' + v[0] + '">' + v[1] + '</button>'; }).join('') + '</div>';
    app.innerHTML =
      '<header class="view"><div class="overline">Operations</div><h1>Campaign Manager</h1>' +
      '<p class="lede">Manage your remediation campaigns as a portfolio: progress, risk, and coverage across every campaign. Open one to work its findings in the tracker.</p></header>' +
      privSlim() +
      '<div class="toolbar"><button class="btn primary" id="campNew">+ New campaign</button><button class="btn" id="campSample">Load sample campaigns</button></div>' +
      '<div id="campForm"></div>' +
      (camps.length
        ? cmPortfolioKpis(camps) + tabs + '<div class="bulkbar" id="cmBulk" hidden></div><div class="ct-body" id="cmBody"></div>' + '<div style="margin-top:16px">' + cmCoverageGap() + '</div>'
        : '<div class="card" style="text-align:center;padding:34px 20px"><div class="muted">No campaigns yet. Create one to start tracking a remediation push.</div></div>');
    document.getElementById('campNew').addEventListener('click', function () { renderCampForm(null, 'campForm'); document.getElementById('campForm').scrollIntoView({ block: 'nearest' }); });
    document.getElementById('campSample').addEventListener('click', loadSampleCampaigns);
    if (_campSeed) { renderCampForm({ scope: _campSeed }, 'campForm'); _campSeed = null; }
    [].forEach.call(document.querySelectorAll('#cmTabs .ct-tab'), function (b) { b.onclick = function () { CM.view = b.dataset.v; campaignList(); }; });
    var sg = document.getElementById('cmScopeGap'); if (sg) sg.onclick = function () { _campSeed = { dynamic: false, staticKeys: unmanagedOpen().map(keyOf), filt: {} }; renderCampForm({ scope: _campSeed }, 'campForm'); _campSeed = null; document.getElementById('campForm').scrollIntoView({ block: 'nearest' }); };
    if (camps.length) cmRenderView();
  }

  function renderCampForm(c, targetId) {
    c = c || {};
    var sc = c.scope || { dynamic: true, filt: {} }, f = sc.filt || {};
    var seededStatic = (sc.dynamic === false && Array.isArray(sc.staticKeys)) ? sc.staticKeys : null;  // hand-picked selection
    var el = document.getElementById(targetId); if (!el) return;
    el.innerHTML = '<div class="card"><h3 style="margin-top:0">' + (c.id ? 'Edit campaign' : 'New campaign') + '</h3>' +
      '<div class="grid2"><div class="field"><label>Name</label><input id="cName" value="' + esc(c.name || '') + '" placeholder="e.g. Q3 internet-facing criticals"></div>' +
      '<div class="field"><label>Owner</label><input id="cOwner" value="' + esc(c.owner || '') + '" placeholder="team or person"></div></div>' +
      '<div class="grid2"><div class="field"><label>Team</label><input id="cTeam" value="' + esc(c.team || '') + '"></div>' +
      '<div class="field"><label>Priority</label><select id="cPrio"><option value=""></option>' + campOpts(CAMP_PRIO, c.priority) + '</select></div></div>' +
      '<div class="grid2"><div class="field"><label>Due date</label><input type="date" id="cDue" value="' + esc(c.dueDate || '') + '"></div>' +
      '<div class="field"><label>Status</label><select id="cStatus">' + CAMP_STATUS.map(function (s) { return '<option value="' + s.k + '"' + ((c.status || 'planning') === s.k ? ' selected' : '') + '>' + s.l + '</option>'; }).join('') + '</select></div></div>' +
      '<div class="field"><label>Ticket <span class="muted" style="font-weight:400;font-size:11px">Jira / SNOW key (optional)</span></label><input id="cTicket" value="' + esc(c.ticketRef || '') + '" placeholder="e.g. VULN-42 or INC0012345"></div>' +
      '<div style="font-weight:600;font-size:13px;color:var(--soft);margin:10px 0 6px">Scope — which findings this campaign covers</div>' +
      (loadViews().length ? '<div class="field"><label>Start from a saved view (optional)</label><select id="cViewPick"><option value="">—</option>' + loadViews().map(function (v) { return '<option value="' + esc(v.name) + '">' + esc(v.name) + '</option>'; }).join('') + '</select></div>' : '') +
      '<div class="grid2"><div class="field"><label>Severity</label><select id="cSev"><option value="">Any</option>' + campOpts(['Critical', 'High', 'Medium', 'Low'], f.sev) + '</select></div>' +
      '<div class="field"><label>Status</label><select id="cFstatus"><option value="">Any</option>' + STATUS.map(function (s) { return '<option value="' + s.k + '"' + (f.status === s.k ? ' selected' : '') + '>' + s.l + '</option>'; }).join('') + '</select></div></div>' +
      '<div class="field"><label>Search (CVE / host / product)</label><input id="cQ" value="' + esc(f.q || '') + '"></div>' +
      '<label style="font-size:13px;margin-right:14px"><input type="checkbox" id="cExpl"' + (f.exploited ? ' checked' : '') + '> Exploited only (KEV / PoC)</label>' +
      '<label style="font-size:13px"><input type="checkbox" id="cOver"' + (f.overdue ? ' checked' : '') + '> Overdue only</label>' +
      '<div style="margin-top:8px"><label style="font-size:13px"><input type="checkbox" id="cStatic"' + (sc.dynamic === false ? ' checked' : '') + '> Static snapshot — freeze the matching findings now (won\'t absorb new discoveries)</label></div>' +
      '<div class="muted" id="cCount" style="font-size:12px;margin-top:8px"></div>' +
      '<div class="muted" id="cDueHint" style="font-size:11.5px;margin-top:3px"></div>' +
      '<div class="toolbar"><button class="btn primary" id="cSave">' + (c.id ? 'Save changes' : 'Create campaign') + '</button><button class="btn" id="cCancel">Cancel</button></div></div>';
    function curFilt() { return { sev: campVal('cSev'), status: campVal('cFstatus'), q: campVal('cQ').trim(), exploited: document.getElementById('cExpl').checked, overdue: document.getElementById('cOver').checked }; }
    function noFilterSet() { var f = curFilt(); return !f.sev && !f.status && !f.q && !f.exploited && !f.overdue; }
    function updCount() {
      var fs, cc = document.getElementById('cCount');
      if (seededStatic && noFilterSet()) {
        var set = {}; seededStatic.forEach(function (k) { set[k] = 1; });
        fs = STATE.findings.filter(function (x) { return set[keyOf(x)]; });
        cc.textContent = fs.length + ' hand-picked finding(s) — frozen as a static campaign.';
      } else {
        fs = campaignFindings({ scope: { dynamic: true, filt: curFilt() } });
        cc.textContent = fs.length + ' finding(s) currently match this scope.';
      }
      var sug = campSuggestDue(fs), hint = document.getElementById('cDueHint');
      if (sug) { hint.innerHTML = 'Suggested target: <b>' + sug.date + '</b> · ' + (sug.kev ? 'KEV/exploited in scope → ' + sug.days + 'd' : sug.days + 'd (severity SLA)') + ' <a href="#" id="cDueUse">Use →</a>'; var u = document.getElementById('cDueUse'); if (u) u.onclick = function (e) { e.preventDefault(); document.getElementById('cDue').value = sug.date; }; }
      else { hint.innerHTML = ''; }
    }
    ['cSev', 'cFstatus', 'cQ', 'cExpl', 'cOver'].forEach(function (id) { var e = document.getElementById(id); e.addEventListener('input', updCount); e.addEventListener('change', updCount); });
    var vp = document.getElementById('cViewPick');
    if (vp) vp.addEventListener('change', function () {
      var s = loadViews().filter(function (x) { return x.name === vp.value; })[0]; if (!s) return; var ff = s.filt || {};
      document.getElementById('cSev').value = ff.sev || ''; document.getElementById('cFstatus').value = ff.status || '';
      document.getElementById('cQ').value = ff.q || ''; document.getElementById('cExpl').checked = !!ff.exploited; document.getElementById('cOver').checked = !!ff.overdue;
      updCount();
    });
    updCount();
    document.getElementById('cCancel').addEventListener('click', function () { el.innerHTML = ''; });
    document.getElementById('cSave').addEventListener('click', function () {
      var name = campVal('cName').trim(); if (!name) { toast('Name the campaign'); return; }
      var filt = curFilt(), isStatic = document.getElementById('cStatic').checked;
      var staticKeys = (seededStatic && noFilterSet()) ? seededStatic : campaignFindings({ scope: { dynamic: true, filt: filt } }).map(keyOf);
      var scope = isStatic ? { dynamic: false, staticKeys: staticKeys, filt: filt } : { dynamic: true, filt: filt };
      var camps = loadCampaigns(), rec = c.id ? camps.filter(function (x) { return x.id === c.id; })[0] : null;
      var data = { name: name, owner: campVal('cOwner').trim(), team: campVal('cTeam').trim(), priority: campVal('cPrio'), dueDate: campVal('cDue'), status: campVal('cStatus'), ticketRef: campVal('cTicket').trim(), scope: scope };
      if (rec) { Object.assign(rec, data); } else { data.id = 'c' + Date.now().toString(36); data.notes = ''; data.created = todayISO(); camps.push(data); }
      if (!saveCampaigns(camps)) { toast('Could not save — browser storage may be full'); return; }
      toast(c.id ? 'Campaign updated' : 'Campaign created');
      if (c.id) campaignDetail(c.id); else campaignList();
    });
  }

  function campaignDetail(id) {
    var camps = loadCampaigns(), c = camps.filter(function (x) { return x.id === id; })[0];
    if (!c) { app.innerHTML = '<header class="view"><a class="btn sm" href="#/campaigns">← Campaigns</a><h1 style="margin-top:12px">Campaign not found</h1></header>'; return; }
    var st = campaignStats(c), dirty = false;
    if (c.scope && c.scope.dynamic === false && st.total && st.pct === 100 && c.status === 'active') { c.status = 'completed'; dirty = true; }
    var today = todayISO(); c.history = c.history || [];   // one progress snapshot per day, for the trend
    if (!c.history.length || c.history[c.history.length - 1].d !== today) { c.history.push({ d: today, pct: st.pct }); if (c.history.length > 60) c.history = c.history.slice(-60); dirty = true; }
    if (dirty) saveCampaigns(camps);
    var fs = campaignFindings(c);
    app.innerHTML =
      '<header class="view"><a class="btn sm" href="#/campaigns">← Campaigns</a>' +
      '<div class="overline" style="margin-top:10px">Campaign</div><h1>' + esc(c.name) + '</h1></header>' +
      '<div class="kpis" id="campKpis">' + campKpiCards(c, st) + '</div>' +
      '<div class="card"><div class="camp-meta">' +
        '<div><span class="k">Owner</span>' + esc(c.owner || '—') + (c.team ? ' · ' + esc(c.team) : '') + '</div>' +
        '<div><span class="k">Priority</span>' + esc(c.priority || '—') + '</div>' +
        '<div><span class="k">Scope</span>' + esc(campScopeText(c)) + '</div>' +
        '<div><span class="k">Status</span><span class="stbadge st-' + esc(c.status) + '">' + esc(campStatusLabel(c.status)) + '</span></div>' +
        (c.ticketRef ? '<div><span class="k">Ticket</span>' + (function () { var sys = ticketSys(c.ticketRef); var u = ticketLink(sys, c.ticketRef); return u ? '<a href="' + esc(u) + '" target="_blank" rel="noopener">' + esc(c.ticketRef) + '</a>' : esc(c.ticketRef); })() + '</div>' : '') +
        '<div><span class="k">Trend</span>' + sparkline(c.history) + '</div></div>' +
        '<div style="margin-top:12px"><label style="display:block;font-size:12px;font-weight:600;color:var(--soft);margin-bottom:5px">Notes</label><textarea id="campNotes" style="width:100%;min-height:70px" placeholder="Plan, blockers, decisions…">' + esc(c.notes || '') + '</textarea></div>' +
        '<div class="toolbar"><button class="btn" id="campEdit">Edit</button><button class="btn" id="campJira" title="One ticket covering the open findings in this campaign">Open Jira story</button><button class="btn" id="campSnow" title="One incident covering the open findings in this campaign">Open SNOW incident</button><button class="btn" id="campDelete">Delete</button></div></div>' +
      '<div id="campEditForm"></div>' +
      '<h2>Findings (' + fs.length + ')</h2>' +
      (fs.length ? '<div id="ctMount" class="ct-mount"></div>'
        : '<div class="card"><span class="muted">No findings currently match this campaign\'s scope.</span></div>');
    var nt = document.getElementById('campNotes');
    nt.addEventListener('input', function () { var cc = loadCampaigns(), r = cc.filter(function (x) { return x.id === id; })[0]; if (r) { r.notes = nt.value; saveCampaigns(cc); } });
    document.getElementById('campEdit').addEventListener('click', function () { renderCampForm(c, 'campEditForm'); document.getElementById('campEditForm').scrollIntoView({ block: 'nearest' }); });
    document.getElementById('campJira').addEventListener('click', function () { var op = fs.filter(isOpen); if (!op.length) { toast('No open findings to ticket'); return; } ticketGroup('jira', op); });
    document.getElementById('campSnow').addEventListener('click', function () { var op = fs.filter(isOpen); if (!op.length) { toast('No open findings to ticket'); return; } ticketGroup('snow', op); });
    document.getElementById('campDelete').addEventListener('click', function () {
      if (!confirm('Delete campaign “' + c.name + '”? (The findings themselves are untouched.)')) return;
      saveCampaigns(loadCampaigns().filter(function (x) { return x.id !== id; })); toast('Campaign deleted'); location.hash = '#/campaigns';
    });
    if (fs.length) campaignTracker(c);
  }

  // ===================== Campaign Tracker (ClickUp-style multi-view) =====================
  // A multi-view lens over ONE campaign's scoped findings (campaignFindings), reusing the app's real
  // risk model (riskScore/priorityOf), intel (cveIntel), status store (setOverride) and finding drawer.
  var CT = { cid: null, view: 'board', group: 'status', q: '', qf: {}, sel: {}, tcol: {}, sort: { k: 'risk', dir: -1 }, closed: {}, grab: null };
  var CT_VIEWS = [['board', 'Board'], ['list', 'List'], ['table', 'Table'], ['calendar', 'Calendar'], ['timeline', 'Timeline'], ['workload', 'Workload'], ['dashboard', 'Dashboard'], ['activity', 'Activity']];
  var CT_GROUPS = [['status', 'Status'], ['severity', 'Severity'], ['owner', 'Assignee'], ['host', 'System'], ['patch', 'Remediation / patch']];
  var ST_VAR = { new: '--st-new', triaged: '--st-triaged', in_remediation: '--st-rem', resolved: '--st-res', risk_accepted: '--st-risk', false_positive: '--st-fp' };
  var SEV_VAR = { Critical: '--crit', High: '--high', Medium: '--med', Low: '--low', Info: '--low' };
  var SEV_BADGE = ['crit', 'high', 'med', 'low', 'low'];
  var CT_AVC = ['#0ea5e9', '#8b5cf6', '#ec4899', '#14b8a6', '#f59e0b', '#ef4444', '#22c55e', '#6366f1'];
  function ctOwner(f) { return ovOf(f).owner || 'Unassigned'; }
  function ctInitials(n) { if (!n || n === 'Unassigned') return '?'; var p = n.trim().split(/\s+/); return (p[0].charAt(0) + (p[1] ? p[1].charAt(0) : '')).toUpperCase(); }
  function ctAvColor(n) { if (!n || n === 'Unassigned') return '#64748b'; var h = 0; for (var i = 0; i < n.length; i++) h = (h * 31 + n.charCodeAt(i)) >>> 0; return CT_AVC[h % CT_AVC.length]; }
  function ctAvatar(n) { return '<span class="ct-av" style="background:' + ctAvColor(n) + '" title="' + esc(n) + '">' + esc(ctInitials(n)) + '</span>'; }
  function ctSevBadge(sev) { return '<span class="badge ' + (SEV_BADGE[SEV_ORDER[sev]] || 'low') + '">' + esc(sev) + '</span>'; }
  function ctDueBadge(f) { if (!isOpen(f)) return '<span class="muted" style="font-size:11px">—</span>'; var di = dueIn(f), ss = slaState(f); var t = di == null ? 'no SLA' : di < 0 ? (-di) + 'd overdue' : di === 0 ? 'due today' : 'due in ' + di + 'd'; return '<span class="ct-due ' + ss + '">' + t + '</span>'; }
  // "No agent" is only knowable when BOTH the AD denominator AND the Tenable agent source are loaded.
  // Without the Tenable source, a host's agent status is unknown, not absent, so do not flag it.
  function ctCoverageKnown() { var M = window._model; return !!(M && M.ad && M.ad.length && M.loaded && M.loaded.indexOf('ten') > -1); }
  function ctNoAgent(f) { if (!ctCoverageKnown()) return false; var M = window._model; if (!M._ctByKey) { M._ctByKey = {}; M.ad.forEach(function (a) { if (!(a.key in M._ctByKey)) M._ctByKey[a.key] = a; }); } var rec = M._ctByKey[norm(f.host)]; return !!(rec && rec.cov && rec.cov.ten && rec.cov.ten.present === false); }
  // MSRC patch (KB) map = the real "one patch clears N findings" fix key (data/msrc/<year>.json, unread elsewhere).
  var MSRC_CACHE = {};
  function kbsFor(cve) { var y = (String(cve).match(/CVE-(\d{4})-/) || [])[1]; if (!y || !MSRC_CACHE[y]) return null; var kb = MSRC_CACHE[y][cve]; return (kb && kb.length) ? kb : null; }
  function ensureMsrc(cves) {
    var years = {}; cves.forEach(function (c) { var y = (String(c).match(/CVE-(\d{4})-/) || [])[1]; if (y && !MSRC_CACHE[y]) years[y] = 1; });
    var need = Object.keys(years); if (!need.length) return Promise.resolve();
    return Promise.all(need.map(function (y) { return fetch('data/msrc/' + y + '.json').then(function (r) { return r.ok ? r.json() : {}; }).catch(function () { return {}; }).then(function (m) { MSRC_CACHE[y] = m || {}; }); }));
  }
  function ctFixKey(f) { var kb = kbsFor(f.cve); if (kb) return 'Patch ' + kb.slice(0, 2).join(' + '); var r = REMED.data ? remediationFor(f) : null; return r ? r.title : 'Manual remediation'; }
  function ctCamp() { return loadCampaigns().filter(function (x) { return x.id === CT.cid; })[0] || null; }
  function ctScoped() { var c = ctCamp(); return c ? campaignFindings(c) : []; }
  function ctFindings() {
    var qf = CT.qf, q = CT.q.trim().toLowerCase();
    return ctScoped().filter(function (f) {
      if (qf.kev) { var it = cveIntel(f.cve); if (!it.kev && !it.exploit) return false; }
      if (qf.overdue && slaState(f) !== 'overdue') return false;
      if (qf.critical && f.severity !== 'Critical') return false;
      if (qf.recurring && !isRecurring(f)) return false;
      if (qf.noagent && !ctNoAgent(f)) return false;
      if (q && (f.cve + ' ' + f.host + ' ' + (f.name || '') + ' ' + ctOwner(f)).toLowerCase().indexOf(q) < 0) return false;
      return true;
    });
  }
  function ctByRisk(a, b) { return riskScore(b) - riskScore(a); }
  function ctFilterActive() { return !!(CT.q || Object.keys(CT.qf).some(function (k) { return CT.qf[k]; }) || Object.keys(CT.tcol).some(function (k) { return CT.tcol[k] !== '' && CT.tcol[k] != null; })); }
  function ctEmptyState() {
    var scoped = ctScoped().length, active = ctFilterActive();
    var msg = scoped === 0 ? 'This campaign has no findings yet.' : (active ? 'No findings match the current search and filters.' : 'No open findings to show.');
    return '<div class="ct-empty"><div class="ct-empty-ic">◍</div><p>' + esc(msg) + '</p>' + (active && scoped ? '<button class="btn sm" id="ctEmptyClear">Clear search and filters</button>' : '') + '</div>';
  }
  function ctFieldVal(f) { return CT.group === 'status' ? statusOf(f) : CT.group === 'severity' ? f.severity : CT.group === 'owner' ? ctOwner(f) : CT.group === 'host' ? f.host : ctFixKey(f); }
  function ctGroupDefs(list) {
    if (CT.group === 'status') return STATUS.map(function (s) { return { k: s.k, label: s.l, color: 'var(' + ST_VAR[s.k] + ')', drag: true }; });
    if (CT.group === 'severity') return ['Critical', 'High', 'Medium', 'Low'].map(function (s) { return { k: s, label: s, color: 'var(' + SEV_VAR[s] + ')' }; });
    if (CT.group === 'owner') { var seen = {}, o = []; list.forEach(function (f) { var w = ctOwner(f); if (!seen[w]) { seen[w] = 1; o.push({ k: w, label: w, color: ctAvColor(w), drag: true }); } }); if (!seen['Unassigned']) o.push({ k: 'Unassigned', label: 'Unassigned', color: ctAvColor('Unassigned'), drag: true }); return o; }   // always offer an Unassigned column so a card can be dragged back to unassigned
    if (CT.group === 'host') { var s = {}, h = []; list.forEach(function (f) { if (!s[f.host]) { s[f.host] = 1; h.push({ k: f.host, label: f.host, color: 'var(--accent)' }); } }); return h.sort(function (a, b) { return a.label < b.label ? -1 : 1; }); }
    var pm = {}, po = []; list.forEach(function (f) { var k = ctFixKey(f); if (!pm[k]) { pm[k] = 0; po.push(k); } pm[k]++; });
    return po.sort(function (a, b) { return pm[b] - pm[a]; }).map(function (k) { return { k: k, label: k, color: 'var(--accent)' }; });
  }

  function ctCard(f) {
    var k = keyOf(f), sel = CT.sel[k];
    var drag = (CT.group === 'status' || CT.group === 'owner'), grabbed = CT.grab === k;
    var colLbl = CT.group === 'status' ? SLABEL[statusOf(f)] : CT.group === 'owner' ? ctOwner(f) : '';
    var aria = f.cve + ', ' + f.severity + ', ' + f.host + (colLbl ? ', ' + (CT.group === 'owner' ? 'assignee ' : 'status ') + colLbl : '') + (sel ? ', selected' : '');
    return '<div class="ct-card' + (slaState(f) === 'overdue' ? ' over' : '') + (sel ? ' sel' : '') + (grabbed ? ' grabbed' : '') + '" draggable="true" tabindex="0"' +
      (drag ? ' aria-roledescription="draggable card" aria-grabbed="' + (grabbed ? 'true' : 'false') + '" aria-describedby="ctKbdHelp"' : '') +
      ' aria-label="' + esc(aria) + '" data-key="' + esc(k) + '" style="border-left-color:var(' + (SEV_VAR[f.severity] || '--low') + ')">' +
      '<span class="ct-cbox' + (sel ? ' on' : '') + '" data-selk="' + esc(k) + '" role="checkbox" aria-checked="' + (sel ? 'true' : 'false') + '">' + (sel ? '✓' : '') + '</span>' +
      '<div class="ct-r1"><a class="cve" href="' + CVE_DETAIL + esc(f.cve) + '" tabindex="-1">' + esc(f.cve) + '</a>' + intelChips(f.cve) + ' ' + priChip(f) + recurChip(f) + '</div>' +
      '<div class="ct-ttl">' + esc(f.name || f.desc || 'Vulnerability') + '</div>' +
      '<div class="ct-r2">' + ctSevBadge(f.severity) + '<span class="host">' + esc(f.host) + '</span>' + (ctNoAgent(f) ? '<span class="ct-flag" title="Host has no Tenable agent — coverage blind spot">NO AGENT</span>' : '') + '<span class="ct-epss">EPSS ' + epssCell(f) + '</span></div>' +
      '<div class="ct-r3">' + ctAvatar(ctOwner(f)) + ctDueBadge(f) + '</div></div>';
  }

  function ctBoard() {
    var list = ctFindings(), groups = ctGroupDefs(list);
    return '<div class="ct-board" id="ctBoard">' + groups.map(function (g) {
      var items = list.filter(function (f) { return ctFieldVal(f) === g.k; }).sort(ctByRisk);
      return '<div class="ct-col' + (g.drag ? '' : ' nodrop') + '" data-k="' + esc(g.k) + '">' +
        '<div class="ct-colh"><span class="ct-sq" style="background:' + g.color + '"></span><span class="ct-lbl">' + esc(g.label) + '</span><span class="ct-cnt">' + items.length + '</span></div>' +
        '<div class="ct-colb">' + (items.map(ctCard).join('') || '<div class="muted" style="font-size:12px;padding:6px 8px">—</div>') + '</div></div>';
    }).join('') + '</div>' + (CT.group !== 'status' && CT.group !== 'owner'
      ? '<div class="muted" style="font-size:11.5px;margin-top:8px">Grouped by ' + esc(CT.group) + ' — read-only (severity, system and patch come from the scan). Drag to change status or assignee.</div>'
      : '<div class="muted" style="font-size:11.5px;margin-top:8px">Drag a card between columns, or focus a card and press <b>Space</b> to pick it up, then <b>←</b> / <b>→</b> to move it. <b>Enter</b> opens the finding.</div>');
  }

  function ctList() {
    var list = ctFindings(), groups = ctGroupDefs(list);
    var h = '';
    groups.forEach(function (g) {
      var items = list.filter(function (f) { return ctFieldVal(f) === g.k; }).sort(ctByRisk); if (!items.length) return;
      var closed = CT.closed[CT.group + ':' + g.k];
      h += '<div class="ct-lg' + (closed ? ' closed' : '') + '" data-g="' + esc(CT.group + ':' + g.k) + '"><div class="ct-lgh"><span class="ct-caret">▾</span><span class="ct-sq" style="background:' + g.color + '"></span><b>' + esc(g.label) + '</b><span class="ct-cnt">' + items.length + '</span></div><div class="ct-lrows">' +
        items.map(function (f) {
          return '<div class="ct-lrow" data-key="' + esc(keyOf(f)) + '"><span class="cve mono">' + esc(f.cve) + '</span>' + intelChips(f.cve) +
            '<span class="ct-lname">' + esc(f.name || f.desc || '') + (ctNoAgent(f) ? ' <span class="ct-flag">NO AGENT</span>' : '') + '</span>' +
            '<span class="host">' + esc(f.host) + '</span>' + priChip(f) + '<span class="ct-vpr">' + vprCell(f) + '</span>' +
            '<span class="ct-lend">' + ctAvatar(ctOwner(f)) + ctDueBadge(f) + '</span></div>';
        }).join('') + '</div></div>';
    });
    return '<div class="ct-list">' + (h || '<div class="muted" style="padding:14px">No findings match.</div>') + '</div>';
  }

  var CT_TCOLS = [['cve', 'CVE'], ['host', 'System'], ['sev', 'Severity'], ['pri', 'Priority'], ['vpr', 'VPR'], ['epss', 'EPSS'], ['owner', 'Assignee'], ['status', 'Status'], ['due', 'SLA due']];
  function ctPassTcol(f) {
    var t = CT.tcol;
    if (t.cve && f.cve.toLowerCase().indexOf(t.cve.toLowerCase()) < 0) return false;
    if (t.host && f.host !== t.host) return false;
    if (t.sev && f.severity !== t.sev) return false;
    if (t.pri && (priorityOf(f) || '') !== t.pri) return false;
    if (t.vpr !== '' && t.vpr != null && !(f.vpr != null && f.vpr >= parseFloat(t.vpr))) return false;
    if (t.epss !== '' && t.epss != null) { var e = cveIntel(f.cve).epss; if (e == null || e * 100 < parseFloat(t.epss)) return false; }
    if (t.owner && ctOwner(f) !== t.owner) return false;
    if (t.status && statusOf(f) !== t.status) return false;
    if (t.due) { var ss = slaState(f); if (t.due === 'overdue' && ss !== 'overdue') return false; if (t.due === 'soon' && ss !== 'soon') return false; if (t.due === 'open' && !isOpen(f)) return false; if (t.due === 'closed' && isOpen(f)) return false; }
    return true;
  }
  function ctDistinct(fn, list) { var s = {}, o = []; (list || ctScoped()).forEach(function (f) { var v = fn(f); if (v && !s[v]) { s[v] = 1; o.push(v); } }); return o.sort(); }
  function ctTctl(key) {
    var v = CT.tcol[key] || '', sc = ctScoped();
    function sel(opts) { return '<select data-tc="' + key + '"><option value="">All</option>' + opts.map(function (o) { return '<option value="' + esc(o[0]) + '"' + (v === o[0] ? ' selected' : '') + '>' + esc(o[1]) + '</option>'; }).join('') + '</select>'; }
    if (key === 'cve') return '<input data-tc="cve" type="text" placeholder="CVE…" value="' + esc(v) + '">';
    if (key === 'host') return sel(ctDistinct(function (f) { return f.host; }, sc).map(function (x) { return [x, x]; }));
    if (key === 'sev') return sel(['Critical', 'High', 'Medium', 'Low'].map(function (x) { return [x, x]; }));
    if (key === 'pri') return sel([['P1', 'P1'], ['P2', 'P2'], ['P3', 'P3']]);
    if (key === 'vpr') return '<input data-tc="vpr" type="number" min="0" max="10" step="0.1" placeholder="≥" value="' + esc(v) + '">';
    if (key === 'epss') return '<input data-tc="epss" type="number" min="0" max="100" placeholder="≥%" value="' + esc(v) + '">';
    if (key === 'owner') return sel(ctDistinct(ctOwner, sc).map(function (x) { return [x, x]; }));
    if (key === 'status') return sel(STATUS.map(function (s) { return [s.k, s.l]; }));
    if (key === 'due') return sel([['open', 'Open'], ['overdue', 'Overdue'], ['soon', 'Due soon'], ['closed', 'Closed']]);
    return '';
  }
  function ctTable() {
    var arrow = function (k) { return CT.sort.k === k ? (CT.sort.dir < 0 ? ' ▼' : ' ▲') : ''; };
    var head = '<tr>' + CT_TCOLS.map(function (c) { return '<th data-sk="' + c[0] + '">' + c[1] + arrow(c[0]) + '</th>'; }).join('') + '</tr>' +
      '<tr class="grid-filterrow">' + CT_TCOLS.map(function (c) { return '<th>' + ctTctl(c[0]) + '</th>'; }).join('') + '</tr>';
    var active = Object.keys(CT.tcol).some(function (k) { return CT.tcol[k] !== '' && CT.tcol[k] != null; });
    return '<div class="ct-tcap"><span id="ctCount"></span>' + (active ? '<button class="btn sm" id="ctClear">Clear filters</button>' : '') + '</div>' +
      '<div class="gridwrap"><table class="grid" id="ctTable"><thead>' + head + '</thead><tbody id="ctTbody"></tbody></table></div>';
  }
  function ctFillTable() {
    var list = ctFindings().filter(ctPassTcol);
    list.sort(function (a, b) {
      var A, B, k = CT.sort.k;
      if (k === 'risk' || k === 'pri') { A = riskScore(a); B = riskScore(b); }
      else if (k === 'sev') { A = SEV_ORDER[b.severity]; B = SEV_ORDER[a.severity]; }
      else if (k === 'vpr') { A = a.vpr || -1; B = b.vpr || -1; }
      else if (k === 'epss') { A = cveIntel(a.cve).epss || -1; B = cveIntel(b.cve).epss || -1; }
      else if (k === 'due') { A = dueIn(a) == null ? 1e9 : dueIn(a); B = dueIn(b) == null ? 1e9 : dueIn(b); }
      else if (k === 'owner') { A = ctOwner(a); B = ctOwner(b); }
      else if (k === 'status') { A = ST_ORDER[statusOf(a)]; B = ST_ORDER[statusOf(b)]; }
      else if (k === 'host') { A = a.host; B = b.host; }
      else { A = a.cve; B = b.cve; }
      return A < B ? -CT.sort.dir : A > B ? CT.sort.dir : 0;
    });
    var tb = document.getElementById('ctTbody'); if (!tb) return;
    tb.innerHTML = list.length ? list.map(function (f) {
      return '<tr class="ct-brow" data-key="' + esc(keyOf(f)) + '"><td class="cid"><a href="' + CVE_DETAIL + esc(f.cve) + '">' + esc(f.cve) + '</a>' + intelChips(f.cve) + '</td>' +
        '<td class="host">' + esc(f.host) + (ctNoAgent(f) ? ' <span class="ct-flag">NO AGENT</span>' : '') + '</td><td>' + ctSevBadge(f.severity) + '</td><td>' + priChip(f) + '</td>' +
        '<td>' + vprCell(f) + '</td><td>' + epssCell(f) + '</td><td>' + ctAvatar(ctOwner(f)) + ' <span class="muted" style="font-size:12px">' + esc(ctOwner(f)) + '</span></td>' +
        '<td><span class="stbadge st-' + statusOf(f) + '" style="font-size:11px">' + esc(SLABEL[statusOf(f)]) + '</span></td><td>' + ctDueBadge(f) + '</td></tr>';
    }).join('') : '<tr><td colspan="9" class="muted" style="text-align:center;padding:22px">No findings match these filters.</td></tr>';
    var cnt = document.getElementById('ctCount'); if (cnt) cnt.innerHTML = 'Showing <b>' + list.length + '</b> of ' + ctScoped().length + ' findings';
    [].forEach.call(tb.querySelectorAll('.ct-brow'), function (r) { r.addEventListener('click', function () { var f = ctFindings().filter(function (x) { return keyOf(x) === r.dataset.key; })[0]; if (f) openDrawer(f); }); });
  }

  function ctCalendar() {
    var list = ctFindings().filter(isOpen), byDay = {};
    list.forEach(function (f) { var dd = dueDate(f); if (dd) (byDay[dd] = byDay[dd] || []).push(f); });
    var now = new Date(), y = now.getFullYear(), m = now.getMonth(), first = new Date(y, m, 1), start = new Date(y, m, 1 - first.getDay());
    var today = todayISO();
    var cells = '';
    for (var i = 0; i < 42; i++) { var cur = new Date(start.getTime() + i * 86400000); var ci = cur.getFullYear() + '-' + String(cur.getMonth() + 1).padStart(2, '0') + '-' + String(cur.getDate()).padStart(2, '0'); var off = cur.getMonth() !== m, evs = byDay[ci] || []; cells += '<div class="ct-cell' + (off ? ' off' : '') + (ci === today ? ' today' : '') + '"><span class="ct-dn">' + cur.getDate() + '</span>' + evs.slice(0, 3).map(function (f) { return '<span class="ct-ev" data-key="' + esc(keyOf(f)) + '" style="background:var(' + (SEV_VAR[f.severity] || '--low') + ')" title="' + esc(f.cve + ' · ' + f.host) + '">' + esc(f.cve.replace('CVE-', '')) + '</span>'; }).join('') + (evs.length > 3 ? '<span class="muted" style="font-size:10px">+' + (evs.length - 3) + '</span>' : '') + '</div>'; }
    return '<div class="ct-cal"><div class="ct-calh">' + first.toLocaleDateString('en-US', { month: 'long', year: 'numeric' }) + ' <span class="muted" style="font-size:12px">— open findings on their SLA due date</span></div><div class="ct-calg">' + ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(function (d) { return '<div class="ct-dow">' + d + '</div>'; }).join('') + '</div><div class="ct-calg">' + cells + '</div></div>';
  }

  function ctTimeline() {
    var list = ctFindings().slice().filter(function (f) { return f.firstSeen; }).sort(function (a, b) { var da = dueDate(a) || '9999', db = dueDate(b) || '9999'; return da < db ? -1 : 1; });
    var MIN = -120, MAX = 60, span = MAX - MIN;
    function p(off) { return (off - MIN) / span * 100; }
    var rows = list.map(function (f) {
      var s = daysSince(f.firstSeen); var e = dueIn(f); var L = p(s == null ? MIN : -s), R = p(e == null ? 30 : e), W = Math.max(2, R - L);
      return '<div class="ct-tlrow" data-key="' + esc(keyOf(f)) + '"><div class="ct-tll"><b class="mono">' + esc(f.cve.replace('CVE-', '')) + '</b> · ' + esc(f.host) + '</div><div class="ct-tltrack"><div class="ct-tlnow" style="left:' + p(0) + '%"></div><div class="ct-tlbar" style="left:' + L + '%;width:' + W + '%;background:var(' + (SEV_VAR[f.severity] || '--low') + ')' + (slaState(f) === 'overdue' ? ';box-shadow:0 0 0 1px var(--crit)' : '') + '"></div></div></div>';
    }).join('');
    var ticks = [-90, -60, -30, 0, 30, 60].map(function (t) { return '<span class="ct-tick" style="left:' + p(t) + '%">' + (t === 0 ? 'today' : (t > 0 ? '+' : '') + t + 'd') + '</span>'; }).join('');
    return '<div class="ct-tl">' + (rows || '<div class="muted" style="padding:14px">No findings.</div>') + '<div class="ct-tlaxis"><div>first seen → SLA due</div><div class="ct-tlticks">' + ticks + '</div></div></div>';
  }

  function ctWorkload() {
    var by = {}; ctFindings().forEach(function (f) { var o = ctOwner(f); (by[o] = by[o] || []).push(f); });
    var rows = Object.keys(by).map(function (o) { var its = by[o], open = its.filter(isOpen), cc = { Critical: 0, High: 0, Medium: 0, Low: 0 }; open.forEach(function (f) { cc[f.severity] = (cc[f.severity] || 0) + 1; }); return { o: o, its: its, open: open.length, cc: cc, total: its.length }; }).sort(function (a, b) { return b.open - a.open; });
    var mx = Math.max.apply(null, rows.map(function (r) { return r.open; }).concat([1]));
    return '<div class="ct-wl">' + rows.map(function (r) {
      var segs = ['Critical', 'High', 'Medium', 'Low'].map(function (s) { return r.cc[s] ? '<span class="ct-wseg" style="width:' + (r.cc[s] / mx * 100) + '%;background:var(' + SEV_VAR[s] + ')" title="' + r.cc[s] + ' ' + s + '"></span>' : ''; }).join('');
      return '<div class="ct-wlrow"><div class="ct-wlwho">' + ctAvatar(r.o) + '<span>' + esc(r.o) + '</span></div><div><div class="ct-wlbar">' + segs + '</div><div class="muted" style="font-size:11px;margin-top:5px">' + r.open + ' open · ' + (r.total - r.open) + ' closed</div></div><div class="ct-wltot">' + r.open + '</div></div>';
    }).join('') + '</div>';
  }

  function ctDashboard() {
    var c = ctCamp(), scoped = ctScoped(), list = ctFindings(), filtered = list.length !== scoped.length;
    var st = filtered ? (function () { var tot = list.length, res = list.filter(function (f) { return !isOpen(f); }).length; return { total: tot, resolved: res, open: tot - res, pct: tot ? Math.round(res / tot * 100) : 0 }; })() : campaignStats(c);
    var open = list.filter(isOpen);
    var overdue = open.filter(function (f) { return slaState(f) === 'overdue'; }).length;
    var critOpen = open.filter(function (f) { return f.severity === 'Critical'; }).length;
    var kevOpen = open.filter(function (f) { return cveIntel(f.cve).kev; }).length;
    var noAgent = ctCoverageKnown() ? open.filter(ctNoAgent).length : null;
    // real findings-aware digest (cross-reference intel to THIS campaign's open findings)
    var digKev = open.filter(function (f) { return cveIntel(f.cve).kev; }).length;
    var digRw = open.filter(function (f) { return cveIntel(f.cve).ransomware; }).length;
    var digEpss = open.filter(function (f) { var e = cveIntel(f.cve).epss; return e != null && e >= 0.5; }).length;
    var digDueToday = open.filter(function (f) { return dueIn(f) === 0; }).length;
    var digest = '<div class="ct-digest"><h3>☼ Campaign digest</h3><ul>' +
      '<li><span class="d" style="background:var(--crit)"></span><b>' + digKev + '</b> open finding(s) are CISA <b>KEV</b> (actively exploited)</li>' +
      '<li><span class="d" style="background:var(--high)"></span><b>' + digEpss + '</b> open with <b>EPSS ≥ 50%</b> · ' + digRw + ' tied to ransomware</li>' +
      '<li><span class="d" style="background:var(--med)"></span><b>' + overdue + '</b> past SLA · <b>' + digDueToday + '</b> due today</li>' +
      '<li><span class="d" style="background:var(--accent)"></span>' + (noAgent == null ? 'Load Agent Coverage to flag no-agent hosts' : '<b>' + noAgent + '</b> open on hosts with no Tenable agent') + '</li></ul></div>';
    var kpi2 = function (l, n, s, cls) { return '<div class="kpi ' + (cls || '') + '"><div class="label">' + l + '</div><div class="num">' + n + '</div><div class="sub">' + s + '</div></div>'; };
    var kpis = '<div class="kpis">' + kpi2('Progress', st.pct + '%', st.resolved + ' of ' + st.total + ' resolved', 'ok') + kpi2('Open', st.open, 'still to fix') + kpi2('Overdue', overdue, 'past SLA', overdue ? 'crit' : '') + kpi2('Critical open', critOpen, 'highest severity', critOpen ? 'crit' : '') + kpi2('KEV open', kevOpen, 'actively exploited', kevOpen ? 'crit' : '') + '</div>';
    // severity donut (open)
    var sc = { Critical: 0, High: 0, Medium: 0, Low: 0 }; open.forEach(function (f) { sc[f.severity] = (sc[f.severity] || 0) + 1; });
    var tot = open.length || 1, circ = 2 * Math.PI * 52, acc = 0;
    var arcs = ['Critical', 'High', 'Medium', 'Low'].map(function (s) { var len = sc[s] / tot * circ, seg = sc[s] ? '<circle r="52" cx="70" cy="70" fill="none" stroke="var(' + SEV_VAR[s] + ')" stroke-width="20" stroke-dasharray="' + len + ' ' + (circ - len) + '" stroke-dashoffset="' + (-acc) + '" transform="rotate(-90 70 70)"/>' : ''; acc += len; return seg; }).join('');
    var donut = '<div class="card"><h3 style="margin:0 0 10px;font-size:13px">Open by severity</h3><div style="display:flex;align-items:center;gap:16px"><svg viewBox="0 0 140 140" style="width:126px;height:126px"><circle r="52" cx="70" cy="70" fill="none" stroke="color-mix(in srgb,var(--line) 60%,transparent)" stroke-width="20"/>' + arcs + '<text x="70" y="66" text-anchor="middle" font-size="26" font-weight="700" fill="var(--ink)">' + open.length + '</text><text x="70" y="84" text-anchor="middle" font-size="10" fill="var(--soft)">open</text></svg><div style="display:flex;flex-direction:column;gap:6px;font-size:12px">' + ['Critical', 'High', 'Medium', 'Low'].map(function (s) { return '<span><span style="display:inline-block;width:9px;height:9px;border-radius:3px;background:var(' + SEV_VAR[s] + ');margin-right:6px"></span>' + s + ' <b>' + sc[s] + '</b></span>'; }).join('') + '</div></div></div>';
    // burndown from real campaign history + ideal target line
    var hist = (c.history || []).slice(-30), W = 380, H = 110;
    var bd;
    if (hist.length >= 2) {
      var openHist = hist.map(function (p) { return Math.round(st.total * (1 - (p.pct || 0) / 100)); });
      var mxB = Math.max.apply(null, openHist.concat([1]));
      var path = openHist.map(function (v, i) { return (i ? 'L' : 'M') + (i / (openHist.length - 1) * W).toFixed(1) + ' ' + (H - v / mxB * (H - 14)).toFixed(1); }).join(' ');
      bd = '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;height:120px" preserveAspectRatio="none"><path d="M0 14 L' + W + ' ' + H + '" stroke="var(--faint)" stroke-width="1.3" stroke-dasharray="4 4" fill="none"/><path d="' + path + ' L' + W + ' ' + H + ' L0 ' + H + ' Z" fill="color-mix(in srgb,var(--accent) 22%,transparent)"/><path d="' + path + '" fill="none" stroke="var(--accent)" stroke-width="2.2" stroke-linejoin="round"/></svg>';
    } else { bd = '<div class="muted" style="font-size:12px;padding:20px 0">Burndown appears after a day of progress history.</div>'; }
    var burn = '<div class="card"><h3 style="margin:0 0 8px;font-size:13px">Burndown vs target <span class="muted" style="font-weight:400;font-size:11.5px">open remaining · dashed = ideal pace</span></h3>' + bd + '</div>';
    var pipe = '<div class="card" style="margin-top:14px"><h3 style="margin:0 0 12px;font-size:13px">Pipeline <span class="muted" style="font-weight:400;font-size:11.5px">findings by status</span></h3>' + STATUS.map(function (s) { var n = list.filter(function (f) { return statusOf(f) === s.k; }).length; return '<div style="display:grid;grid-template-columns:110px 1fr 34px;gap:10px;align-items:center;font-size:12px;margin-bottom:8px"><span class="muted">' + s.l + '</span><span style="height:9px;border-radius:99px;background:color-mix(in srgb,var(--line) 60%,transparent);overflow:hidden;display:block"><span style="display:block;height:100%;width:' + (list.length ? n / list.length * 100 : 0) + '%;background:var(' + ST_VAR[s.k] + ')"></span></span><b style="text-align:right">' + n + '</b></div>'; }).join('') + '</div>';
    var note = filtered ? '<div class="muted ct-dnote">Showing <b>' + list.length + '</b> of ' + scoped.length + ' findings (search and filters applied). Progress and charts reflect the filtered set; the burndown history reflects the whole campaign.</div>' : '';
    return '<div class="ct-dash">' + note + digest + kpis + '<div class="ct-dgrid">' + burn + donut + '</div>' + pipe + '</div>';
  }

  function ctActivity() {
    var list = ctFindings(), ev = [];
    list.forEach(function (f) { (ovOf(f).updates || []).forEach(function (u) { ev.push({ at: u.at, text: u.text, f: f }); }); });
    ev.sort(function (a, b) { return a.at < b.at ? 1 : -1; });
    if (!ev.length) return '<div class="card"><span class="muted">' + (ctFilterActive() ? 'No activity matches the current search and filters.' : 'No activity yet. Status changes and notes on this campaign\'s findings appear here.') + '</span></div>';
    return '<div class="ct-feed">' + ev.slice(0, 200).map(function (e) {
      var d = new Date(e.at), ds = isNaN(d) ? e.at : d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      return '<div class="ct-fitem"><span class="ct-fdot"></span><div><div style="font-size:13px"><b class="mono">' + esc(e.f.cve) + '</b> <span class="muted">' + esc(e.f.host) + '</span> — ' + esc(e.text) + '</div><div class="muted" style="font-size:11.5px">' + esc(ds) + '</div></div></div>';
    }).join('') + '</div>';
  }

  function ctBulkBar() {
    var n = Object.keys(CT.sel).length, b = document.getElementById('ctBulk'); if (!b) return;
    if (!n) { b.setAttribute('hidden', ''); return; }
    b.removeAttribute('hidden');
    b.innerHTML = '<span class="bulkcount"><b>' + n + '</b> selected</span>' +
      '<select id="ctbStatus"><option value="">Set status…</option>' + STATUS.map(function (s) { return '<option value="' + s.k + '">' + s.l + '</option>'; }).join('') + '</select>' +
      '<select id="ctbOwner"><option value="">Assign…</option>' + owners().map(function (o) { return '<option>' + esc(o) + '</option>'; }).join('') + '<option value="__new">+ new owner…</option></select>' +
      '<button class="btn sm" id="ctbClear">Clear</button>';
    var keys = function () { return Object.keys(CT.sel); };
    var applyEach = function (patch, msg) { keys().forEach(function (k) { var f = ctScoped().filter(function (x) { return keyOf(x) === k; })[0]; if (f) { setOverride(f, patch); if (msg) addUpdate(f, msg); } }); };
    document.getElementById('ctbStatus').onchange = function (e) { if (!e.target.value) return; var nk = keys().length; applyEach({ status: e.target.value }, 'Bulk set to ' + SLABEL[e.target.value] + ' in campaign board'); toast(nk + ' → ' + SLABEL[e.target.value]); CT.sel = {}; refreshCampaign(); };
    document.getElementById('ctbOwner').onchange = function (e) { var v = e.target.value; if (!v) return; if (v === '__new') { v = (prompt('Assign to') || '').trim(); if (!v) return; } var nk = keys().length; applyEach({ owner: v }, 'Assigned to ' + v + ' in campaign board'); toast(nk + ' assigned to ' + v); CT.sel = {}; refreshCampaign(); };
    document.getElementById('ctbClear').onclick = function () { CT.sel = {}; refreshCampaign(); };
  }

  var CT_SAVED = [['', 'Views…'], ['risk', 'SLA risk (Table, worst first)'], ['patch', 'By patch (Board)'], ['overdue', 'Overdue criticals (List)'], ['coverage', 'No-agent blind spots (Table)']];
  function ctApplySaved(v) {
    if (v === 'coverage' && !ctCoverageKnown()) { toast('Load Agent Coverage first (open Agent Coverage)'); return; }
    CT.qf = {}; CT.q = ''; CT.tcol = {};
    if (v === 'risk') { CT.view = 'table'; CT.sort = { k: 'vpr', dir: -1 }; }
    else if (v === 'patch') { CT.view = 'board'; CT.group = 'patch'; }
    else if (v === 'overdue') { CT.view = 'list'; CT.group = 'severity'; CT.qf = { overdue: true, critical: true }; }
    else if (v === 'coverage') { CT.view = 'table'; CT.qf = { noagent: true }; }
    var c = ctCamp(); if (!c) return;
    if (CT.group === 'patch') { ensureMsrc(ctScoped().map(function (f) { return f.cve; })).then(function () { return REMED.data ? Promise.resolve() : ensureRemed(); }).then(function () { campaignTracker(c); }); }
    else campaignTracker(c);
  }

  // Load MSRC / remediation data lazily when patch-grouping is used, then re-render.
  function ctSyncGrouping(cb) {
    if (CT.group === 'patch') {
      var cves = ctScoped().map(function (f) { return f.cve; });
      Promise.all([ensureMsrc(cves), REMED.data ? Promise.resolve() : ensureRemed()]).then(function () { refreshCampaign(); if (cb) cb(); });
    } else { refreshCampaign(); if (cb) cb(); }
  }

  function campKpiCards(c, st) {
    return kpi('Progress', st.pct + '%', st.resolved + ' of ' + st.total + ' resolved') +
      kpi('Open', st.open, 'still to fix') +
      kpi('Overdue (SLA)', st.overdue, 'past due', st.overdue ? 'crit' : 'ok') +
      kpi('Due', c.dueDate || '—', campStatusLabel(c.status));
  }
  // Lightweight refresh after a status/owner write: re-render only the tracker body + the campaign KPI row,
  // instead of rebuilding the whole campaignDetail page on every drag/bulk. CT state persists across renders.
  function refreshCampaign() {
    if (!CT.cid) return; var c = ctCamp(); if (!c) return;
    var kp = document.getElementById('campKpis'); if (kp) kp.innerHTML = campKpiCards(c, campaignStats(c));
    ctRenderView(); ctBulkBar();
  }

  function ctRenderView() {
    var host = document.getElementById('ctBody'); if (!host) return;
    var listViews = { board: 1, list: 1, calendar: 1, timeline: 1, workload: 1 };   // Table keeps its own empty row so the filter header stays; Dashboard/Activity have their own empty copy
    if (listViews[CT.view] && !ctFindings().length) { host.innerHTML = ctEmptyState(); ctWireBody(); return; }
    host.innerHTML = ({ board: ctBoard, list: ctList, table: ctTable, calendar: ctCalendar, timeline: ctTimeline, workload: ctWorkload, dashboard: ctDashboard, activity: ctActivity }[CT.view] || ctBoard)();
    if (CT.view === 'table') { ctWireTable(); ctFillTable(); }
    ctWireBody();
  }
  function ctWireTable() {
    [].forEach.call(document.querySelectorAll('#ctTable th[data-sk]'), function (th) { th.onclick = function () { var k = th.dataset.sk; if (CT.sort.k === k) CT.sort.dir = -CT.sort.dir; else { CT.sort = { k: k, dir: (k === 'cve' || k === 'host' || k === 'owner' || k === 'status') ? 1 : -1 }; } document.getElementById('ctBody').innerHTML = ''; ctRenderView(); }; });
    [].forEach.call(document.querySelectorAll('#ctTable .grid-filterrow [data-tc]'), function (el) { var ev = el.tagName === 'SELECT' ? 'change' : 'input'; el.addEventListener(ev, function () { CT.tcol[el.dataset.tc] = el.value; var active = Object.keys(CT.tcol).some(function (k) { return CT.tcol[k] !== '' && CT.tcol[k] != null; }); var cap = document.querySelector('.ct-tcap'), cl = document.getElementById('ctClear'); if (active && !cl && cap) { var bb = document.createElement('button'); bb.className = 'btn sm'; bb.id = 'ctClear'; bb.textContent = 'Clear filters'; bb.onclick = function () { CT.tcol = {}; ctRenderView(); }; cap.appendChild(bb); } else if (!active && cl) { cl.remove(); } ctFillTable(); }); });
    var clr = document.getElementById('ctClear'); if (clr) clr.onclick = function () { CT.tcol = {}; ctRenderView(); };
  }
  function ctAnnounce(msg) { var el = document.getElementById('ctLive'); if (el) { el.textContent = ''; el.textContent = msg; } }
  function ctFocusCard(key) { var el = document.querySelector('#ctBody .ct-card[data-key="' + key + '"]'); if (el) el.focus(); return el; }
  function ctFocusSibling(card, dir) { var colb = card.closest('.ct-colb'); if (!colb) return; var cards = [].slice.call(colb.querySelectorAll('.ct-card')); var n = cards[cards.indexOf(card) + dir]; if (n) n.focus(); }
  function ctFocusAdjacentColumn(card, dir) {
    var col = card.closest('.ct-col'); if (!col) return;
    var cols = [].slice.call(document.querySelectorAll('#ctBoard .ct-col')); var ci = cols.indexOf(col);
    var vi = [].slice.call(col.querySelectorAll('.ct-card')).indexOf(card);
    for (var t = ci + dir; t >= 0 && t < cols.length; t += dir) {
      var tc = [].slice.call(cols[t].querySelectorAll('.ct-card'));
      if (tc.length) { (tc[Math.min(vi, tc.length - 1)] || tc[0]).focus(); return; }
    }
  }
  // Keyboard equivalent of dragging: move a grabbed card one column left/right (reassign status or owner).
  function ctMoveCardKb(f, dir) {
    var cols = [].slice.call(document.querySelectorAll('#ctBoard .ct-col'));
    var cur = ctFieldVal(f), idx = -1;
    for (var i = 0; i < cols.length; i++) { if (cols[i].dataset.k === cur) { idx = i; break; } }
    var target = idx + dir;
    if (idx < 0 || target < 0 || target >= cols.length) { ctAnnounce('Already in the ' + (dir < 0 ? 'first' : 'last') + ' column.'); return; }
    var tk = cols[target].dataset.k;
    if (CT.group === 'status') { setOverride(f, { status: tk }); addUpdate(f, 'Moved to ' + SLABEL[tk] + ' on the campaign board (keyboard)'); }
    else { var nw = tk === 'Unassigned' ? '' : tk; setOverride(f, { owner: nw }); addUpdate(f, nw ? 'Assigned to ' + nw + ' on the campaign board (keyboard)' : 'Unassigned on the campaign board (keyboard)'); }
    refreshCampaign();                                  // CT.grab is preserved, so the card stays picked up after the re-render
    ctFocusCard(keyOf(f));
    ctAnnounce('Moved ' + f.cve + ' to ' + (CT.group === 'owner' ? tk : SLABEL[tk]) + '. Still holding, use arrow keys to keep moving or space to drop.');
  }
  function ctReleaseGrab(card, msg) { CT.grab = null; if (card) { card.classList.remove('grabbed'); card.setAttribute('aria-grabbed', 'false'); } if (msg) ctAnnounce(msg); }
  function ctBoardKey(e, card, draggable) {
    var key = card.dataset.key, k = e.key, grabbed = CT.grab === key;
    var f = ctScoped().filter(function (x) { return keyOf(x) === key; })[0]; if (!f) return;
    if (k === 'Enter' || k === 'o' || k === 'O') { e.preventDefault(); if (grabbed) ctReleaseGrab(card, 'Dropped.'); else openDrawer(f); return; }
    if (k === ' ' || k === 'Spacebar') {
      e.preventDefault();
      if (!draggable) { openDrawer(f); return; }
      if (grabbed) ctReleaseGrab(card, 'Dropped ' + f.cve + '.');
      else { CT.grab = key; card.classList.add('grabbed'); card.setAttribute('aria-grabbed', 'true'); ctAnnounce('Picked up ' + f.cve + '. Use left and right arrow keys to change ' + (CT.group === 'owner' ? 'assignee' : 'status') + ', space to drop, escape to cancel.'); }
      return;
    }
    if (k === 'Escape') { if (grabbed) { e.preventDefault(); ctReleaseGrab(card, 'Cancelled.'); } return; }
    if (k === 'x' || k === 'X') {
      e.preventDefault();
      if (CT.sel[key]) delete CT.sel[key]; else CT.sel[key] = 1;
      card.classList.toggle('sel', !!CT.sel[key]);
      var cb = card.querySelector('.ct-cbox'); if (cb) { cb.classList.toggle('on', !!CT.sel[key]); cb.innerHTML = CT.sel[key] ? '✓' : ''; cb.setAttribute('aria-checked', CT.sel[key] ? 'true' : 'false'); }
      ctBulkBar(); ctAnnounce(CT.sel[key] ? 'Selected.' : 'Deselected.'); return;
    }
    if (k === 'ArrowLeft' || k === 'ArrowRight') { e.preventDefault(); var dir = k === 'ArrowRight' ? 1 : -1; if (grabbed && draggable) ctMoveCardKb(f, dir); else ctFocusAdjacentColumn(card, dir); return; }
    if (k === 'ArrowUp' || k === 'ArrowDown') { e.preventDefault(); if (grabbed) return; ctFocusSibling(card, k === 'ArrowDown' ? 1 : -1); return; }
  }
  function ctWireBody() {
    // open drawer on card / row / list-row / cal-ev / timeline-row click
    [].forEach.call(document.querySelectorAll('#ctBody [data-key]'), function (el) {
      if (el.classList.contains('ct-cbox') || el.classList.contains('ct-brow')) return;   // table rows are bound in ctFillTable; skip here so the drawer does not open twice
      el.addEventListener('click', function (e) {
        if (e.target.closest('a') || e.target.closest('.ct-cbox')) return;
        var f = ctScoped().filter(function (x) { return keyOf(x) === el.dataset.key; })[0]; if (f) openDrawer(f);
      });
    });
    var ec = document.getElementById('ctEmptyClear'); if (ec) ec.onclick = function () { CT.q = ''; CT.qf = {}; CT.tcol = {}; var c = ctCamp(); if (c) campaignTracker(c); };
    // selection checkboxes
    [].forEach.call(document.querySelectorAll('#ctBody .ct-cbox'), function (cb) { cb.addEventListener('click', function (e) { e.stopPropagation(); var k = cb.dataset.selk; if (CT.sel[k]) delete CT.sel[k]; else CT.sel[k] = 1; cb.classList.toggle('on'); cb.innerHTML = CT.sel[k] ? '✓' : ''; cb.closest('.ct-card').classList.toggle('sel'); ctBulkBar(); }); });
    // list group collapse
    [].forEach.call(document.querySelectorAll('#ctBody .ct-lgh'), function (h) { h.addEventListener('click', function () { var g = h.parentNode.dataset.g; CT.closed[g] = !CT.closed[g]; h.parentNode.classList.toggle('closed'); }); });
    // board drag-and-drop (only Status / Assignee groupings write back)
    var dragKey = null, draggable = (CT.group === 'status' || CT.group === 'owner');
    [].forEach.call(document.querySelectorAll('#ctBody .ct-card'), function (card) {
      card.addEventListener('dragstart', function (e) { dragKey = card.dataset.key; card.classList.add('drag'); e.dataTransfer.effectAllowed = 'move'; });
      card.addEventListener('dragend', function () { card.classList.remove('drag'); });
      card.addEventListener('keydown', function (e) { ctBoardKey(e, card, draggable); });   // keyboard drag-and-drop equivalent
    });
    [].forEach.call(document.querySelectorAll('#ctBody .ct-col'), function (col) {
      col.addEventListener('dragover', function (e) { if (!draggable) return; e.preventDefault(); col.classList.add('drop'); });
      col.addEventListener('dragleave', function () { col.classList.remove('drop'); });
      col.addEventListener('drop', function (e) { e.preventDefault(); col.classList.remove('drop'); if (!draggable) return; var f = ctScoped().filter(function (x) { return keyOf(x) === dragKey; })[0]; if (!f) return; if (ctFieldVal(f) === col.dataset.k) return; if (CT.group === 'status') { setOverride(f, { status: col.dataset.k }); addUpdate(f, 'Moved to ' + SLABEL[col.dataset.k] + ' on the campaign board'); } else { var nw = col.dataset.k === 'Unassigned' ? '' : col.dataset.k; setOverride(f, { owner: nw }); addUpdate(f, nw ? 'Assigned to ' + nw + ' on the campaign board' : 'Unassigned on the campaign board'); } refreshCampaign(); });
    });
  }

  // Public entry: render the tracker for a campaign into #ctMount (called from campaignDetail).
  function campaignTracker(c) {
    if (CT.cid !== c.id) { CT.sel = {}; CT.q = ''; CT.qf = {}; CT.tcol = {}; CT.closed = {}; }   // don't leak state between campaigns
    CT.cid = c.id; CT.grab = null;   // any fresh render (campaign/view/group/filter change) releases a picked-up card; in-progress moves go through refreshCampaign, which keeps it
    var mount = document.getElementById('ctMount'); if (!mount) return;
    var tabs = '<div class="ct-tabs">' + CT_VIEWS.map(function (v) { return '<button class="ct-tab' + (v[0] === CT.view ? ' on' : '') + '" data-v="' + v[0] + '">' + v[1] + '</button>'; }).join('') + '</div>';
    var groupSel = (CT.view === 'board' || CT.view === 'list') ? '<label class="ct-ctl">Group <select id="ctGroup">' + CT_GROUPS.map(function (g) { return '<option value="' + g[0] + '"' + (CT.group === g[0] ? ' selected' : '') + '>' + g[1] + '</option>'; }).join('') + '</select></label>' : '';
    var chips = ['kev:KEV / exploited', 'overdue:Overdue', 'critical:Critical', 'recurring:Recurring', 'noagent:No agent'].map(function (q) { var p = q.split(':'); return '<button class="ct-qf' + (CT.qf[p[0]] ? ' on' : '') + '" data-q="' + p[0] + '"' + (p[0] === 'noagent' && !ctCoverageKnown() ? ' disabled title="Load Agent Coverage first"' : '') + '>' + p[1] + '</button>'; }).join('');
    var toolbar = '<div class="ct-toolbar">' + groupSel + '<div class="ct-qfs">' + chips + '</div><input class="ct-search" id="ctSearch" type="text" placeholder="Search CVE, host, owner…" value="' + esc(CT.q) + '">' +
      '<span style="flex:1"></span><select id="ctSaved" class="ct-ctl">' + CT_SAVED.map(function (s) { return '<option value="' + s[0] + '">' + s[1] + '</option>'; }).join('') + '</select><button class="btn sm" id="ctAuto">⚙ Automations</button></div>';
    mount.innerHTML = tabs + toolbar + '<div class="bulkbar" id="ctBulk" hidden></div><div class="ct-body" id="ctBody"></div>' +
      '<div id="ctKbdHelp" class="ct-sr">Draggable card. Press Space to pick it up, then use the Left and Right arrow keys to move it between columns. Press Space or Enter to drop, Escape to cancel. Press Enter to open the finding, or x to select it.</div>' +
      '<div id="ctLive" class="ct-sr" aria-live="polite" aria-atomic="true"></div>';
    [].forEach.call(mount.querySelectorAll('.ct-tab'), function (b) { b.onclick = function () { CT.view = b.dataset.v; campaignTracker(c); }; });
    var g = document.getElementById('ctGroup'); if (g) g.onchange = function () { CT.group = g.value; ctSyncGrouping(); };
    [].forEach.call(mount.querySelectorAll('.ct-qf'), function (b) { b.onclick = function () { if (b.disabled) return; CT.qf[b.dataset.q] = !CT.qf[b.dataset.q]; campaignTracker(c); }; });
    document.getElementById('ctSearch').oninput = function (e) { CT.q = e.target.value; if (CT.view === 'table') ctFillTable(); else ctRenderView(); };
    document.getElementById('ctSaved').onchange = function (e) { if (e.target.value) ctApplySaved(e.target.value); };
    document.getElementById('ctAuto').onclick = ctAutomations;
    ctRenderView(); ctBulkBar();
    // If the board opens grouped by patch, load this campaign's MSRC KB map, else cards collapse into "Manual remediation" until the group is re-picked.
    if (CT.group === 'patch') ensureMsrc(ctScoped().map(function (f) { return f.cve; })).then(function () { if (CT.cid === c.id) ctRenderView(); });
    if (!INTEL.loaded) ensureIntel().then(function () { if (CT.cid === c.id && (location.hash || '').indexOf('#/campaigns/') === 0) { if (CT.view === 'table') ctFillTable(); else ctRenderView(); } });
  }
  function ctAutomations() {
    var ov = document.getElementById('ctModal') || (function () { var d = document.createElement('div'); d.id = 'ctModal'; d.className = 'ct-modal vmops'; document.body.appendChild(d); return d; })();
    ov.innerHTML = '<div class="ct-mcard"><button class="x" id="ctMx">×</button><h3 style="margin:0 0 3px">Automations</h3><div class="muted" style="font-size:12.5px;margin-bottom:12px">What runs today vs. what\'s planned.</div>' +
      [['Rescan reconcile', 'Re-importing a scan auto-resolves any open finding that no longer appears (with a dated update).', true],
       ['Tenable State=Fixed → Resolved', 'When the export has a "State" column, a still-listed row marked Fixed auto-resolves, not just vanished rows.', true],
       ['Reopen on recurrence', 'A resolved finding that shows up again (still active) reopens, and its reopen count is tracked so recurring / flapping findings stand out.', true],
       ['KEV → priority', 'KEV / ransomware / exploited findings are surfaced as P1 by the risk model everywhere.', true],
       ['EPSS ≥ 90% → escalate to lead', 'Auto-notify the campaign owner when EPSS crosses the threshold.', false],
       ['No-agent → block auto-close', 'Prevent auto-resolving a finding whose host has no scanner agent.', false]].map(function (r) {
        return '<div class="ct-rule"><span class="ct-sw ' + (r[2] ? 'on' : '') + '"></span><div><div style="font-weight:600;font-size:13px">' + r[0] + ' <span class="muted" style="font-weight:400;font-size:11px">' + (r[2] ? 'active' : 'planned') + '</span></div><div class="muted" style="font-size:12px">' + r[1] + '</div></div></div>';
      }).join('') + '<div style="text-align:right;margin-top:14px"><button class="btn primary sm" id="ctMdone">Done</button></div></div>';
    ov.classList.add('on');
    var close = function () { ov.classList.remove('on'); };
    document.getElementById('ctMx').onclick = document.getElementById('ctMdone').onclick = close;
    ov.onclick = function (e) { if (e.target === ov) close(); };
  }

  // ========================= Asset Inventory =========================
  // Distinct hosts across all findings, each with an editable business-criticality tier that
  // feeds the risk score (asset component). This is the denominator the commercial tools call
  // "asset context" — here it stays local and user-owned.
  function assetRows() {
    var m = {};
    STATE.findings.forEach(function (f) {
      var h = norm(f.host); if (!m[h]) m[h] = { host: f.host, key: h, all: 0, open: 0, sev: 'Low', risk: 0, src: {} };
      var a = m[h]; a.all++; if (isOpen(f)) { a.open++; a.risk += riskScore(f); }
      if ((SEV_ORDER[f.severity] != null ? SEV_ORDER[f.severity] : 4) < (SEV_ORDER[a.sev] != null ? SEV_ORDER[a.sev] : 4)) a.sev = f.severity;
      if (f.source) a.src[f.source] = 1;
    });
    return Object.keys(m).map(function (k) { return m[k]; });
  }
  function critSelect(host) {
    var cur = assetCrit(host);
    return '<select class="asset-crit" data-host="' + esc(norm(host)) + '"><option value=""' + (cur === '' ? ' selected' : '') + '>—</option>' +
      ASSET_CRITS.map(function (c) { return '<option value="' + c.k + '"' + (cur === c.k ? ' selected' : '') + '>' + c.l + '</option>'; }).join('') + '</select>';
  }
  function viewAssets() {
    setActive('assets');
    if (!STATE.findings.length) return viewEmpty('assets');
    preloadLev();
    var rows = assetRows().sort(function (a, b) { return b.risk - a.risk; });
    var assigned = rows.filter(function (r) { return assetCrit(r.host); }).length;
    var critBiz = rows.filter(function (r) { return assetCrit(r.host) === 'critical'; }).length;
    var kpi = function (n, l) { return '<div class="kpi"><div class="num">' + n + '</div><div class="label">' + l + '</div></div>'; };
    app.innerHTML =
      '<header class="view"><div class="overline">Inventory</div><h1>Asset inventory</h1>' +
      '<p class="lede">Every host seen across your findings, with a business-criticality tier you assign. Criticality feeds the risk score, so a critical asset raises the priority of the same vulnerability. Stored in this browser only.</p></header>' +
      privSlim() +
      '<div class="kpis">' + kpi(rows.length, 'Assets') + kpi(assigned, 'Criticality set') + kpi(rows.length - assigned, 'Unrated') + kpi(critBiz, 'Business-critical') + '</div>' +
      '<div class="gridwrap"><table class="grid"><thead><tr><th>Host</th><th>Sources</th><th>Open</th><th>Max sev</th><th>Risk</th><th>Criticality</th><th>Owner</th><th>Tags</th></tr></thead><tbody>' +
      rows.map(function (r) {
        return '<tr><td class="mono">' + esc(r.host) + '</td>' +
          '<td class="muted" style="font-size:12px">' + esc(Object.keys(r.src).join(', ')) + '</td>' +
          '<td>' + r.open + '</td><td>' + sevBadge(r.sev) + '</td><td>' + Math.round(r.risk) + '</td>' +
          '<td>' + critSelect(r.host) + '</td>' +
          '<td><input class="asset-owner" data-host="' + esc(r.key) + '" value="' + esc((assetOf(r.host) || {}).owner || '') + '" placeholder="—" style="width:120px"></td>' +
          '<td><input class="asset-tags" data-host="' + esc(r.key) + '" value="' + esc(((assetOf(r.host) || {}).tags || []).join(', ')) + '" placeholder="e.g. pci, internet-facing" style="width:180px"></td></tr>';
      }).join('') +
      '</tbody></table></div>' +
      '<div class="muted" style="font-size:12px;margin-top:10px">Criticality tiers: Critical, High, Medium, Low. Unrated assets are treated as Medium in scoring. Adjust the weight of asset context under <a href="#/settings">Settings → Risk weighting</a>.</div>';
    [].forEach.call(document.querySelectorAll('.asset-crit'), function (s) { s.addEventListener('change', function () { setAsset(s.getAttribute('data-host'), { crit: s.value }); viewAssets(); toast('Asset criticality updated'); }); });
    [].forEach.call(document.querySelectorAll('.asset-owner'), function (i) { i.addEventListener('change', function () { setAsset(i.getAttribute('data-host'), { owner: i.value.trim() }); toast('Saved'); }); });
    [].forEach.call(document.querySelectorAll('.asset-tags'), function (i) { i.addEventListener('change', function () { setAsset(i.getAttribute('data-host'), { tags: i.value.split(',').map(function (x) { return x.trim(); }).filter(Boolean) }); toast('Saved'); }); });
  }

  // ========================= Remediations (root-cause grouping) =========================
  // Group open findings by the fix that resolves them (product/package), so one action shows
  // how many findings across how many assets it clears — the "one patch, N findings" rollup.
  function remediationGroups() {
    var m = {};
    STATE.findings.filter(isOpen).forEach(function (f) {
      var k = fixKey(f); if (!m[k]) m[k] = { key: k, label: fixLabel(f), n: 0, hosts: {}, cves: {}, src: {}, sev: 'Low', risk: 0 };
      var g = m[k]; g.n++; g.hosts[norm(f.host)] = 1; g.cves[f.cve] = 1; if (f.source) g.src[f.source] = 1; g.risk += riskScore(f);
      if ((SEV_ORDER[f.severity] != null ? SEV_ORDER[f.severity] : 4) < (SEV_ORDER[g.sev] != null ? SEV_ORDER[g.sev] : 4)) g.sev = f.severity;
    });
    return Object.keys(m).map(function (k) { var g = m[k]; return { label: g.label, n: g.n, assets: Object.keys(g.hosts).length, cves: Object.keys(g.cves), src: Object.keys(g.src), sev: g.sev, risk: Math.round(g.risk) }; });
  }
  function viewRemediations() {
    setActive('remediations');
    if (!STATE.findings.length) return viewEmpty('remediations');
    preloadLev();
    var groups = remediationGroups().sort(function (a, b) { return b.risk - a.risk; });
    var kpi = function (n, l) { return '<div class="kpi"><div class="num">' + n + '</div><div class="label">' + l + '</div></div>'; };
    var top = groups[0];
    app.innerHTML =
      '<header class="view"><div class="overline">Remediations</div><h1>Fix-first remediations</h1>' +
      '<p class="lede">Open findings grouped by the fix that clears them, so you can see the single action that removes the most risk across the most assets. One patch often resolves many findings.</p></header>' +
      privSlim() +
      '<div class="kpis">' + kpi(groups.length, 'Distinct fixes') + kpi(STATE.findings.filter(isOpen).length, 'Open findings') + kpi(top ? top.n : 0, 'Top fix clears') + kpi(top ? top.assets : 0, 'across assets') + '</div>' +
      '<div class="gridwrap"><table class="grid"><thead><tr><th>Fix</th><th>Max sev</th><th>Findings</th><th>Assets</th><th>CVEs</th><th>Risk removed</th></tr></thead><tbody>' +
      groups.map(function (g) {
        return '<tr><td><b>Update ' + esc(g.label) + '</b>' + (g.src.length ? '<div class="muted" style="font-size:11px">' + esc(g.src.join(', ')) + '</div>' : '') + '</td>' +
          '<td>' + sevBadge(g.sev) + '</td><td><b>' + g.n + '</b></td><td>' + g.assets + '</td>' +
          '<td class="mono" style="font-size:11.5px">' + g.cves.slice(0, 4).map(esc).join(', ') + (g.cves.length > 4 ? ' +' + (g.cves.length - 4) : '') + '</td>' +
          '<td class="risknum">' + g.risk.toLocaleString() + '</td></tr>';
      }).join('') +
      '</tbody></table></div>' +
      '<div class="muted" style="font-size:12px;margin-top:10px">Findings are grouped by the product a fix targets (derived from the finding name). Risk removed is the summed risk score of the findings that fix would close.</div>';
  }

  // ========================= Licenses & SBOM =========================
  // Component inventory from an imported CycloneDX BOM, with a license-risk summary.
  var LIC_CLASS = { permissive: { l: 'Permissive', c: 'ok' }, copyleft: { l: 'Copyleft', c: 'high' }, other: { l: 'Other', c: 'med' }, unknown: { l: 'Unknown', c: 'crit' } };
  function viewSbom() {
    setActive('sbom');
    var sb = STATE.sbom;
    if (!sb || !sb.components || !sb.components.length) {
      app.innerHTML = '<header class="view"><div class="overline">Inventory</div><h1>Licenses &amp; SBOM</h1>' +
        '<p class="lede">Import a CycloneDX software bill of materials to inventory your components and their licenses, and flag copyleft or unknown-license dependencies. Vulnerabilities in the BOM also flow into the Findings workbench.</p></header>' +
        privSlim() + '<div class="card" style="text-align:center;padding:40px 24px"><div style="font-family:var(--serif);font-size:20px;margin-bottom:8px">No SBOM imported yet</div>' +
        '<div class="muted" style="max-width:520px;margin:0 auto 18px;font-size:14px;line-height:1.6">On the Data Import page, choose a CycloneDX JSON file (for example from Syft, Trivy, or cdxgen). It is parsed in your browser and never uploaded.</div>' +
        '<a class="btn primary" href="#/import">Open Data Import →</a></div>';
      return;
    }
    var comps = sb.components.slice();
    var byClass = { permissive: 0, copyleft: 0, other: 0, unknown: 0 };
    var byLic = {};
    comps.forEach(function (c) { var cl = licenseClass(c.license); byClass[cl]++; var key = c.license || '(none)'; byLic[key] = (byLic[key] || 0) + 1; });
    var withVulns = comps.filter(function (c) { return c.vulns > 0; }).length;
    var kpi = function (n, l, cls) { return '<div class="kpi ' + (cls || '') + '"><div class="num">' + n + '</div><div class="label">' + l + '</div></div>'; };
    var licKeys = Object.keys(byLic).sort(function (a, b) { return byLic[b] - byLic[a]; });
    var licMax = Math.max.apply(null, licKeys.map(function (k) { return byLic[k]; }).concat([1]));
    var licBars = licKeys.slice(0, 12).map(function (k) {
      var cl = licenseClass(k === '(none)' ? '' : k);
      return '<div class="sbom-bar"><span class="sbom-bl">' + esc(k) + ' <span class="badge ' + LIC_CLASS[cl].c + '" style="font-size:9px">' + LIC_CLASS[cl].l + '</span></span>' +
        '<span class="sbom-track"><span class="sbom-fill" style="width:' + Math.round(byLic[k] / licMax * 100) + '%;background:var(--' + LIC_CLASS[cl].c + ')"></span></span><span class="sbom-n">' + byLic[k] + '</span></div>';
    }).join('');
    comps.sort(function (a, b) { return b.vulns - a.vulns || a.name.localeCompare(b.name); });
    app.innerHTML =
      '<header class="view"><div class="overline">Inventory</div><h1>Licenses &amp; SBOM</h1>' +
      '<p class="lede">Components from <b>' + esc(sb.name || 'the imported BOM') + '</b>' + (sb.at ? ' (' + esc(new Date(sb.at).toLocaleString()) + ')' : '') + '. Copyleft and unknown licenses are flagged for review; vulnerable components link to the Findings workbench.</p></header>' +
      privSlim() +
      '<div class="kpis">' + kpi(comps.length, 'Components') + kpi(licKeys.filter(function (k) { return k !== '(none)'; }).length, 'Distinct licenses') + kpi(byClass.copyleft, 'Copyleft', byClass.copyleft ? 'warn' : '') + kpi(byClass.unknown, 'Unknown license', byClass.unknown ? 'crit' : '') + kpi(withVulns, 'With vulnerabilities', withVulns ? 'crit' : '') + '</div>' +
      '<div class="card"><h3 style="margin:0 0 10px;font-size:13px">Components by license</h3>' + licBars + '</div>' +
      '<div class="gridwrap"><table class="grid"><thead><tr><th>Component</th><th>Version</th><th>Type</th><th>License</th><th>Class</th><th>Vulns</th></tr></thead><tbody>' +
      comps.map(function (c) { var cl = licenseClass(c.license); return '<tr><td class="mono">' + esc(c.name) + '</td><td class="mono">' + esc(c.version || '—') + '</td><td class="muted" style="font-size:12px">' + esc(c.type) + '</td><td>' + esc(c.license || '—') + '</td><td><span class="badge ' + LIC_CLASS[cl].c + '">' + LIC_CLASS[cl].l + '</span></td><td>' + (c.vulns ? '<b>' + c.vulns + '</b>' : '—') + '</td></tr>'; }).join('') +
      '</tbody></table></div>';
  }

  function vmShow(fn){ return function(){ app.className='vmops'; return fn.apply(null, arguments); }; }
  function goDash() { if ((location.hash||'').indexOf('#/dashboard')===0){ app.className='vmops'; viewDashboard(); } else { location.hash='#/dashboard'; } }
  // Exposed to the host (CVE-Explorer-based) router, which dispatches the ops routes.
  // Read-only snapshot of the current findings (used by the cross-vendor Scanner
  // Coverage view to include the Tenable baseline).
  function getFindings() { return STATE.findings.slice(); }
  // Opt-in loader: merge externally-normalized scanner findings (Qualys/Rapid7/
  // CrowdStrike/Wiz sample) into the shared store so the workbench, Overview, and
  // Campaigns reflect all sources. Returns the new total.
  function loadScannerFindings(list) { if (!list || !list.length) return STATE.findings.length; mergeFindings(list); return STATE.findings.length; }
  window.VMOPS = { dashboard: vmShow(viewDashboard), findings: vmShow(viewFindings), campaigns: vmShow(viewCampaigns), import: vmShow(viewImport), settings: vmShow(viewSettings), wiz: vmShow(viewWiz), assets: vmShow(viewAssets), remediations: vmShow(viewRemediations), sbom: vmShow(viewSbom),
    getFindings: getFindings, loadScannerFindings: loadScannerFindings,
    remediation: { ensure: ensureRemed, for: remediationFor, copy: copyText } };
})();
