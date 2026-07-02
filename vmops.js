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
  var OPEN_STATES = STATUS.filter(function (s) { return s.open; }).map(function (s) { return s.k; });
  var SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  var DEFAULT_CFG = { brand: '', brandIcon: '', brandIconColor: '', sla: { Critical: 7, High: 30, Medium: 90, Low: 180 }, jiraBase: '', jiraPid: '', jiraType: '', snowBase: '', tsUrl: '', tsAccess: '', tsSecret: '', tioAccess: '', tioSecret: '', meUrl: '', meClientId: '', meClientSecret: '' };
  var DEFAULT_BRAND = 'VM Ops Console';
  var DEFAULT_ICON_COLOR = '#28415d';

  function load(k, d) { try { var v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch (e) { return d; } }
  function save(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }

  var STATE = {
    findings: load('vmops-findings', []),
    ov: load('vmops-overrides', {}),       // key -> {status, owner, notes, updated}
    cfg: Object.assign({}, DEFAULT_CFG, load('vmops-config', {})),
    sort: { col: 'risk', dir: 1 },
    filt: { q: '', status: '', sev: '', owner: '', repo: '', overdue: false, seen: '', exploited: false, fresh: false, epssHi: false, noTicket: false, group: '' }
  };
  STATE.cfg.sla = Object.assign({}, DEFAULT_CFG.sla, STATE.cfg.sla || {});
  STATE._newKeys = {}; try { (JSON.parse(localStorage.getItem('vmops-newkeys') || '[]') || []).forEach(function (k) { STATE._newKeys[k] = 1; }); } catch (e) {}
  STATE._colW = {}; try { STATE._colW = JSON.parse(localStorage.getItem('vmops-colw') || '{}') || {}; } catch (e) {}

  // Custom branding: apply the configured app name to the nav brand + document title, and rebuild the
  // favicon (monogram + color) — all default to the VM Ops Console look when unset.
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
  function applyBrand() {
    var name = (STATE.cfg.brand || '').trim() || DEFAULT_BRAND;
    window.VM_BRAND = name;   // read by the CVE-shell views (About, footer, diagram, ledes)
    var el = document.querySelector('nav.top .brand'); if (el) el.textContent = name;
    [].forEach.call(document.querySelectorAll('.brandname'), function (s) { s.textContent = name; });
    try { document.title = name; } catch (e) {}
    var mono = ((STATE.cfg.brandIcon || '').trim() || brandInitials(name)).slice(0, 3);
    var col = (STATE.cfg.brandIconColor || '').trim() || DEFAULT_ICON_COLOR;
    var link = document.getElementById('favicon');
    if (link) { var nw = link.cloneNode(false); nw.setAttribute('href', faviconURI(mono, col)); link.parentNode.replaceChild(nw, link); }
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
  function riskScore(f) { // severity + real exploitation (KEV/ransomware/PoC) + SLA pressure + age
    var s = (4 - (SEV_ORDER[f.severity] != null ? SEV_ORDER[f.severity] : 4)) * 100;
    var it = cveIntel(f.cve);
    if (it.kev) s += 600; if (it.ransomware) s += 250; if (it.exploit) s += 200;
    if (it.epss != null) s += Math.round(it.epss * 300);   // EPSS probability folds in (0 → +300)
    if (f.vpr != null) s += Math.round(f.vpr * 20);         // Tenable VPR folds in (0 → +200)
    var di = dueIn(f); if (di != null && isOpen(f)) s += di < 0 ? 60 + Math.min(40, -di) : Math.max(0, 30 - di);
    s += Math.min(20, (daysSince(f.firstSeen) || 0) / 10);
    if (!isOpen(f)) s -= 2000;   // resolved/accepted always rank below anything open
    return s;
  }
  // ---------- the other prioritization models, per CVE (for the drawer): EPSS, NIST LEV, SSVC ----------
  // Same sources the CVE detail page uses: EPSS live from FIRST, LEV from the local data/lev/<year>.json,
  // SSVC the simplified Act/Attend/Track derived from exploitation + impact (CISA's authoritative SSVC is on the detail page).
  function pct(x) { return Math.round((x || 0) * 100) + '%'; }
  function isHigh(cvss) { return cvss != null && !isNaN(cvss) && cvss >= 7; }
  function epssVerdict(e) { if (e == null) return { v: 'No data', why: '' }; if (e >= 0.5) return { v: 'High', why: pct(e) + ' chance in 30 days' }; if (e >= 0.1) return { v: 'Elevated', why: pct(e) + ' chance in 30 days' }; return { v: 'Low', why: pct(e) + ' chance in 30 days' }; }
  function levVerdict(l) { if (l == null) return { v: 'No data', why: '' }; if (l >= 0.5) return { v: 'Likely exploited', why: pct(l) + ' lower-bound it was already exploited' }; if (l >= 0.1) return { v: 'Possibly', why: pct(l) + ' lower-bound' }; return { v: 'Unlikely', why: pct(l) + ' lower-bound' }; }
  function ssvcVerdict(kev, exploit, cvss) { var a = kev || exploit, t = isHigh(cvss); if (a && t) return { v: 'Act', why: 'active exploitation · high impact' }; if (a) return { v: 'Attend', why: 'active exploitation' }; if (t) return { v: 'Attend', why: 'high impact' }; return { v: 'Track', why: 'no active exploitation · limited impact' }; }
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
      if (f.status && statusOf(x) !== f.status) return false;
      if (f.sev && x.severity !== f.sev) return false;
      if (f.owner && (ovOf(x).owner || '') !== f.owner) return false;
      if (f.repo && repoOf(x) !== f.repo) return false;
      if (f.overdue && slaState(x) !== 'overdue') return false;
      if (f.exploited) { var it = cveIntel(x.cve); if (!it.kev && !it.exploit) return false; }
      if (f.epssHi) { var ee = cveIntel(x.cve).epss; if (ee == null || ee < 0.5) return false; }
      if (f.noTicket) { if (ticketOf(x)) return false; if (!isOpen(x)) return false; }
      if (f.fresh && !isNewKey(keyOf(x))) return false;
      if (f.seen) { var _ds = daysSince(x.firstSeen); if (_ds == null || _ds > +f.seen) return false; }
      if (f.q) { var q = f.q.toLowerCase(); if ((x.cve + ' ' + x.host + ' ' + (x.name || '') + ' ' + (x.desc || '') + ' ' + repoOf(x) + ' ' + (ovOf(x).owner || '')).toLowerCase().indexOf(q) === -1) return false; }
      if (f.colf) { for (var _cid in f.colf) { if (f.colf[_cid] && String(colfVal(_cid, x)).toLowerCase().indexOf(f.colf[_cid].toLowerCase()) < 0) return false; } }
      return true;
    });
    var c = STATE.sort.col, d = STATE.sort.dir;
    list.sort(function (a, b) {
      var va, vb;
      if (c === 'risk') { va = riskScore(b); vb = riskScore(a); }              // default high->low
      else if (c === 'sev') { va = SEV_ORDER[a.severity]; vb = SEV_ORDER[b.severity]; }
      else if (c === 'due') { va = dueIn(a); vb = dueIn(b); va = va == null ? 1e9 : va; vb = vb == null ? 1e9 : vb; }
      else if (c === 'status') { va = SLABEL[statusOf(a)]; vb = SLABEL[statusOf(b)]; }
      else if (c === 'age') { va = daysSince(a.firstSeen) || 0; vb = daysSince(b.firstSeen) || 0; }
      else if (c === 'epss') { va = cveIntel(b.cve).epss || 0; vb = cveIntel(a.cve).epss || 0; }   // high → low by default
      else if (c === 'vpr') { va = b.vpr || 0; vb = a.vpr || 0; }                                   // high → low by default
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
    return { total: STATE.findings.length, open: open.length, overdue: overdue.length, comp: comp, crit: crit.length, assets: assetCount(), unassigned: open.filter(function (f) { return !ovOf(f).owner; }).length, noTicket: open.filter(function (f) { return !ticketOf(f); }).length };
  }
  function assetCount() { var s = {}; STATE.findings.forEach(function (f) { s[norm(f.host)] = 1; }); return Object.keys(s).length; }

  // ---------- views ----------
  // Mirror the shell's global setActive: reconcile top tabs AND dropdown items + .menu-active,
  // so an intra-VMOPS re-render can't leave a stale CVE-Intelligence/Tools menu highlight.
  function setActive(r) {
    [].forEach.call(document.querySelectorAll('nav.top a.tab, nav.top .navmenu-list a'), function (a) { a.classList.toggle('active', a.getAttribute('data-route') === r); });
    [].forEach.call(document.querySelectorAll('nav.top .navmenu'), function (m) { m.classList.toggle('menu-active', !!m.querySelector('.navmenu-list a.active')); });
  }

  function viewDashboard() {
    setActive('dashboard');
    if (!STATE.findings.length) return viewEmpty('dashboard');
    var k = kpis();
    var bySev = ['Critical', 'High', 'Medium', 'Low'].map(function (s) { return { s: s, n: STATE.findings.filter(function (f) { return f.severity === s && isOpen(f); }).length }; });
    var byStatus = STATUS.map(function (st) { return { l: st.l, k: st.k, n: STATE.findings.filter(function (f) { return statusOf(f) === st.k; }).length }; });
    var top = STATE.findings.filter(isOpen).slice().sort(function (a, b) { return riskScore(b) - riskScore(a); }).slice(0, 8);
    app.innerHTML =
      '<header class="view"><div class="overline">Operations dashboard</div><h1>Where the program stands</h1>' +
      '<p class="lede wide">Live read-out over your imported scan findings — status, SLA pressure, and the highest-risk open work.</p></header>' +
      privSlim() +
      '<div class="kpis">' +
      kpi('Open findings', k.open, k.total + ' total') +
      kpi('Overdue (SLA)', k.overdue, 'past remediation window', k.overdue ? 'crit' : 'ok') +
      kpi('SLA compliance', k.comp + '%', 'open findings within window', k.comp >= 90 ? 'ok' : '') +
      kpi('Open critical', k.crit, 'severity = Critical', k.crit ? 'crit' : '') +
      kpi('Assets', k.assets, 'distinct hosts') +
      kpi('Unassigned', k.unassigned, 'no owner set') +
      kpi('No ticket', k.noTicket, 'open findings, none linked', k.noTicket ? '' : 'ok') +
      '</div>' +
      '<h2>Open by severity</h2>' + barRows(bySev.map(function (x) { return { l: x.s, n: x.n, cls: x.s.toLowerCase() }; })) +
      '<h2>By status</h2>' + barRows(byStatus.map(function (x) { return { l: x.l, n: x.n, color: 'var(--' + (STATUS_BAR_COLOR[x.k] || 'accent') + ')' }; })) +
      '<h2>Highest-risk open findings</h2>' +
      (top.length ? gridTable(top) : '<div class="empty">Nothing open.</div>');
    wireGrid();
  }

  function kpi(label, num, sub, cls) { return '<div class="kpi ' + (cls || '') + '"><div class="label">' + esc(label) + '</div><div class="num">' + esc(num) + '</div><div class="sub">' + esc(sub || '') + '</div></div>'; }
  // per-status bar colours (mirror the status pill colours)
  var STATUS_BAR_COLOR = { new: 'st-new', triaged: 'st-triaged', in_remediation: 'st-rem', resolved: 'st-res', risk_accepted: 'st-risk', false_positive: 'st-fp' };
  function barRows(rows) {
    var max = Math.max.apply(null, rows.map(function (r) { return r.n; }).concat([1]));
    return '<div class="card" style="padding:14px 18px">' + rows.map(function (r) {
      var w = Math.round(r.n / max * 100);
      var color = r.color ? r.color : (r.cls ? 'var(--' + (r.cls === 'critical' ? 'crit' : r.cls === 'high' ? 'high' : r.cls === 'medium' ? 'med' : r.cls === 'low' ? 'low' : 'accent') + ')' : 'var(--accent)');
      return '<div style="display:flex;align-items:center;gap:12px;margin:7px 0;font-size:13.5px">' +
        '<div style="width:130px;color:var(--soft)">' + esc(r.l) + '</div>' +
        '<div style="flex:1;background:color-mix(in srgb,var(--line) 60%,transparent);border-radius:6px;height:18px"><div style="width:' + w + '%;min-width:2px;height:100%;background:' + color + ';border-radius:6px"></div></div>' +
        '<div style="width:48px;text-align:right;font-family:var(--mono);font-size:12.5px">' + r.n + '</div></div>';
    }).join('') + '</div>';
  }

  // Re-render whichever ops view is active (grid/drawer handlers call this after
  // mutating state). Dispatches by route so it works from any VMOPS page.
  function currentView() {
    var h = (location.hash || '').split('?')[0];
    if (h.indexOf('#/dashboard') === 0) return viewDashboard();
    if (h.indexOf('#/settings') === 0) return viewSettings();
    if (h.indexOf('#/import') === 0) return viewImport();
    return viewFindings();
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
  function defaultFilt() { return { q: '', status: '', sev: '', owner: '', repo: '', overdue: false, seen: '', exploited: false, fresh: false, epssHi: false, noTicket: false, colf: {}, group: '' }; }
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
  function viewFindings() {
    setActive('findings');
    // Apply a deep-link query (e.g. Ask AI -> #/findings?sev=Critical&overdue=1) ONLY when it actually
    // changes — otherwise the in-page filter handlers (which re-call viewFindings without touching the
    // hash) would re-parse the stale query every render and clobber the user's selection.
    (function(){ var q=(location.hash.split('?')[1]||''); if(q===STATE._findingsQuery) return; STATE._findingsQuery=q; if(!q) return; var p={}; q.split('&').forEach(function(kv){var a=kv.split('=');p[a[0]]=decodeURIComponent(a[1]||'');}); STATE.filt={ q:p.q||'', status:p.status||'', sev:p.sev||'', owner:p.owner||'', repo:p.repo||'', overdue:p.overdue==='1', seen:p.seen||'', exploited:p.exploited==='1', fresh:p.fresh==='1', epssHi:p.epssHi==='1', noTicket:p.noTicket==='1', colf:{}, group:STATE.filt.group||'' }; })();
    if (!STATE.findings.length) return viewEmpty('findings');
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
      '<header class="view"><div class="overline">Findings workbench</div><h1>Vulnerability findings</h1>' +
      '<p class="lede">Triage your imported scan findings by status, owner, SLA, and recency — keep per-finding notes and a dated status log, and open Jira or ServiceNow tickets. Everything stays in your browser.</p></header>' +
      privSlim() +
      '<div class="toolbar">' +
      '<input type="text" id="fq" placeholder="Search CVE, host, description, repo, owner…" value="' + esc(STATE.filt.q) + '">' +
      '<select id="fStatus">' + statusOpts + '</select>' +
      '<select id="fSev">' + sevOpts + '</select>' +
      '<select id="fSeen">' + seenOpts + '</select>' +
      '<select id="fOwner">' + ownerOpts + '</select>' +
      (repoList.length ? '<select id="fRepo">' + repoOpts + '</select>' : '') +
      '<button class="btn sm" id="fOverdue" style="' + (STATE.filt.overdue ? 'border-color:var(--crit);color:var(--crit)' : '') + '">Overdue only</button>' +
      '<button class="btn sm" id="fExploit" style="' + (STATE.filt.exploited ? 'border-color:var(--crit);color:var(--crit)' : '') + '" title="KEV-listed or with a public exploit">Exploited only</button>' +
      '<button class="btn sm" id="fEpssHi" style="' + (STATE.filt.epssHi ? 'border-color:var(--crit);color:var(--crit)' : '') + '" title="EPSS ≥ 50% (high near-term exploitation probability)">EPSS ≥ 50%</button>' +
      '<button class="btn sm" id="fNoTicket" style="' + (STATE.filt.noTicket ? 'border-color:var(--high);color:var(--high)' : '') + '" title="Open findings with no linked ticket — needs a ticket">No ticket</button>' +
      (Object.keys(STATE._newKeys || {}).length ? '<button class="btn sm" id="fFresh" style="' + (STATE.filt.fresh ? 'border-color:var(--accent);color:var(--accent)' : '') + '" title="Added in the most recent scan">New only</button>' : '') +
      '<select id="fGroup" title="Group findings"><option value="">No grouping</option><option value="cve"' + (STATE.filt.group === 'cve' ? ' selected' : '') + '>Group by CVE</option><option value="product"' + (STATE.filt.group === 'product' ? ' selected' : '') + '>Group by product / fix</option><option value="host"' + (STATE.filt.group === 'host' ? ' selected' : '') + '>Group by host</option></select>' +
      '<select id="fView" title="Saved & preset views">' + viewOpts + '</select>' +
      '<button class="btn sm" id="fViewSave" title="Save the current filters as a view">Save view</button>' +
      '<button class="btn sm" id="fViewDel" title="Delete the active saved view"' + (activeView.indexOf('saved:') === 0 ? '' : ' style="display:none"') + '>Delete view</button>' +
      '<span class="spacer"></span>' +
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
      '<button class="btn sm" id="bulkJira" title="One Jira ticket covering all selected">Jira ticket</button>' +
      '<button class="btn sm" id="bulkSnow" title="One ServiceNow incident covering all selected">SNOW ticket</button>' +
      '<button class="btn sm" id="bulkTicket" title="Link one ticket key to all selected findings">Link ticket…</button>' +
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
    document.getElementById('fOverdue').addEventListener('click', function () { STATE.filt.overdue = !STATE.filt.overdue; viewFindings(); });
    document.getElementById('fExploit').addEventListener('click', function () { STATE.filt.exploited = !STATE.filt.exploited; viewFindings(); });
    document.getElementById('fEpssHi').addEventListener('click', function () { STATE.filt.epssHi = !STATE.filt.epssHi; viewFindings(); });
    document.getElementById('fNoTicket').addEventListener('click', function () { STATE.filt.noTicket = !STATE.filt.noTicket; viewFindings(); });
    var fFresh = document.getElementById('fFresh'); if (fFresh) fFresh.addEventListener('click', function () { STATE.filt.fresh = !STATE.filt.fresh; viewFindings(); });
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
      fs.forEach(function (f) { var ex = ovOf(f).notes || ''; setOverride(f, { notes: ex ? ex + '\n' + t : t }); });
      clearTxt(); toast('Note appended to ' + fs.length + ' finding' + (fs.length > 1 ? 's' : ''));
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
      fs.forEach(function (f) { setOverride(f, { status: v }); addUpdate(f, 'Status → ' + SLABEL[v]); });
      toast('Status → ' + SLABEL[v] + ' for ' + fs.length + ' finding' + (fs.length > 1 ? 's' : ''));
      currentView();
    });
    var bj = document.getElementById('bulkJira'); if (bj) bj.addEventListener('click', function () { var fs = need(); if (fs.length) ticketGroup('jira', fs); });
    var bsn = document.getElementById('bulkSnow'); if (bsn) bsn.addEventListener('click', function () { var fs = need(); if (fs.length) ticketGroup('snow', fs); });
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
  function totalW() { return COL_DEFS.reduce(function (s, c) { return s + colW(c); }, 0); }
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
      '<td class="cid"><a href="' + CVE_DETAIL + esc(f.cve) + '" title="Open CVE detail">' + esc(f.cve) + '</a>' + (isNewKey(keyOf(f)) ? '<span class="ichip new" title="New since last scan">NEW</span>' : '') + intelChips(f.cve) + '</td>' +
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
        '<td colspan="7" class="muted" style="font-size:12px">' + g.openCount + ' open / ' + g.count + '</td><td></td></tr>';
      return head + g.items.map(function (f) { return findingRow(f, g.id); }).join('');
    }).join('');
    return '<table class="grid resizable" id="gridHost" style="width:' + totalW() + 'px">' + gridHead() + '<tbody>' + body + '</tbody></table>';
  }
  function renderGrid(list) { return STATE.filt.group ? groupedTable(list, STATE.filt.group) : gridTable(list); }
  function intelChips(cve) {
    var it = cveIntel(cve), c = '';
    if (it.kev) c += '<span class="ichip kev" title="CISA Known Exploited Vulnerability' + (it.kevDue ? ' — remediate by ' + it.kevDue : '') + '">KEV</span>';
    if (it.ransomware) c += '<span class="ichip rw" title="Known ransomware campaign use">RW</span>';
    if (!it.kev && it.exploit) c += '<span class="ichip poc" title="Public exploit / PoC available">PoC</span>';
    return c ? ' ' + c : '';
  }
  function priChip(f) { var p = priorityOf(f); return p ? '<span class="pri ' + p.toLowerCase() + '">' + p + '</span>' : '<span class="muted">—</span>'; }
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
      th.addEventListener('click', function (e) { if (e.target.closest('.col-resize')) return; var c = th.getAttribute('data-col'); if (STATE.sort.col === c) STATE.sort.dir *= -1; else { STATE.sort.col = c; STATE.sort.dir = 1; } currentView(); });
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
    [].forEach.call(document.querySelectorAll('table.grid tbody tr'), function (tr) {
      var f = findByKey(tr.getAttribute('data-key'));
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
      '<div class="row"><span class="k">SLA due</span><span class="pill-sla ' + ss + '">' + (dd ? esc(dd) + (di == null ? '' : ' · ' + (di < 0 ? Math.abs(di) + 'd overdue' : di + 'd left')) : '—') + '</span></div>' +
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
      '</div>';
    bg.classList.add('open'); dr.classList.add('open');
    // Fill the remaining prioritization models: SSVC is derived (instant); EPSS (live) + LEV (local) load async.
    (function () {
      var it = cveIntel(f.cve), sv = ssvcVerdict(it.kev, it.exploit, f.cvss);
      var se = document.getElementById('drSsvc'); if (se) se.innerHTML = '<b>' + sv.v + '</b>' + (sv.why ? ' · ' + esc(sv.why) : '');
      var setEpss = function (e) { var el = document.getElementById('drEpss'); if (!el) return; el.className = ''; var v = epssVerdict(e); el.innerHTML = e == null ? '<span class="muted">—</span>' : '<b>' + v.v + '</b> · ' + esc(v.why); };
      if (it.epss != null) setEpss(it.epss); else epssFor(f.cve).then(setEpss);   // prefer the loaded feed; fall back to a live lookup
      levFor(f.cve).then(function (l) { var el = document.getElementById('drLev'); if (!el) return; el.className = ''; var v = levVerdict(l); el.innerHTML = l == null ? '<span class="muted">—</span>' : '<b>' + v.v + '</b> · ' + esc(v.why); });
    })();
    function close() { bg.classList.remove('open'); dr.classList.remove('open'); }
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
  function openTicket(kind, f) { var u = ticketUrl(kind, ticketSummary(f), ticketBody(f)); if (u) window.open(u, '_blank', 'noopener'); }
  // One ticket covering a whole selection/group (deep-link → a single ticket listing every host).
  function groupSummary(fs) {
    var cves = {}, hosts = {}; fs.forEach(function (f) { cves[f.cve] = 1; hosts[f.host] = 1; });
    var nc = Object.keys(cves).length, nh = Object.keys(hosts).length;
    return nc === 1 ? ('[' + fs[0].severity + '] ' + fs[0].cve + ' on ' + nh + ' host' + (nh > 1 ? 's' : ''))
      : (nc + ' vulnerabilities across ' + nh + ' host' + (nh > 1 ? 's' : ''));
  }
  function groupBody(fs) {
    var lines = fs.map(function (f) { return '- ' + f.cve + ' | ' + f.host + ' | ' + f.severity + (priorityOf(f) ? ' | ' + priorityOf(f) : '') + (cveIntel(f.cve).kev ? ' | KEV' : ''); });
    return 'Remediation ticket covering ' + fs.length + ' finding(s):\n' + lines.join('\n') + '\n\nGenerated by ' + (window.VM_BRAND || 'VM Ops Console') + '.';
  }
  function ticketGroup(kind, fs) { if (!fs.length) return; var u = ticketUrl(kind, groupSummary(fs), groupBody(fs)); if (u) window.open(u, '_blank', 'noopener'); }
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
      { id: 'findings', label: 'Scan findings', sub: 'Nessus / Tenable vulnerability CSV → Findings workbench', accept: '.csv,text/csv' }
    ] },
    { title: 'Agent coverage', open: { route: '#/agent-coverage', label: 'Open Agent Coverage →' }, items: [
      { id: 'acd:ad', label: 'Active Directory (AD)', sub: 'Computer inventory → Agent Coverage denominator', accept: '.json,.csv' },
      { id: 'acd:me', label: 'ManageEngine (ME)', sub: 'Endpoint Central agents → Agent Coverage', accept: '.json,.csv' },
      { id: 'acd:tsc', label: 'Tenable.sc (TSC)', sub: 'Tenable.sc agents / assets → Agent Coverage', accept: '.json,.csv' },
      { id: 'acd:tio', label: 'Tenable.io (TIO)', sub: 'Tenable.io agents / assets → Agent Coverage', accept: '.json,.csv' },
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
      '<div class="toolbar"><a class="btn sm" href="#/settings">← Settings</a><span class="spacer"></span><a class="btn sm" href="sharepoint-test.html" target="_blank" rel="noopener">SharePoint tester ↗</a><button class="btn sm" id="loadSample">Load sample findings</button></div>' +
      IMPORT_GROUPS.map(function (g) {
        return '<div class="import-grouprow"><h2 class="import-grouphdr">' + esc(g.title) + '</h2>' +
          (g.open ? '<a class="btn sm import-open" href="' + g.open.route + '">' + esc(g.open.label) + '</a>' : '') +
          '</div><div class="importgrid">' + g.items.map(importCard).join('') + '</div>';
      }).join('') +
      '<h2 class="import-grouphdr">Coming soon</h2><div class="importgrid">' +
      IMPORT_SOON.map(function (s) { return '<div class="card import-src soon"><div class="src-title">' + esc(s.label) + '</div><div class="muted src-sub">' + esc(s.sub) + '</div><div class="src-status muted">Coming soon</div></div>'; }).join('') +
      '</div>';
    document.getElementById('loadSample').addEventListener('click', function () { var _s = SAMPLE(); mergeFindings(_s); seedSampleOverrides(_s); if (window.VMStore) VMStore.put({ id: 'findings', name: 'sample (built-in)', text: '', kind: 'sample' }); toast('Loaded sample findings'); goDash(); });
    [].forEach.call(document.querySelectorAll('.src-pick'), function (b) { b.addEventListener('click', function () { document.querySelector('.src-file[data-id="' + b.getAttribute('data-id') + '"]').click(); }); });
    [].forEach.call(document.querySelectorAll('.src-file'), function (inp) { inp.addEventListener('change', function () { if (inp.files[0]) handleSourceFile(inp.getAttribute('data-id'), inp.files[0]); inp.value = ''; }); });
    [].forEach.call(document.querySelectorAll('.src-clear'), function (b) { b.addEventListener('click', function () { clearSource(b.getAttribute('data-id')); }); });
    IMPORT_SOURCES.forEach(function (s) { refreshSourceStatus(s.id); });
  }
  function refreshSourceStatus(id) {
    var el = document.getElementById(stId(id)); if (!el) return;
    if (id === 'findings') { el.innerHTML = STATE.findings.length ? '<span class="ok-txt">✓ ' + STATE.findings.length + ' findings loaded</span>' : 'Not imported yet.'; return; }
    if (!window.VMStore) { el.textContent = 'Browser storage unavailable.'; return; }
    VMStore.get(id).then(function (rec) { el.innerHTML = rec ? '<span class="ok-txt">✓ ' + esc(rec.name) + '</span> · ' + esc(new Date(rec.importedAt).toLocaleString()) : 'Not imported yet.'; }).catch(function () { el.textContent = 'Not imported yet.'; });
  }
  function handleSourceFile(id, file) {
    var r = new FileReader();
    r.onload = function () {
      var text = String(r.result || '');
      var kind = (/\.json$/i.test(file.name) || /^\s*[\[{]/.test(text)) ? 'json' : 'csv';
      if (id === 'findings') {
        var fs; try { fs = parseCsv(text); } catch (e) { return toast('Parse error: ' + e.message); }
        if (!fs.length) return toast('No CVE rows found in that CSV');
        var sum = importScan(fs);
        if (window.VMStore) VMStore.put({ id: 'findings', name: file.name, text: text, kind: 'csv' });
        toast(sum.reimport ? ('Rescan: ' + sum.total + ' findings · ' + sum.added + ' new · ' + sum.fixed + ' auto-resolved (fixed)') : ('Imported ' + sum.total + ' findings')); refreshSourceStatus(id);
      } else if (window.VMStore) {
        var dest = id.indexOf('tvd:') === 0 ? 'the Tenable dashboard' : 'Agent Coverage';
        VMStore.put({ id: id, name: file.name, text: text, kind: kind }).then(function () { toast(file.name + ' imported — open ' + dest + ' to view'); refreshSourceStatus(id); });
      } else { toast('Browser storage unavailable'); }
    };
    r.readAsText(file);
  }
  function clearSource(id) {
    if (id === 'findings') { if (!confirm('Clear all findings, status, owners, and notes from this browser?')) return; STATE.findings = []; STATE.ov = {}; save('vmops-findings', []); save('vmops-overrides', {}); }
    if (window.VMStore) VMStore.remove(id);
    toast('Cleared'); refreshSourceStatus(id);
  }
  function readFile(file) { var r = new FileReader(); r.onload = function () { try { var fs = parseCsv(String(r.result || '')); if (!fs.length) return toast('No CVE rows found in that CSV'); mergeFindings(fs); toast('Imported ' + fs.length + ' findings'); goDash(); } catch (e) { toast('Parse error: ' + e.message); } }; r.readAsText(file); }
  function mergeFindings(incoming) {
    var idx = {}; STATE.findings.forEach(function (f, i) { idx[keyOf(f)] = i; });
    incoming.forEach(function (f) {
      var k = keyOf(f);
      if (idx[k] != null) { var old = STATE.findings[idx[k]]; if (old.firstSeen && (!f.firstSeen || old.firstSeen < f.firstSeen)) f.firstSeen = old.firstSeen; STATE.findings[idx[k]] = f; }
      else { STATE.findings.push(f); idx[k] = STATE.findings.length - 1; }
    });
    save('vmops-findings', STATE.findings);
  }
  // A re-import is a fresh scan: diff vs the current set, auto-resolve anything that's gone
  // (no longer detected), and remember what's new — so you see progress, not a static list.
  function importScan(incoming) {
    var reimport = STATE.findings.length > 0;
    var incKeys = {}, existing = {};
    incoming.forEach(function (f) { incKeys[keyOf(f)] = 1; });
    STATE.findings.forEach(function (f) { existing[keyOf(f)] = 1; });
    var added = 0; incoming.forEach(function (f) { if (!existing[keyOf(f)]) added++; });
    var fixed = 0;
    STATE.findings.forEach(function (f) { if (isOpen(f) && !incKeys[keyOf(f)]) { setOverride(f, { status: 'resolved' }); addUpdate(f, 'Rescan: no longer detected — auto-resolved'); fixed++; } });
    STATE._newKeys = {}; if (reimport) incoming.forEach(function (f) { var k = keyOf(f); if (!existing[k]) STATE._newKeys[k] = 1; });
    try { localStorage.setItem('vmops-newkeys', JSON.stringify(Object.keys(STATE._newKeys))); } catch (e) {}
    var today = todayISO();
    mergeFindings(incoming.map(function (f) { f.lastSeen = today; return f; }));
    return { added: added, fixed: fixed, total: incoming.length, reimport: reimport };
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
      iVpr = col([/vpr.*score/i, /\bvpr\b/i]);
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
      cves.forEach(function (cve) { out.push({ cve: cve.toUpperCase(), host: host || 'unknown', severity: sev, cvss: isNaN(cvss) ? null : cvss, vpr: (vpr == null || isNaN(vpr)) ? null : vpr, plugin: iPid > -1 ? (r[iPid] || '').trim() : '', name: nm, desc: ds || nm, repo: rp, source: 'Tenable', firstSeen: seen }); });
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

  function exportCsv() {
    var list = visibleFindings();
    var head = ['CVE', 'Host', 'Description', 'Severity', 'CVSS', 'VPR', 'EPSS', 'Status', 'Ticket', 'Owner', 'Repo', 'FirstSeen', 'LastSeen', 'SLA_Due', 'Days_To_Due', 'Plugin', 'Source', 'Notes', 'Updates'];
    var lines = [head.join(',')].concat(list.map(function (f) {
      var o = ovOf(f), ep = cveIntel(f.cve).epss;
      var ups = updatesOf(f).map(function (u) { return (u.at || '').slice(0, 10) + ' ' + (u.text || '').replace(/\s+/g, ' '); }).join(' | ');
      return [f.cve, f.host, f.desc || f.name || '', f.severity, f.cvss == null ? '' : f.cvss, f.vpr == null ? '' : f.vpr, ep == null ? '' : ep, SLABEL[statusOf(f)], (ticketOf(f) ? ticketOf(f).key : ''), o.owner || '', repoOf(f), f.firstSeen, f.lastSeen || '', dueDate(f) || '', dueIn(f) == null ? '' : dueIn(f), f.plugin || '', f.source || '', (o.notes || '').replace(/\s+/g, ' '), ups]
        .map(function (v) { v = String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }).join(',');
    }));
    var blob = new Blob([lines.join('\n')], { type: 'text/csv' }), a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = 'vm-findings-' + todayISO() + '.csv'; a.click(); URL.revokeObjectURL(a.href); toast('Exported ' + list.length + ' findings');
  }

  // ---------- settings ----------
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
      '<div class="muted" style="font-size:12.5px">Sets the name in the top nav + browser tab and the page icon (favicon) — 1–3 letters on a colored tile. Leave the name blank to use “' + esc(DEFAULT_BRAND) + '”; leave the monogram blank to derive it from the name.</div></div>' +
      '<h2>Data import</h2><div class="card">' +
      '<div class="muted" style="font-size:13px;margin-bottom:12px">Bring in each data source — Active Directory, ManageEngine, Tenable.sc / .io, CrowdStrike, and scan findings. Files are parsed and cached in your browser and feed the dashboards.</div>' +
      '<a class="btn primary" href="#/import">Open Data Import →</a></div>' +
      '<h2>Remediation SLA windows (days)</h2><div class="card"><div class="grid2">' +
      ['Critical', 'High', 'Medium', 'Low'].map(function (s) { return '<div class="field"><label>' + s + '</label><input type="number" min="0" data-sla="' + s + '" value="' + esc(c.sla[s]) + '"></div>'; }).join('') +
      '</div><div class="muted" style="font-size:12.5px">SLA due = first-seen date + window. Drives overdue flags and SLA compliance.</div></div>' +
      '<h2>Jira</h2><div class="card">' +
      '<div class="field"><label>Base URL</label><input type="text" id="jiraBase" value="' + esc(c.jiraBase) + '" placeholder="https://yourorg.atlassian.net"></div>' +
      '<div class="grid2"><div class="field"><label>Project ID (pid, numeric)</label><input type="text" id="jiraPid" value="' + esc(c.jiraPid) + '" placeholder="10001"></div>' +
      '<div class="field"><label>Issue type ID</label><input type="text" id="jiraType" value="' + esc(c.jiraType) + '" placeholder="10002"></div></div>' +
      '<div class="muted" style="font-size:12.5px">With project + issue-type IDs set, "Open Jira story" pre-fills summary & description. Without them it opens the create dialog. (Path A: deep-link only — no API token, nothing leaves the browser.)</div></div>' +
      '<h2>ServiceNow</h2><div class="card">' +
      '<div class="field"><label>Base URL</label><input type="text" id="snowBase" value="' + esc(c.snowBase) + '" placeholder="https://yourorg.service-now.com"></div>' +
      '<div class="muted" style="font-size:12.5px">"Open SNOW incident" opens a new incident pre-filled with the finding. "Search ServiceNow" queries existing incidents for the CVE.</div></div>' +
      '<h2>Tenable API keys</h2><div class="card">' +
      '<div class="muted" style="font-size:12.5px;margin-bottom:12px">Stored in <b>this browser only</b> — never uploaded. Note: Tenable.sc / Tenable.io block direct in-browser API calls (CORS), so these aren\'t used for live pulls yet; they\'re saved here for a future local connector. To bring data in today, use <a href="#/import">Import</a> with a Tenable export.</div>' +
      '<div style="font-weight:600;font-size:13px;color:var(--soft);margin:2px 0 6px">Tenable.sc</div>' +
      '<div class="field"><label>Tenable.sc URL</label><input type="text" id="tsUrl" value="' + esc(c.tsUrl) + '" placeholder="https://tenable-sc.yourorg.com"></div>' +
      '<div class="grid2"><div class="field"><label>Access key</label><input type="password" id="tsAccess" autocomplete="off" value="' + esc(c.tsAccess) + '" placeholder="access key"></div>' +
      '<div class="field"><label>Secret key</label><input type="password" id="tsSecret" autocomplete="off" value="' + esc(c.tsSecret) + '" placeholder="secret key"></div></div>' +
      '<div style="font-weight:600;font-size:13px;color:var(--soft);margin:14px 0 6px">Tenable.io (cloud.tenable.com)</div>' +
      '<div class="grid2"><div class="field"><label>Access key</label><input type="password" id="tioAccess" autocomplete="off" value="' + esc(c.tioAccess) + '" placeholder="access key"></div>' +
      '<div class="field"><label>Secret key</label><input type="password" id="tioSecret" autocomplete="off" value="' + esc(c.tioSecret) + '" placeholder="secret key"></div></div></div>' +
      '<h2>ManageEngine API</h2><div class="card">' +
      '<div class="muted" style="font-size:12.5px;margin-bottom:12px">Endpoint Central / Vulnerability Manager Plus uses <b>OAuth2</b> (Zoho self-client). Stored in <b>this browser only</b>. Like Tenable.io / CrowdStrike, ManageEngine doesn\'t send CORS headers to a static origin, so these aren\'t used for live in-browser pulls yet — they\'re saved for a future local connector. To bring data in today, use <a href="#/import">Import</a> with a ManageEngine export.</div>' +
      '<div class="field"><label>Server URL</label><input type="text" id="meUrl" value="' + esc(c.meUrl) + '" placeholder="https://endpoint-central.yourorg.com"></div>' +
      '<div class="grid2"><div class="field"><label>Client ID</label><input type="password" id="meClientId" autocomplete="off" value="' + esc(c.meClientId) + '" placeholder="client ID"></div>' +
      '<div class="field"><label>Client Secret</label><input type="password" id="meClientSecret" autocomplete="off" value="' + esc(c.meClientSecret) + '" placeholder="client secret"></div></div></div>' +
      '<h2>SharePoint access tester</h2><div class="card">' +
      '<div class="muted" style="font-size:12.5px;margin-bottom:12px">Diagnostic: paste a SharePoint / OneDrive sharing link and test which method can read the file in-browser — anonymous (blocked) vs. Microsoft Graph (<code>downloadUrl</code>, works after sign-in). Opens in a new tab; your link &amp; token stay there, nothing is uploaded.</div>' +
      '<a class="btn" href="sharepoint-test.html" target="_blank" rel="noopener">Open SharePoint Access Tester ↗</a></div>' +
      '<div class="toolbar"><button class="btn primary" id="saveCfg">Save settings</button><button class="btn" id="resetSla">Reset SLA to defaults</button></div>';
    document.getElementById('saveCfg').addEventListener('click', function () {
      STATE.cfg.brand = document.getElementById('brandName').value.trim();
      STATE.cfg.brandIcon = document.getElementById('brandIcon').value.trim();
      STATE.cfg.brandIconColor = document.getElementById('brandIconColor').value.trim();
      [].forEach.call(document.querySelectorAll('[data-sla]'), function (i) { var v = parseInt(i.value, 10); if (!isNaN(v)) STATE.cfg.sla[i.getAttribute('data-sla')] = v; });
      STATE.cfg.jiraBase = document.getElementById('jiraBase').value.trim();
      STATE.cfg.jiraPid = document.getElementById('jiraPid').value.trim();
      STATE.cfg.jiraType = document.getElementById('jiraType').value.trim();
      STATE.cfg.snowBase = document.getElementById('snowBase').value.trim();
      STATE.cfg.tsUrl = document.getElementById('tsUrl').value.trim();
      STATE.cfg.tsAccess = document.getElementById('tsAccess').value.trim();
      STATE.cfg.tsSecret = document.getElementById('tsSecret').value.trim();
      STATE.cfg.tioAccess = document.getElementById('tioAccess').value.trim();
      STATE.cfg.tioSecret = document.getElementById('tioSecret').value.trim();
      STATE.cfg.meUrl = document.getElementById('meUrl').value.trim();
      STATE.cfg.meClientId = document.getElementById('meClientId').value.trim();
      STATE.cfg.meClientSecret = document.getElementById('meClientSecret').value.trim();
      save('vmops-config', STATE.cfg); applyBrand(); toast('Settings saved');
    });
    document.getElementById('resetSla').addEventListener('click', function () { STATE.cfg.sla = Object.assign({}, DEFAULT_CFG.sla); save('vmops-config', STATE.cfg); viewSettings(); toast('SLA windows reset'); });
  }

  // ---------- vendored same-origin sub-apps ----------
  // The Tenable VM Dashboard and Agent Coverage dashboards are native same-origin views
  // (acd.js / tvd.js, rendered into #app on their routes) — no iframes.

  function viewEmpty(active) {
    setActive(active);
    app.innerHTML = '<header class="view"><div class="overline">' + esc(window.VM_BRAND || 'VM Ops Console') + '</div><h1>No findings yet</h1>' +
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
    setActive('dashboard');
    app.innerHTML =
      '<header class="view"><div class="overline">Operations Dashboard</div><h1>Wiz cloud findings</h1>' +
      '<p class="lede">Cloud (CNAPP) findings from Wiz — issues, toxic combinations, public exposure, and SLA — alongside your Tenable findings and agent coverage, so every vulnerability from Tenable <i>and</i> Wiz lives in one place.</p></header>' +
      privSlim() +
      '<div class="card" style="text-align:center;padding:40px 24px">' +
      '<div style="font-family:var(--serif);font-size:20px;margin-bottom:8px">Wiz isn’t connected yet</div>' +
      '<div class="muted" style="max-width:560px;margin:0 auto 18px;font-size:14px;line-height:1.6">The Wiz connector is on the roadmap. Wiz uses a GraphQL API with OAuth2 service-account auth, so live pulls need a small local connector (the same one that will unlock Tenable.io / CrowdStrike). Once it lands, import your Wiz export on the Data Import page and this dashboard lights up — issues by cloud, by resource type, toxic combinations, and SLA.</div>' +
      '<a class="btn primary" href="#/import">Open Data Import →</a></div>';
  }

  function vmShow(fn){ return function(){ app.className='vmops'; return fn.apply(null, arguments); }; }
  function goDash() { if ((location.hash||'').indexOf('#/dashboard')===0){ app.className='vmops'; viewDashboard(); } else { location.hash='#/dashboard'; } }
  // Exposed to the host (CVE-Explorer-based) router, which dispatches the ops routes.
  window.VMOPS = { dashboard: vmShow(viewDashboard), findings: vmShow(viewFindings), import: vmShow(viewImport), settings: vmShow(viewSettings), wiz: vmShow(viewWiz) };
})();
