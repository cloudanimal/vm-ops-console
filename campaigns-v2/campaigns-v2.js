/* ============================================================================
 * campaigns-v2.js  —  Campaigns v2 workspace, wrapped as ONE IIFE => window.CV2
 * Built by build_cv2.js (P3 of the Campaigns v2 merge). Source clone files
 * util.js + themes.js + views.js + drawer.js + app.js are concatenated below,
 * in that order, inside a single closure. store/model/idb/import are DROPPED
 * and replaced by stubs + an injected Store adapter (or an in-memory FIXTURE
 * for standalone verification). No clone auto-boot, no clone router, no clone
 * IndexedDB. See cv2_blueprint.md sections C/E/G.
 * ==========================================================================*/
(function(){
'use strict';

/* ---- Store alias: set at the top of CV2.mount() so the clone's ~229 Store.*
 *      calls resolve to the injected adapter (or the FIXTURE). ------------- */
let Store;

/* ============================================================================
 * STUBS for the dropped modules (idb.js / model.js / import.js). Each provides
 * the minimum surface the kept files touch so nothing is `undefined`.
 * ==========================================================================*/
const IDB = {
  available: false,
  reason: 'IndexedDB disabled in Campaigns v2 (data comes from the console)',
  open(){ return Promise.reject(new Error('idb disabled')); },
  getAll(){ return Promise.resolve([]); },
  put(){ return Promise.resolve(); },
  stats(){ return Promise.resolve({}); },
  quota(){ return Promise.resolve(null); },
  requestPersistence(){ return Promise.resolve({ granted:false }); }
};
const Remediation = { rollup(){ return []; }, saveGroup(){ return Promise.resolve(); } };
const Importers   = { run(){ throw new Error('Scan import is not available in Campaigns v2'); } };
const Exceptions  = {
  evaluate(){ return { suppressed:false, winner:null }; },
  create(){ return {}; },
  preview(){ return []; }
};
const EXCEPTION_TYPES  = {};   // object: Object.keys()/[k].label only hit on the (unrouted) findings view
const DETECTION_STATES = [];   // array
const Lifecycle   = { isOpen(){ return true; } };
const TabSync     = { withImportLock(fn){ return fn(); }, onMessage(){}, broadcast(){} };

/* ============================================================================
 * Theme + Brand persistence, decoupled from the dropped Store into the
 * console's localStorage under the 'vmops-cv2-' prefix; seeded from the
 * console's own light/dark choice.
 * ==========================================================================*/
let _cv2Theme = null, _cv2Brand = null;
function consoleIsDark(){
  var t = document.documentElement.getAttribute('data-theme');
  return t === 'dark' || (!t && matchMedia('(prefers-color-scheme:dark)').matches);
}
function cv2ThemeCfg(){
  if (!_cv2Theme){
    try { _cv2Theme = JSON.parse(localStorage.getItem('vmops-cv2-theme')); } catch(e){}
    if (!_cv2Theme || typeof _cv2Theme !== 'object') _cv2Theme = { preset: consoleIsDark() ? 'dark' : 'light', custom:null };
  }
  return _cv2Theme;
}
function cv2SaveTheme(){ try { localStorage.setItem('vmops-cv2-theme', JSON.stringify(_cv2Theme)); } catch(e){} }
function cv2BrandCfg(){
  if (!_cv2Brand){
    try { _cv2Brand = JSON.parse(localStorage.getItem('vmops-cv2-brand')); } catch(e){}
    if (!_cv2Brand || typeof _cv2Brand !== 'object') _cv2Brand = { name:'Campaigns', icon:'' };
  }
  return _cv2Brand;
}
function cv2SaveBrand(){ try { localStorage.setItem('vmops-cv2-brand', JSON.stringify(_cv2Brand)); } catch(e){} }

/* ============================== util.js ================================== */
/* ===== util.js - helpers ===== */

const U = {
  uid(p){ return (p||'id') + '_' + Math.random().toString(36).slice(2,9) + Date.now().toString(36).slice(-4); },

  esc(s){
    if (s === null || s === undefined) return '';
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  },

  // ---- dates (all task dates stored as YYYY-MM-DD strings, local) ----
  today(){ return U.ymd(new Date()); },
  ymd(d){
    const y = d.getFullYear(), m = String(d.getMonth()+1).padStart(2,'0'), dd = String(d.getDate()).padStart(2,'0');
    return `${y}-${m}-${dd}`;
  },
  parse(s){
    if (!s) return null;
    const p = String(s).split('-').map(Number);
    if (p.length !== 3 || p.some(isNaN)) return null;
    return new Date(p[0], p[1]-1, p[2]);
  },
  addDays(s, n){ const d = U.parse(s) || new Date(); d.setDate(d.getDate()+n); return U.ymd(d); },
  daysBetween(a, b){
    const da = U.parse(a), db = U.parse(b);
    if (!da || !db) return 0;
    return Math.round((db - da) / 86400000);
  },
  fmtDate(s){
    const d = U.parse(s); if (!d) return '';
    const t = U.parse(U.today());
    const diff = Math.round((d - t) / 86400000);
    if (diff === 0) return 'Today';
    if (diff === 1) return 'Tomorrow';
    if (diff === -1) return 'Yesterday';
    const opts = { month:'short', day:'numeric' };
    if (d.getFullYear() !== t.getFullYear()) opts.year = 'numeric';
    return d.toLocaleDateString(undefined, opts);
  },
  dueClass(s){
    if (!s) return '';
    const diff = U.daysBetween(U.today(), s);
    if (diff < 0) return 'over';
    if (diff === 0) return 'today';
    return 'soon';
  },
  fmtTime(ts){
    const d = new Date(ts);
    const diff = (Date.now() - ts) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff/60) + 'm ago';
    if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
    if (diff < 604800) return Math.floor(diff/86400) + 'd ago';
    return d.toLocaleDateString(undefined, { month:'short', day:'numeric' });
  },
  // minutes -> "3h 20m"
  dur(mins){
    if (!mins) return '';
    const h = Math.floor(mins/60), m = Math.round(mins%60);
    return (h ? h + 'h ' : '') + (m ? m + 'm' : (h ? '' : '0m'));
  },

  initials(name){
    return String(name||'?').trim().split(/\s+/).slice(0,2).map(w => w[0]||'').join('').toUpperCase() || '?';
  },

  debounce(fn, ms){
    let t; return function(...a){ clearTimeout(t); t = setTimeout(() => fn.apply(this,a), ms||220); };
  },

  // safe query
  $(sel, root){ return (root||document).querySelector(sel); },
  $$(sel, root){ return Array.from((root||document).querySelectorAll(sel)); },

  download(filename, text, type){
    const blob = new Blob([text], { type: type || 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  },

  // CSV cell that cannot be interpreted as a formula by spreadsheet apps
  csvCell(v){
    let s = v === null || v === undefined ? '' : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  },

  toast(msg, actionLabel, actionFn){
    const wrap = document.getElementById('cv2-toasts');
    const el = document.createElement('div');
    el.className = 'c2toast';
    const span = document.createElement('span');
    span.textContent = msg;
    el.appendChild(span);
    if (actionLabel && actionFn){
      const b = document.createElement('button');
      b.textContent = actionLabel;
      b.onclick = () => { actionFn(); el.remove(); };
      el.appendChild(b);
    }
    wrap.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .25s'; setTimeout(() => el.remove(), 260); }, actionLabel ? 6000 : 2600);
  }
};

const PRIORITIES = {
  1: { name:'Urgent', color:'var(--red)',   cls:'prio-1' },
  2: { name:'High',   color:'var(--amber)', cls:'prio-2' },
  3: { name:'Normal', color:'var(--blue)',  cls:'prio-3' },
  4: { name:'Low',    color:'var(--gray)',  cls:'prio-4' }
};

const PALETTE = ['#7b68ee','#fd71af','#49ccf9','#2ecc8f','#f5a623','#e8506e','#8e44ad','#00b8a9','#ff7f50','#5c7cfa','#20c997','#868a96'];

/* ============================== themes.js ================================ */
/* ===== themes.js - branding + theme engine ===== */

// Variables a theme is allowed to set. Anything omitted falls back to the
// stylesheet default for that theme's base (light or dark).
const THEME_VARS = ['bg','bg-2','bg-3','sidebar','panel','border','border-2',
                    'text','text-2','muted','accent','accent-2','accent-3'];

const THEMES = [
  { id:'light', name:'Light', base:'light', swatch:['#ffffff','#f7f8f9','#7b68ee'], vars:{} },
  { id:'dark',  name:'Dark',  base:'dark',  swatch:['#1a1a22','#15151c','#7b68ee'], vars:{} },
  { id:'midnight', name:'Midnight', base:'dark', swatch:['#0d1117','#161b22','#6366f1'], vars:{
      'bg':'#0d1117','bg-2':'#010409','bg-3':'#21262d','sidebar':'#010409','panel':'#161b22',
      'border':'#21262d','border-2':'#30363d','text':'#e6edf3','text-2':'#b9c0c8','muted':'#8b949e',
      'accent':'#6366f1','accent-2':'#c084fc','accent-3':'#38bdf8' } },
  { id:'nord', name:'Nord', base:'dark', swatch:['#2e3440','#3b4252','#88c0d0'], vars:{
      'bg':'#2e3440','bg-2':'#272c36','bg-3':'#3b4252','sidebar':'#272c36','panel':'#3b4252',
      'border':'#434c5e','border-2':'#4c566a','text':'#eceff4','text-2':'#d8dee9','muted':'#9aa5b8',
      'accent':'#88c0d0','accent-2':'#b48ead','accent-3':'#8fbcbb' } },
  { id:'solarized', name:'Solarized', base:'dark', swatch:['#002b36','#073642','#268bd2'], vars:{
      'bg':'#002b36','bg-2':'#01212b','bg-3':'#073642','sidebar':'#01212b','panel':'#073642',
      'border':'#0d4552','border-2':'#155a6b','text':'#eee8d5','text-2':'#c3bda8','muted':'#93a1a1',
      'accent':'#268bd2','accent-2':'#d33682','accent-3':'#2aa198' } },
  { id:'forest', name:'Forest', base:'dark', swatch:['#12211c','#1a2f27','#4ade80'], vars:{
      'bg':'#12211c','bg-2':'#0d1915','bg-3':'#1a2f27','sidebar':'#0d1915','panel':'#1a2f27',
      'border':'#254036','border-2':'#2f5244','text':'#e4f0ea','text-2':'#b6ccc1','muted':'#84a294',
      'accent':'#4ade80','accent-2':'#facc15','accent-3':'#38bdf8' } },
  { id:'graphite', name:'Graphite', base:'light', swatch:['#f8fafc','#eef2f6','#0f766e'], vars:{
      'bg':'#f8fafc','bg-2':'#eef2f6','bg-3':'#e2e8f0','sidebar':'#f1f5f9','panel':'#ffffff',
      'border':'#e2e8f0','border-2':'#cbd5e1','text':'#0f172a','text-2':'#475569','muted':'#7c8899',
      'accent':'#0f766e','accent-2':'#0ea5e9','accent-3':'#14b8a6' } },
  { id:'rose', name:'Rose', base:'light', swatch:['#fffafc','#fdf0f5','#e11d74'], vars:{
      'bg':'#fffafc','bg-2':'#fdf0f5','bg-3':'#f9dfe9','sidebar':'#fdf5f8','panel':'#ffffff',
      'border':'#f5dde6','border-2':'#eec3d3','text':'#3d1f2c','text-2':'#6b4757','muted':'#9c7684',
      'accent':'#e11d74','accent-2':'#a855f7','accent-3':'#f97316' } },
  { id:'contrast', name:'High Contrast', base:'dark', swatch:['#000000','#111111','#ffd400'], vars:{
      'bg':'#000000','bg-2':'#0a0a0a','bg-3':'#1c1c1c','sidebar':'#000000','panel':'#0d0d0d',
      'border':'#3a3a3a','border-2':'#585858','text':'#ffffff','text-2':'#e0e0e0','muted':'#b5b5b5',
      'accent':'#ffd400','accent-2':'#00e5ff','accent-3':'#7cff6b' } }
];

const Theme = {
  get cfg(){ return cv2ThemeCfg(); },

  preset(id){ return THEMES.find(t => t.id === id) || THEMES[0]; },

  // mix two hex colors, t = 0..1 toward b
  mix(a, b, t){
    const p = h => { h = h.replace('#',''); if (h.length===3) h = h.split('').map(c=>c+c).join('');
      return [parseInt(h.slice(0,2),16), parseInt(h.slice(2,4),16), parseInt(h.slice(4,6),16)]; };
    const A = p(a), B = p(b);
    const c = A.map((v,i) => Math.round(v + (B[i]-v)*t));
    return '#' + c.map(v => Math.max(0,Math.min(255,v)).toString(16).padStart(2,'0')).join('');
  },

  // Build the full variable set for a custom theme from a few user choices.
  deriveCustom(c){
    const dark = c.base === 'dark';
    const toward = dark ? '#ffffff' : '#000000';
    const bg = c.bg, panel = c.panel, text = c.text;
    return {
      'bg': bg,
      'bg-2': this.mix(bg, toward, dark ? 0.03 : 0.03),
      'bg-3': this.mix(bg, toward, dark ? 0.09 : 0.07),
      'sidebar': c.sidebar,
      'panel': panel,
      'border': this.mix(bg, toward, dark ? 0.12 : 0.10),
      'border-2': this.mix(bg, toward, dark ? 0.20 : 0.18),
      'text': text,
      'text-2': this.mix(text, bg, 0.28),
      'muted': this.mix(text, bg, 0.48),
      'accent': c.accent,
      'accent-2': c.accent2 || c.accent,
      'accent-3': c.accent3 || c.accent
    };
  },

  resolved(){
    const cfg = this.cfg;
    if (cfg.preset === 'custom' && cfg.custom){
      return { base: cfg.custom.base, vars: this.deriveCustom(cfg.custom) };
    }
    const p = this.preset(cfg.preset);
    return { base: p.base, vars: p.vars };
  },

  apply(){
    const { base, vars } = this.resolved();
    const root = document.getElementById('cv2root');
    if (!root) return;
    root.setAttribute('data-theme', base);
    // clear any previously applied overrides so themes never bleed into each other
    THEME_VARS.forEach(v => root.style.removeProperty('--' + v));
    Object.keys(vars || {}).forEach(k => root.style.setProperty('--' + k, vars[k]));
  },

  set(presetId){
    this.cfg.preset = presetId;
    cv2SaveTheme();
    this.apply();
  },

  setCustom(custom){
    const cfg = this.cfg;
    cfg.custom = custom;
    cfg.preset = 'custom';
    cv2SaveTheme();
    this.apply();
  },

  // quick light/dark flip used by the T shortcut
  toggle(){
    const cur = this.resolved().base;
    this.set(cur === 'dark' ? 'light' : 'dark');
  },

  defaultCustom(){
    const r = this.resolved();
    const cs = getComputedStyle(document.getElementById('cv2root') || document.documentElement);
    const g = n => (r.vars && r.vars[n]) || cs.getPropertyValue('--' + n).trim() || '#000000';
    return {
      base: r.base,
      bg: g('bg'), panel: g('panel'), sidebar: g('sidebar'),
      text: g('text'), accent: g('accent'),
      accent2: g('accent-2'), accent3: g('accent-3')
    };
  }
};

const Brand = {
  get cfg(){ return cv2BrandCfg(); },
  set(patch){
    Object.assign(this.cfg, patch);
    cv2SaveBrand();
    this.apply();
  },
  apply(){
    const b = this.cfg;
    const name = (b.name || 'Vulnerability Manager').trim() || 'Vulnerability Manager';
    /* app title stays owned by the console */
    const nameEl = document.querySelector('.ws-name');
    const avEl = document.querySelector('.ws-avatar');
    if (nameEl){ nameEl.textContent = name; nameEl.title = name; }
    if (avEl){
      const ini = (b.icon && b.icon.trim()) ? b.icon.trim() : U.initials(name);
      avEl.textContent = ini.slice(0, 3);
      avEl.style.fontSize = ini.length > 2 ? '10px' : '11px';
    }
  }
};

/* ============================== views.js ================================= */
/* ===== views.js - all view renderers ===== */

const V = {

  // ---------- shared bits ----------
  avatars(t){
    const list = (t.assignees || []).map(id => Store.member(id)).filter(Boolean);
    if (!list.length) return '<span class="avatar sm" style="background:var(--bg-3);color:var(--muted);border-style:dashed">+</span>';
    return '<div class="avatar-stack">' + list.slice(0,3).map(m =>
      `<div class="avatar sm" style="background:${U.esc(m.color)}" title="${U.esc(m.name)}">${U.esc(U.initials(m.name))}</div>`
    ).join('') + (list.length > 3 ? `<div class="avatar sm" style="background:var(--gray)">+${list.length-3}</div>` : '') + '</div>';
  },

  prioIcon(t){
    if (!t.priority) return '<span class="prio" style="color:var(--border-2)" title="No priority">&#9873;</span>';
    const p = PRIORITIES[t.priority];
    return `<span class="prio ${p.cls}" title="${U.esc(p.name)}">&#9873;</span>`;
  },

  statusBadge(t){
    const s = Store.status(t.listId, t.statusId);
    return `<span class="status-badge" style="background:${U.esc(s.color)}">${U.esc(s.name)}</span>`;
  },

  tagsHtml(t){
    return (t.tags || []).map(tg =>
      `<span class="c2tag" style="background:${U.esc(tg.color)}22;color:${U.esc(tg.color)}">${U.esc(tg.name)}</span>`
    ).join('');
  },

  dueHtml(t){
    if (!t.dueDate) return '<span style="color:var(--border-2)">&mdash;</span>';
    return `<span class="due ${U.dueClass(t.dueDate)}">${U.esc(U.fmtDate(t.dueDate))}</span>`;
  },

  // ---------- filtering + sorting ----------
  applyFilters(tasks){
    const f = App.ui.filters;
    const q = (f.search || '').trim().toLowerCase();
    return tasks.filter(t => {
      if (!f.showClosed && Store.isDone(t)) return false;
      if (f.assignee && !(t.assignees || []).includes(f.assignee)) return false;
      if (f.priority && String(t.priority) !== String(f.priority)) return false;
      if (f.tag && !(t.tags || []).some(tg => tg.name === f.tag)) return false;
      if (f.due === 'overdue' && !(t.dueDate && U.daysBetween(U.today(), t.dueDate) < 0 && !Store.isDone(t))) return false;
      if (f.due === 'today' && t.dueDate !== U.today()) return false;
      if (f.due === 'week'){
        if (!t.dueDate) return false;
        const d = U.daysBetween(U.today(), t.dueDate);
        if (d < 0 || d > 7) return false;
      }
      if (f.due === 'none' && t.dueDate) return false;
      if (q){
        const hay = (t.name + ' ' + (t.description||'') + ' ' + (t.tags||[]).map(x=>x.name).join(' ')).toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  },

  sortTasks(tasks){
    const s = App.ui.sort;
    const arr = tasks.slice();
    const byDue = (a,b) => {
      if (!a.dueDate && !b.dueDate) return 0;
      if (!a.dueDate) return 1;
      if (!b.dueDate) return -1;
      return a.dueDate < b.dueDate ? -1 : a.dueDate > b.dueDate ? 1 : 0;
    };
    if (s === 'due') arr.sort(byDue);
    else if (s === 'priority') arr.sort((a,b) => (a.priority || 9) - (b.priority || 9) || byDue(a,b));
    else if (s === 'name') arr.sort((a,b) => a.name.localeCompare(b.name));
    else if (s === 'updated') arr.sort((a,b) => (b.updatedAt||0) - (a.updatedAt||0));
    else if (s === 'created') arr.sort((a,b) => (b.createdAt||0) - (a.createdAt||0));
    else arr.sort((a,b) => (a.order||0) - (b.order||0));
    return arr;
  },

  groupTasks(tasks, listId){
    const g = App.ui.group;
    const out = [];
    if (g === 'none'){
      out.push({ key:'all', label:'All Tasks', color:'var(--gray)', tasks });
      return out;
    }
    if (g === 'status'){
      const sts = listId ? Store.statusesFor(listId) : Store.statusesFor(Store.state.lists[0] && Store.state.lists[0].id);
      sts.forEach(s => out.push({
        key:s.id, label:s.name, color:s.color,
        tasks: tasks.filter(t => Store.status(t.listId, t.statusId).name === s.name)
      }));
      return out;
    }
    if (g === 'assignee'){
      const none = tasks.filter(t => !(t.assignees||[]).length);
      Store.state.members.forEach(m => {
        const mine = tasks.filter(t => (t.assignees||[]).includes(m.id));
        if (mine.length) out.push({ key:m.id, label:m.name, color:m.color, tasks:mine });
      });
      if (none.length) out.push({ key:'none', label:'Unassigned', color:'var(--gray)', tasks:none });
      return out;
    }
    if (g === 'priority'){
      [1,2,3,4].forEach(p => {
        const mine = tasks.filter(t => t.priority === p);
        if (mine.length) out.push({ key:'p'+p, label:PRIORITIES[p].name, color:PRIORITIES[p].color, tasks:mine });
      });
      const none = tasks.filter(t => !t.priority);
      if (none.length) out.push({ key:'pnone', label:'No Priority', color:'var(--gray)', tasks:none });
      return out;
    }
    if (g === 'list'){
      const map = new Map();
      tasks.forEach(t => { if (!map.has(t.listId)) map.set(t.listId, []); map.get(t.listId).push(t); });
      map.forEach((arr, lid) => {
        const l = Store.list(lid);
        const sp = l ? Store.space(l.spaceId) : null;
        out.push({ key:lid, label: l ? l.name : 'Unknown', color: sp ? sp.color : 'var(--gray)', tasks:arr });
      });
      return out;
    }
    if (g === 'due'){
      const buckets = [
        { key:'over',  label:'Overdue',    color:'var(--red)',   test:t => t.dueDate && U.daysBetween(U.today(), t.dueDate) < 0 },
        { key:'today', label:'Today',      color:'var(--amber)', test:t => t.dueDate === U.today() },
        { key:'week',  label:'Next 7 Days',color:'var(--blue)',  test:t => t.dueDate && U.daysBetween(U.today(), t.dueDate) > 0 && U.daysBetween(U.today(), t.dueDate) <= 7 },
        { key:'later', label:'Later',      color:'var(--accent)',test:t => t.dueDate && U.daysBetween(U.today(), t.dueDate) > 7 },
        { key:'nodate',label:'No Due Date',color:'var(--gray)',  test:t => !t.dueDate }
      ];
      buckets.forEach(b => {
        const mine = tasks.filter(b.test);
        if (mine.length) out.push({ key:b.key, label:b.label, color:b.color, tasks:mine });
      });
      return out;
    }
    return [{ key:'all', label:'All', color:'var(--gray)', tasks }];
  },

  // ---------- LIST VIEW ----------
  taskRow(t, indent){
    const done = Store.isDone(t);
    const subs = Store.subtasks(t.id);
    const doneSubs = subs.filter(s => Store.isDone(s)).length;
    const l = Store.list(t.listId);
    return `
      <div class="trow ${done ? 'done' : ''}" data-task="${U.esc(t.id)}" data-ctx="task">
        <div class="checkbox ${done ? 'on' : ''}" data-act="toggle" data-id="${U.esc(t.id)}" title="Mark complete">&#10003;</div>
        <div class="t-name" style="padding-left:${(indent||0) * 18}px">
          ${subs.length ? `<span class="group-caret ${App.ui.openSubs[t.id] ? 'open' : ''}" data-act="subs" data-id="${U.esc(t.id)}" style="cursor:pointer">&#9654;</span>` : ''}
          <span class="nm">${U.esc(t.name)}</span>
          ${subs.length ? `<span class="subcount">${doneSubs}/${subs.length}</span>` : ''}
          ${t.comments && t.comments.length ? `<span class="subcount" title="${t.comments.length} comments">&#128172; ${t.comments.length}</span>` : ''}
          ${this.tagsHtml(t)}
        </div>
        <div class="cell hide-sm">${this.statusBadge(t)}</div>
        <div class="cell hide-sm">${this.avatars(t)}${App.route.name !== 'list' && l ? `<span style="font-size:11px;color:var(--muted);margin-left:4px">${U.esc(l.name)}</span>` : ''}</div>
        <div class="cell">${this.dueHtml(t)}</div>
        <div class="cell hide-sm">${t.timeEstimate ? U.esc(U.dur(t.timeEstimate)) : '<span style="color:var(--border-2)">&mdash;</span>'}</div>
        <div class="cell">${this.prioIcon(t)}</div>
      </div>`;
  },

  renderList(tasks, listId){
    const groups = this.groupTasks(this.sortTasks(tasks), listId);
    let html = `<div class="thead">
        <div></div><div>Name</div><div class="hide-sm">Status</div><div class="hide-sm">Assignee</div>
        <div>Due date</div><div class="hide-sm">Estimate</div><div>Priority</div>
      </div>`;

    const total = groups.reduce((n,g) => n + g.tasks.length, 0);
    if (!total) return html + this.emptyState(listId);

    groups.forEach(g => {
      if (!g.tasks.length && App.ui.group === 'status' && !App.ui.filters.showClosed) { /* still show, allows adding */ }
      const open = App.ui.closedGroups[g.key] !== true;
      html += `<div class="group">
        <div class="group-head" data-act="group" data-key="${U.esc(g.key)}">
          <span class="group-caret ${open ? 'open' : ''}">&#9654;</span>
          <span class="status-badge" style="background:${U.esc(g.color)}">${U.esc(g.label)}</span>
          <span class="group-count">${g.tasks.length}</span>
        </div>`;
      if (open){
        g.tasks.forEach(t => {
          html += this.taskRow(t, 0);
          if (App.ui.openSubs[t.id]){
            Store.subtasks(t.id).forEach(s => { html += this.taskRow(s, 1); });
          }
        });
        if (listId){
          html += `<div class="addrow" data-act="quickadd" data-list="${U.esc(listId)}" data-status="${U.esc(App.ui.group === 'status' ? g.key : '')}">
            <span>+</span><span>Add task</span></div>`;
        }
      }
      html += `</div>`;
    });
    return html;
  },

  emptyState(listId){
    return `<div class="empty">
      <div class="big">&#128203;</div>
      <h4>Nothing here yet</h4>
      <p>No tasks match your filters.</p>
      ${listId ? `<button class="btn primary" data-act="quickadd" data-list="${U.esc(listId)}">+ Add a task</button>` : ''}
    </div>`;
  },

  // ---------- BOARD ----------
  renderBoard(tasks, listId){
    const sorted = this.sortTasks(tasks);
    let cols;
    if (App.ui.group === 'status' || !listId){
      const sts = Store.statusesFor(listId || (Store.state.lists[0]||{}).id);
      cols = sts.map(s => ({ key:s.id, label:s.name, color:s.color,
        tasks: sorted.filter(t => Store.status(t.listId, t.statusId).name === s.name) }));
    } else {
      cols = this.groupTasks(sorted, listId);
    }

    return '<div class="board">' + cols.map(c => `
      <div class="bcol" data-col="${U.esc(c.key)}">
        <div class="bcol-head">
          <span class="status-badge" style="background:${U.esc(c.color)}">${U.esc(c.label)}</span>
          <span class="group-count">${c.tasks.length}</span>
        </div>
        <div class="bcol-body" data-drop="${U.esc(c.key)}">
          ${c.tasks.map(t => this.card(t)).join('')}
        </div>
        ${listId ? `<div class="bcol-add" data-act="quickadd" data-list="${U.esc(listId)}" data-status="${U.esc(c.key)}">+ Add task</div>` : ''}
      </div>`).join('') + '</div>';
  },

  card(t){
    const subs = Store.subtasks(t.id);
    const doneSubs = subs.filter(s => Store.isDone(s)).length;
    const l = Store.list(t.listId);
    return `<div class="card" draggable="true" data-task="${U.esc(t.id)}" data-ctx="task">
      ${t.tags && t.tags.length ? `<div class="card-tags">${this.tagsHtml(t)}</div>` : ''}
      <div class="card-top">
        <div class="checkbox ${Store.isDone(t) ? 'on' : ''}" data-act="toggle" data-id="${U.esc(t.id)}">&#10003;</div>
        <div class="card-name">${U.esc(t.name)}</div>
      </div>
      <div class="card-meta">
        ${this.prioIcon(t)}
        ${t.dueDate ? this.dueHtml(t) : ''}
        ${subs.length ? `<span class="subcount">&#9776; ${doneSubs}/${subs.length}</span>` : ''}
        ${t.checklist && t.checklist.length ? `<span class="subcount">&#10003; ${t.checklist.filter(c=>c.done).length}/${t.checklist.length}</span>` : ''}
        ${App.route.name !== 'list' && l ? `<span class="subcount">${U.esc(l.name)}</span>` : ''}
        <span style="margin-left:auto">${this.avatars(t)}</span>
      </div>
    </div>`;
  },

  // ---------- TABLE ----------
  renderTable(tasks){
    const sorted = this.sortTasks(tasks);
    if (!sorted.length) return this.emptyState(App.route.listId);
    let html = `<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead><tr>
        ${['Task','List','Status','Assignees','Start','Due','Est','Tracked','Priority','Tags'].map(h =>
          `<th style="text-align:left;padding:9px 12px;border-bottom:1px solid var(--border);font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);white-space:nowrap">${h}</th>`).join('')}
      </tr></thead><tbody>`;
    sorted.forEach(t => {
      const l = Store.list(t.listId);
      html += `<tr data-task="${U.esc(t.id)}" data-ctx="task" style="cursor:pointer;border-bottom:1px solid var(--border)">
        <td style="padding:8px 12px;max-width:340px"><div style="display:flex;align-items:center;gap:8px">
          <div class="checkbox ${Store.isDone(t)?'on':''}" data-act="toggle" data-id="${U.esc(t.id)}">&#10003;</div>
          <span style="${Store.isDone(t)?'text-decoration:line-through;color:var(--muted)':''}">${U.esc(t.name)}</span></div></td>
        <td style="padding:8px 12px;color:var(--text-2);white-space:nowrap">${U.esc(l ? l.name : '')}</td>
        <td style="padding:8px 12px">${this.statusBadge(t)}</td>
        <td style="padding:8px 12px">${this.avatars(t)}</td>
        <td style="padding:8px 12px;color:var(--text-2);white-space:nowrap">${t.startDate ? U.esc(U.fmtDate(t.startDate)) : '&mdash;'}</td>
        <td style="padding:8px 12px;white-space:nowrap">${this.dueHtml(t)}</td>
        <td style="padding:8px 12px;color:var(--text-2);white-space:nowrap">${U.esc(U.dur(t.timeEstimate)) || '&mdash;'}</td>
        <td style="padding:8px 12px;color:var(--text-2);white-space:nowrap">${U.esc(U.dur(t.timeSpent)) || '&mdash;'}</td>
        <td style="padding:8px 12px">${this.prioIcon(t)} <span style="font-size:12px;color:var(--text-2)">${t.priority ? U.esc(PRIORITIES[t.priority].name) : ''}</span></td>
        <td style="padding:8px 12px">${this.tagsHtml(t)}</td>
      </tr>`;
    });
    return html + '</tbody></table></div>';
  },

  // ---------- CALENDAR ----------
  renderCalendar(tasks){
    const cur = App.ui.calMonth || U.today().slice(0,7);
    const [y, m] = cur.split('-').map(Number);
    const first = new Date(y, m-1, 1);
    const startOffset = first.getDay();
    const gridStart = new Date(y, m-1, 1 - startOffset);
    const monthName = first.toLocaleDateString(undefined, { month:'long', year:'numeric' });

    const byDate = new Map();
    tasks.forEach(t => {
      if (!t.dueDate) return;
      if (!byDate.has(t.dueDate)) byDate.set(t.dueDate, []);
      byDate.get(t.dueDate).push(t);
    });

    let cells = '';
    for (let i = 0; i < 42; i++){
      const d = new Date(gridStart.getFullYear(), gridStart.getMonth(), gridStart.getDate() + i);
      const key = U.ymd(d);
      const other = d.getMonth() !== m-1;
      const isToday = key === U.today();
      const dayTasks = (byDate.get(key) || []).slice(0, 4);
      const more = (byDate.get(key) || []).length - dayTasks.length;
      cells += `<div class="cal-cell ${other?'other':''} ${isToday?'today':''}" data-act="calday" data-date="${key}">
        <div class="cal-dnum">${d.getDate()}</div>
        ${dayTasks.map(t => {
          const s = Store.status(t.listId, t.statusId);
          return `<div class="cal-task" data-task="${U.esc(t.id)}" style="border-left-color:${U.esc(s.color)}" title="${U.esc(t.name)}">${U.esc(t.name)}</div>`;
        }).join('')}
        ${more > 0 ? `<div style="font-size:10.5px;color:var(--muted);font-weight:650">+${more} more</div>` : ''}
      </div>`;
    }

    return `<div class="cal">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
        <button class="btn ghost sm" data-act="calprev">&#8249;</button>
        <button class="btn ghost sm" data-act="caltoday">Today</button>
        <button class="btn ghost sm" data-act="calnext">&#8250;</button>
        <h3 style="margin:0 0 0 6px;font-size:16px">${U.esc(monthName)}</h3>
        <span style="color:var(--muted);font-size:12.5px">${byDate.size} day(s) with due tasks</span>
      </div>
      <div class="cal-head">${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map(d => `<div class="cal-dow">${d}</div>`).join('')}</div>
      <div class="cal-grid">${cells}</div>
    </div>`;
  },

  // ---------- GANTT ----------
  renderGantt(tasks){
    const dated = this.sortTasks(tasks).filter(t => t.startDate || t.dueDate);
    if (!dated.length) return `<div class="empty"><div class="big">&#128197;</div><h4>No scheduled tasks</h4>
      <p>Add a start date or due date to a task and it will appear on the timeline.</p></div>`;

    let min = null, max = null;
    dated.forEach(t => {
      const s = t.startDate || t.dueDate, e = t.dueDate || t.startDate;
      if (!min || s < min) min = s;
      if (!max || e > max) max = e;
    });
    min = U.addDays(min, -3);
    max = U.addDays(max, 3);
    let span = U.daysBetween(min, max) + 1;
    if (span > 200){ span = 200; max = U.addDays(min, 199); }
    const DAY = 34;
    const todayIdx = U.daysBetween(min, U.today());

    let days = '', grid = '';
    for (let i = 0; i < span; i++){
      const d = U.parse(U.addDays(min, i));
      const wk = d.getDay() === 0 || d.getDay() === 6;
      const isToday = i === todayIdx;
      days += `<div class="g-day ${wk?'wk':''} ${isToday?'today':''}">
        <div>${d.toLocaleDateString(undefined,{weekday:'narrow'})}</div><div>${d.getDate()}</div></div>`;
      grid += `<div class="g-gcol ${wk?'wk':''}"></div>`;
    }

    const rows = dated.map(t => {
      const s = t.startDate || t.dueDate;
      const e = t.dueDate || t.startDate;
      const off = Math.max(0, U.daysBetween(min, s));
      const len = Math.max(1, U.daysBetween(s, e) + 1);
      const st = Store.status(t.listId, t.statusId);
      const pct = t.timeEstimate ? Math.min(100, Math.round((t.timeSpent||0) / t.timeEstimate * 100)) : null;
      return `<div class="g-row" data-task="${U.esc(t.id)}">
        <div class="g-bar" data-task="${U.esc(t.id)}" style="left:${off*DAY+3}px;width:${len*DAY-6}px;background:${U.esc(st.color)}"
             title="${U.esc(t.name)} &#183; ${U.esc(U.fmtDate(s))} to ${U.esc(U.fmtDate(e))}">
          ${U.esc(t.name)}${pct !== null ? ` &#183; ${pct}%` : ''}
        </div></div>`;
    }).join('');

    const left = dated.map(t => `<div class="g-lrow" data-task="${U.esc(t.id)}">
        ${this.prioIcon(t)}<span class="nm">${U.esc(t.name)}</span></div>`).join('');

    return `<div class="gantt"><div class="g-wrap">
      <div class="g-left"><div class="g-lh">Task</div>${left}</div>
      <div class="g-right" style="width:${span*DAY}px">
        <div class="g-days">${days}</div>
        <div class="g-grid">${grid}</div>
        ${rows}
      </div>
    </div></div>`;
  },

  // ---------- HOME ----------
  renderHome(){
    const all = Store.allTasks().filter(t => !t.parentId);
    const mine = all.filter(t => (t.assignees||[]).includes(Store.me));
    const open = all.filter(t => !Store.isDone(t));
    const overdue = open.filter(t => t.dueDate && U.daysBetween(U.today(), t.dueDate) < 0);
    const todayT = open.filter(t => t.dueDate === U.today());
    const week = open.filter(t => t.dueDate && U.daysBetween(U.today(), t.dueDate) > 0 && U.daysBetween(U.today(), t.dueDate) <= 7);
    const done = all.filter(t => Store.isDone(t));
    const pct = all.length ? Math.round(done.length / all.length * 100) : 0;

    const miniList = (arr, emptyMsg) => arr.length
      ? arr.slice(0,7).map(t => {
          const l = Store.list(t.listId);
          return `<div class="mini-row" data-task="${U.esc(t.id)}">
            ${this.prioIcon(t)}<span class="nm">${U.esc(t.name)}</span>
            <span style="font-size:11px;color:var(--muted)">${U.esc(l?l.name:'')}</span>
            ${t.dueDate ? this.dueHtml(t) : ''}</div>`;
        }).join('')
      : `<div style="color:var(--muted);font-size:13px;padding:8px 0">${U.esc(emptyMsg)}</div>`;

    // workload by member
    const workload = Store.state.members.map(m => ({
      m, n: open.filter(t => (t.assignees||[]).includes(m.id)).length
    })).sort((a,b) => b.n - a.n);
    const maxW = Math.max(1, ...workload.map(w => w.n));

    // status breakdown across the workspace
    const stMap = new Map();
    open.concat(done).forEach(t => {
      const s = Store.status(t.listId, t.statusId);
      const k = s.name;
      if (!stMap.has(k)) stMap.set(k, { name:s.name, color:s.color, n:0 });
      stMap.get(k).n++;
    });
    const stArr = Array.from(stMap.values()).sort((a,b) => b.n - a.n);
    const stTotal = stArr.reduce((n,s) => n + s.n, 0) || 1;

    return `
    <div style="padding:18px 18px 0">
      <h2 style="margin:0 0 4px;font-size:22px">Good to see you, ${U.esc(((Store.member(Store.me)||{}).name || 'there').split(' ')[0])}</h2>
      <p style="margin:0 0 16px;color:var(--muted);font-size:13.5px">${U.esc(new Date().toLocaleDateString(undefined,{weekday:'long',month:'long',day:'numeric'}))}</p>
      <div class="stat-row">
        <div class="c2stat"><div class="n">${open.length}</div><div class="l">Open tasks</div></div>
        <div class="c2stat"><div class="n" style="color:var(--red)">${overdue.length}</div><div class="l">Overdue</div></div>
        <div class="c2stat"><div class="n" style="color:var(--amber)">${todayT.length}</div><div class="l">Due today</div></div>
        <div class="c2stat"><div class="n" style="color:var(--blue)">${mine.filter(t=>!Store.isDone(t)).length}</div><div class="l">Assigned to me</div></div>
        <div class="c2stat"><div class="n" style="color:var(--green)">${pct}%</div><div class="l">Complete
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:var(--green)"></div></div></div></div>
      </div>
    </div>
    <div class="dash">
      <div class="card-panel"><h3>&#128293; Overdue</h3>${miniList(overdue, 'Nothing overdue. Nice.')}</div>
      <div class="card-panel"><h3>&#9203; Due this week</h3>${miniList(week.concat(todayT), 'No due dates in the next seven days.')}</div>
      <div class="card-panel"><h3>&#128100; My open tasks</h3>${miniList(mine.filter(t=>!Store.isDone(t)), 'You are all clear.')}</div>
      <div class="card-panel"><h3>&#128202; Status breakdown</h3>
        <div class="legend">${stArr.map(s => `
          <div class="legend-item"><span class="sw" style="background:${U.esc(s.color)}"></span>${U.esc(s.name)}
            <span class="v">${s.n}</span></div>
          <div class="bar-track" style="margin-top:-3px"><div class="bar-fill" style="width:${Math.round(s.n/stTotal*100)}%;background:${U.esc(s.color)}"></div></div>
        `).join('')}</div>
      </div>
      <div class="card-panel"><h3>&#128101; Workload</h3>
        ${workload.map(w => `
          <div class="legend-item" style="margin-bottom:3px">
            <span class="avatar sm" style="background:${U.esc(w.m.color)}">${U.esc(U.initials(w.m.name))}</span>
            ${U.esc(w.m.name)}<span class="v">${w.n}</span></div>
          <div class="bar-track" style="margin-bottom:9px"><div class="bar-fill" style="width:${Math.round(w.n/maxW*100)}%;background:${U.esc(w.m.color)}"></div></div>
        `).join('')}
      </div>
      <div class="card-panel"><h3>&#128193; Lists</h3>
        ${Store.state.lists.map(l => {
          const ts = Store.tasksIn(l.id);
          const d = ts.filter(t => Store.isDone(t)).length;
          const p = ts.length ? Math.round(d/ts.length*100) : 0;
          const sp = Store.space(l.spaceId);
          return `<div class="mini-row" data-act="goto" data-list="${U.esc(l.id)}">
            <span class="sw" style="width:9px;height:9px;border-radius:3px;background:${U.esc(sp?sp.color:'var(--gray)')}"></span>
            <span class="nm">${U.esc(l.name)}</span>
            <span style="font-size:11.5px;color:var(--muted);font-weight:650">${d}/${ts.length}</span>
            <div class="bar-track" style="width:64px;margin:0"><div class="bar-fill" style="width:${p}%;background:var(--accent)"></div></div>
          </div>`;
        }).join('')}
      </div>
    </div>`;
  },

  // ---------- FINDINGS ----------
  renderFindings(){
    const rows = App.findingsCache || [];
    const excs = App.exceptionsCache || [];
    if (!rows.length){
      return `<div class="empty">
        <div class="big">&#128269;</div>
        <h4>No scan data imported yet</h4>
        <p>Import a Tenable VM export to populate findings.<br>
           Findings are stored in IndexedDB, separately from your campaign tasks.</p>
        <button class="btn primary" data-act="open-import">Import a scan</button>
      </div>`;
    }
    const f = App.ui.findingFilters || {};
    const today = U.today();
    let list = rows.filter(r => {
      const ev = Exceptions.evaluate(r, excs, today);
      r._suppressed = ev.suppressed; r._exc = ev.winner;
      if (!f.showSuppressed && ev.suppressed) return false;
      if (f.state && r.detectionState !== f.state) return false;
      if (!f.showClosed && !Lifecycle.isOpen(r)) return false;
      if (f.q){
        const q = f.q.toLowerCase();
        if (!((r.name||'') + ' ' + (r.assetHostname||'') + ' ' + (r.cve||[]).join(' ')).toLowerCase().includes(q)) return false;
      }
      return true;
    });
    list.sort((a,b) => (a.priority||9)-(b.priority||9) || (b.lastSeen||0)-(a.lastSeen||0));
    const shown = list.slice(0, 300);

    const stateColor = { NEW:'#7b68ee', ACTIVE:'#49ccf9', REOPENED:'#e8506e',
                         FIXED:'#2ecc8f', STALE:'#f5a623', RETIRED:'#7c8899' };

    return `<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead><tr>${['Finding','Asset','State','Severity','CVE','First seen','SLA','Exception']
        .map(h=>`<th style="text-align:left;padding:9px 12px;border-bottom:1px solid var(--border);font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);white-space:nowrap">${h}</th>`).join('')}
      </tr></thead><tbody>
      ${shown.map(r => {
        const overdue = r.slaDueAt && U.daysBetween(today, r.slaDueAt) < 0 && Lifecycle.isOpen(r);
        return `<tr data-finding="${U.esc(r.findingUid)}" style="cursor:pointer;border-bottom:1px solid var(--border);${r._suppressed?'opacity:.55':''}">
          <td style="padding:8px 12px;max-width:420px">
            <div style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${U.esc(r.name || r.checkId)}</div>
            <div style="font-size:11px;color:var(--muted)">${U.esc(r.source)} &#183; check ${U.esc(r.checkId)} &#183; ${U.esc(r.locator)}</div>
          </td>
          <td style="padding:8px 12px;white-space:nowrap">${U.esc(r.assetHostname || r.assetKey.slice(0,12))}</td>
          <td style="padding:8px 12px"><span class="status-badge" style="background:${stateColor[r.detectionState]||'#868a96'}">${U.esc(r.detectionState)}</span>
            ${r.timesReopened ? `<span class="subcount" title="reopened ${r.timesReopened}x">&#8635;${r.timesReopened}</span>` : ''}</td>
          <td style="padding:8px 12px">${V.prioIcon(r)} <span style="font-size:12px">${U.esc(r.severity||'')}</span></td>
          <td style="padding:8px 12px;font-size:11.5px;color:var(--text-2);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${U.esc((r.cve||[]).join(', ')) || '&mdash;'}</td>
          <td style="padding:8px 12px;white-space:nowrap;font-size:12px;color:var(--text-2)">${r.firstSeen ? U.esc(U.fmtDate(U.ymd(new Date(r.firstSeen)))) : '&mdash;'}</td>
          <td style="padding:8px 12px;white-space:nowrap">${r.slaDueAt ? `<span class="due ${overdue?'over':''}">${U.esc(U.fmtDate(r.slaDueAt))}</span>` : '&mdash;'}</td>
          <td style="padding:8px 12px;white-space:nowrap">${r._exc
              ? `<span class="c2tag" style="background:var(--amber)22;color:var(--amber)" title="${U.esc(r._exc.reasonText||'')}">${U.esc(EXCEPTION_TYPES[r._exc.type].label)} &#183; to ${U.esc(r._exc.expiresAt)}</span>`
              : `<button class="btn ghost sm" data-act="add-exception" data-id="${U.esc(r.findingUid)}">Accept risk</button>`}</td>
        </tr>`;
      }).join('')}
      </tbody></table>
      ${list.length > shown.length ? `<div style="padding:12px;color:var(--muted);font-size:12.5px">Showing ${shown.length} of ${list.length}. Narrow the filters to see the rest.</div>` : ''}
      </div>`;
  },

  // ---------- REMEDIATIONS ----------
  renderRemediations(){
    const rows = App.remediationsCache || [];
    if (!rows.length){
      return `<div class="empty"><div class="big">&#128736;</div><h4>No remediation work yet</h4>
        <p>Remediations appear automatically once findings are imported.<br>
        One fix action becomes one item, however many assets it touches.</p></div>`;
    }
    const f = App.ui.remFilters || {};
    const list = rows.filter(r => f.showDone ? true : r.derivedState !== 'DONE');
    const stateColor = { TODO:'#868a96', IN_PROGRESS:'#49ccf9', AWAITING_VERIFICATION:'#f5a623',
                         DONE:'#2ecc8f', WONT_DO:'#7c8899', STALLED_UNVERIFIED:'#e8506e' };

    return list.map(r => {
      const open = App.ui.openRem && App.ui.openRem[r.key];
      return `<div class="group" style="border-bottom:1px solid var(--border)">
        <div class="group-head" data-act="rem-toggle" data-key="${U.esc(r.key)}" style="gap:12px">
          <span class="group-caret ${open?'open':''}">&#9654;</span>
          ${V.prioIcon(r)}
          <div style="flex:1;min-width:0">
            <div style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${U.esc(r.title)}</div>
            <div style="font-size:11.5px;color:var(--muted)">
              ${r.assets} asset${r.assets===1?'':'s'} &#183; ${r.counts.total} finding${r.counts.total===1?'':'s'}
              &#183; ${r.groupList.length} team${r.groupList.length===1?'':'s'}
              ${r.cve.length ? ' &#183; ' + U.esc(r.cve.join(', ')) : ''}
            </div>
          </div>
          ${r.regressed ? '<span class="c2tag" style="background:var(--red)22;color:var(--red)">regressed</span>' : ''}
          ${r.counts.suppressed ? `<span class="c2tag" style="background:var(--amber)22;color:var(--amber)">${r.counts.suppressed} accepted</span>` : ''}
          <div style="width:150px">
            <div class="progress-lbl"><span>${r.counts.fixed}/${r.counts.total} fixed</span><span>${r.counts.pct}%</span></div>
            <div class="bar-track"><div class="bar-fill" style="width:${r.counts.pct}%;background:${r.counts.pct===100?'var(--green)':'var(--accent)'}"></div></div>
          </div>
          ${r.dueAt ? `<span class="due ${r.overdue?'over':''}" style="width:86px;text-align:center">${U.esc(U.fmtDate(r.dueAt))}</span>` : '<span style="width:86px"></span>'}
          <span class="status-badge" style="background:${stateColor[r.derivedState]||'#868a96'}">${U.esc(r.derivedState.replace(/_/g,' '))}</span>
        </div>
        ${open ? `<div style="padding:0 18px 12px 46px">
          ${r.groupList.map(g => `
            <div style="display:flex;align-items:center;gap:12px;padding:9px 0;border-bottom:1px solid var(--border)">
              <span class="ico-sm">&#128101;</span>
              <div style="flex:1;min-width:0">
                <div style="font-size:13.5px;font-weight:550">${U.esc(g.name)}</div>
                <div style="font-size:11.5px;color:var(--muted)">${g.assets} asset${g.assets===1?'':'s'} &#183; ${g.counts.total} finding${g.counts.total===1?'':'s'}${g.counts.reopened?' &#183; '+g.counts.reopened+' regressed':''}</div>
              </div>
              <div style="width:130px">
                <div class="progress-lbl"><span>${g.counts.fixed}/${g.counts.total}</span><span>${g.counts.pct}%</span></div>
                <div class="bar-track"><div class="bar-fill" style="width:${g.counts.pct}%;background:${g.counts.pct===100?'var(--green)':'var(--accent-3)'}"></div></div>
              </div>
              <select class="sel" data-act="rem-group-assign" data-key="${U.esc(r.key)}" data-group="${U.esc(g.name)}" style="width:120px">
                <option value="">Unassigned</option>
                ${Store.state.members.map(m=>`<option value="${U.esc(m.id)}" ${g.assignee===m.id?'selected':''}>${U.esc(m.name)}</option>`).join('')}
              </select>
              <span class="status-badge" style="background:${stateColor[g.derivedState]||'#868a96'}">${U.esc(g.derivedState.replace(/_/g,' '))}</span>
            </div>`).join('')}
          <div style="padding-top:10px;font-size:12px;color:var(--muted)">
            Progress is computed from the findings underneath. Marking work done by hand does not
            close a finding; only a scan that no longer reports it does.
          </div>
        </div>` : ''}
      </div>`;
    }).join('') + (rows.length > list.length
      ? `<div style="padding:14px 18px;color:var(--muted);font-size:12.5px">${rows.length-list.length} completed remediation(s) hidden.</div>` : '');
  },

  // ---------- DASHBOARD ----------
  renderDashboard(){
    const all = Store.allTasks();
    const open = all.filter(t => !Store.isDone(t));
    const est = all.reduce((n,t) => n + (t.timeEstimate||0), 0);
    const spent = all.reduce((n,t) => n + (t.timeSpent||0), 0);

    // burn-down style: completions over the last 14 days by updatedAt
    const days = [];
    for (let i = 13; i >= 0; i--){
      const key = U.addDays(U.today(), -i);
      const n = all.filter(t => Store.isDone(t) && U.ymd(new Date(t.updatedAt || 0)) === key).length;
      days.push({ key, n });
    }
    const maxD = Math.max(1, ...days.map(d => d.n));

    const prioCount = [1,2,3,4].map(p => ({ p, n: open.filter(t => t.priority === p).length }));
    const maxP = Math.max(1, ...prioCount.map(x => x.n));

    const spaceRows = Store.state.spaces.map(sp => {
      const lists = Store.listsInSpace(sp.id);
      const ts = lists.flatMap(l => Store.tasksIn(l.id));
      const d = ts.filter(t => Store.isDone(t)).length;
      return { sp, total: ts.length, done: d, pct: ts.length ? Math.round(d/ts.length*100) : 0 };
    });

    return `<div class="dash">
      <div class="card-panel" style="grid-column:1/-1">
        <h3>&#128200; Completed in the last 14 days</h3>
        <div style="display:flex;align-items:flex-end;gap:6px;height:130px">
          ${days.map(d => `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:5px" title="${U.esc(d.key)}: ${d.n}">
            <div style="font-size:10.5px;color:var(--muted);font-weight:700">${d.n || ''}</div>
            <div style="width:100%;height:${Math.round(d.n/maxD*88)+3}px;background:linear-gradient(180deg,var(--accent),#9a8cf5);border-radius:4px 4px 2px 2px"></div>
            <div style="font-size:9.5px;color:var(--muted)">${U.parse(d.key).getDate()}</div>
          </div>`).join('')}
        </div>
      </div>
      <div class="card-panel"><h3>&#9201; Time</h3>
        <div class="stat-row" style="grid-template-columns:1fr 1fr">
          <div><div class="n" style="font-size:22px;font-weight:750">${U.esc(U.dur(est) || '0m')}</div><div class="l">Estimated</div></div>
          <div><div class="n" style="font-size:22px;font-weight:750">${U.esc(U.dur(spent) || '0m')}</div><div class="l">Tracked</div></div>
        </div>
        <div class="bar-track" style="margin-top:12px"><div class="bar-fill" style="width:${est ? Math.min(100, Math.round(spent/est*100)) : 0}%;background:var(--accent-3)"></div></div>
        <div class="progress-lbl" style="margin-top:5px"><span>Tracked vs estimated</span><span>${est ? Math.round(spent/est*100) : 0}%</span></div>
      </div>
      <div class="card-panel"><h3>&#9873; Open by priority</h3>
        ${prioCount.map(x => `
          <div class="legend-item" style="margin-bottom:3px"><span class="sw" style="background:${PRIORITIES[x.p].color}"></span>
            ${U.esc(PRIORITIES[x.p].name)}<span class="v">${x.n}</span></div>
          <div class="bar-track" style="margin-bottom:9px"><div class="bar-fill" style="width:${Math.round(x.n/maxP*100)}%;background:${PRIORITIES[x.p].color}"></div></div>
        `).join('')}
      </div>
      <div class="card-panel"><h3>&#128506; Spaces</h3>
        ${spaceRows.map(r => `
          <div class="legend-item" style="margin-bottom:3px"><span class="sw" style="background:${U.esc(r.sp.color)}"></span>
            ${U.esc(r.sp.name)}<span class="v">${r.done}/${r.total}</span></div>
          <div class="bar-track" style="margin-bottom:9px"><div class="bar-fill" style="width:${r.pct}%;background:${U.esc(r.sp.color)}"></div></div>
        `).join('')}
      </div>
    </div>`;
  }
};

/* ============================== drawer.js =============================== */
/* ===== drawer.js - task detail panel ===== */

const Drawer = {
  taskId: null,

  open(id){
    const t = Store.task(id);
    if (!t) return;
    this.taskId = id;
    document.getElementById('cv2drawerScrim').classList.remove('hidden');
    const el = document.getElementById('cv2drawer');
    el.classList.remove('hidden');
    this.render();
  },

  close(){
    this.taskId = null;
    document.getElementById('cv2drawer').classList.add('hidden');
    document.getElementById('cv2drawerScrim').classList.add('hidden');
  },

  get task(){ return this.taskId ? Store.task(this.taskId) : null; },

  render(){
    const t = this.task;
    if (!t) return this.close();
    const el = document.getElementById('cv2drawer');
    const list = Store.list(t.listId);
    const path = Store.listPath(t.listId).map(x => U.esc(x.name)).join(' <span class="sep">/</span> ');
    const statuses = Store.statusesFor(t.listId);
    const parent = t.parentId ? Store.task(t.parentId) : null;
    const subs = Store.subtasks(t.id);
    const chkDone = t.checklist.filter(c => c.done).length;
    const timer = Store.state.meta.timer;
    const running = timer && timer.taskId === t.id;
    const pct = t.timeEstimate ? Math.min(100, Math.round((t.timeSpent||0) / t.timeEstimate * 100)) : null;

    el.innerHTML = `
      <div class="dw-head">
        <button class="icon-btn" data-dw="close" title="Close (Esc)">&#10005;</button>
        <div class="dw-crumb">${path}${parent ? ` <span class="sep">/</span> ${U.esc(parent.name)}` : ''}</div>
        <button class="icon-btn" data-dw="timer" title="${running ? 'Stop timer' : 'Start timer'}">${running ? '&#9209;' : '&#9654;'}</button>
        <button class="icon-btn" data-dw="dup" title="Duplicate">&#128203;</button>
        <button class="icon-btn" data-dw="del" title="Delete task">&#128465;</button>
      </div>

      <div class="dw-body">
        <div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:6px">
          <div class="checkbox ${Store.isDone(t)?'on':''}" data-dw="toggle" style="margin-top:6px">&#10003;</div>
          <textarea class="dw-title" data-dw="name" rows="1" placeholder="Task name">${U.esc(t.name)}</textarea>
        </div>

        <div class="dw-props">
          <label>Status</label>
          <div class="dw-field">
            <select class="sel" data-dw="status" style="background:${U.esc(Store.status(t.listId,t.statusId).color)}22;color:${U.esc(Store.status(t.listId,t.statusId).color)}">
              ${statuses.map(s => `<option value="${U.esc(s.id)}" ${s.id===t.statusId?'selected':''}>${U.esc(s.name)}</option>`).join('')}
            </select>
          </div>

          <label>Assignees</label>
          <div class="dw-field" data-dw="assignees">
            ${Store.state.members.map(m => {
              const on = (t.assignees||[]).includes(m.id);
              return `<button class="avatar sm" data-dw="assign" data-id="${U.esc(m.id)}" title="${U.esc(m.name)}"
                style="background:${U.esc(m.color)};cursor:pointer;opacity:${on?1:.28};border:0">${U.esc(U.initials(m.name))}</button>`;
            }).join('')}
          </div>

          <label>Priority</label>
          <div class="dw-field">
            <select class="sel" data-dw="priority">
              <option value="">No priority</option>
              ${[1,2,3,4].map(p => `<option value="${p}" ${t.priority==p?'selected':''}>${U.esc(PRIORITIES[p].name)}</option>`).join('')}
            </select>
          </div>

          <label>Start date</label>
          <div class="dw-field"><input class="sel" type="date" data-dw="start" value="${U.esc(t.startDate||'')}"></div>

          <label>Due date</label>
          <div class="dw-field">
            <input class="sel" type="date" data-dw="due" value="${U.esc(t.dueDate||'')}">
            ${t.dueDate ? `<span class="due ${U.dueClass(t.dueDate)}">${U.esc(U.fmtDate(t.dueDate))}</span>` : ''}
            <button class="btn ghost sm" data-dw="due-today">Today</button>
            <button class="btn ghost sm" data-dw="due-week">+1 week</button>
          </div>

          <label>Time</label>
          <div class="dw-field">
            <input class="sel" type="number" min="0" step="15" data-dw="est" value="${Number(t.timeEstimate)||0}" style="width:82px" title="Estimate in minutes">
            <span style="font-size:12px;color:var(--muted)">min estimated</span>
            <span style="font-size:12px;color:var(--text-2);font-weight:650">&#183; ${U.esc(U.dur(t.timeSpent) || '0m')} tracked</span>
            ${running ? '<span class="timer-chip" data-dw="timer">&#9209; running</span>' : ''}
          </div>

          <label>Tags</label>
          <div class="dw-field">
            ${(t.tags||[]).map((tg,i) => `<span class="c2tag" style="background:${U.esc(tg.color)}22;color:${U.esc(tg.color)}">${U.esc(tg.name)}
              <button data-dw="untag" data-i="${i}" style="background:none;border:0;color:inherit;cursor:pointer;font-size:12px">&#10005;</button></span>`).join('')}
            <button class="btn ghost sm" data-dw="addtag">+ Tag</button>
          </div>

          <label>List</label>
          <div class="dw-field">
            <select class="sel" data-dw="movelist">
              ${Store.state.lists.map(l => {
                const sp = Store.space(l.spaceId);
                return `<option value="${U.esc(l.id)}" ${l.id===t.listId?'selected':''}>${U.esc((sp?sp.name+' / ':'') + l.name)}</option>`;
              }).join('')}
            </select>
          </div>
        </div>

        ${pct !== null ? `<div style="margin-bottom:16px">
          <div class="progress-lbl"><span>Time progress</span><span>${pct}%</span></div>
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${pct>100?'var(--red)':'var(--accent)'}"></div></div>
        </div>` : ''}

        <div class="dw-sec">
          <h4>Description</h4>
          <textarea class="dw-desc" data-dw="desc" placeholder="Add more detail...">${U.esc(t.description||'')}</textarea>
        </div>

        <div class="dw-sec">
          <h4>Checklist ${t.checklist.length ? `<span style="color:var(--text-2);font-weight:650">${chkDone}/${t.checklist.length}</span>` : ''}</h4>
          ${t.checklist.length ? `<div class="bar-track" style="margin-bottom:8px"><div class="bar-fill" style="width:${Math.round(chkDone/t.checklist.length*100)}%;background:var(--green)"></div></div>` : ''}
          ${t.checklist.map(c => `<div class="chk-item ${c.done?'done':''}">
            <div class="checkbox ${c.done?'on':''}" data-dw="chk" data-id="${U.esc(c.id)}">&#10003;</div>
            <span class="txt" data-dw="chk-edit" data-id="${U.esc(c.id)}">${U.esc(c.text)}</span>
            <button class="x" data-dw="chk-del" data-id="${U.esc(c.id)}">&#10005;</button>
          </div>`).join('')}
          <div class="inline-add"><input data-dw="chk-add" placeholder="Add a checklist item and press Enter"></div>
        </div>

        <div class="dw-sec">
          <h4>Subtasks ${subs.length ? `<span style="color:var(--text-2);font-weight:650">${subs.filter(s=>Store.isDone(s)).length}/${subs.length}</span>` : ''}</h4>
          ${subs.map(s => `<div class="sub-item ${Store.isDone(s)?'done':''}" data-dw="opensub" data-id="${U.esc(s.id)}">
            <div class="checkbox ${Store.isDone(s)?'on':''}" data-dw="subtoggle" data-id="${U.esc(s.id)}">&#10003;</div>
            <span class="nm">${U.esc(s.name)}</span>
            ${s.dueDate ? `<span class="due ${U.dueClass(s.dueDate)}">${U.esc(U.fmtDate(s.dueDate))}</span>` : ''}
            ${V.avatars(s)}
          </div>`).join('')}
          ${t.parentId ? '<div style="font-size:12.5px;color:var(--muted)">This is a subtask.</div>' :
            `<div class="inline-add"><input data-dw="sub-add" placeholder="Add a subtask and press Enter"></div>`}
        </div>

        <div class="dw-sec">
          <h4>Activity &amp; comments</h4>
          ${(t.comments||[]).map(c => {
            const m = Store.member(c.authorId) || { name:'Someone', color:'var(--gray)' };
            return `<div class="cmt">
              <div class="avatar sm" style="background:${U.esc(m.color)}">${U.esc(U.initials(m.name))}</div>
              <div class="cmt-body">
                <div class="cmt-head"><b>${U.esc(m.name)}</b><time>${U.esc(U.fmtTime(c.ts))}</time>
                  <button class="x" data-dw="cmt-del" data-id="${U.esc(c.id)}" style="margin-left:auto;background:none;border:0;color:var(--muted);cursor:pointer">&#10005;</button></div>
                <div class="cmt-text">${U.esc(c.text)}</div>
              </div></div>`;
          }).join('')}
          <div class="inline-add" style="align-items:flex-start;margin-top:10px">
            <div class="avatar sm me" style="background:${U.esc((Store.member(Store.me)||{}).color||'var(--accent)')}">${U.esc(U.initials((Store.member(Store.me)||{}).name))}</div>
            <input data-dw="cmt-add" placeholder="Write a comment and press Enter">
          </div>
          <div style="margin-top:14px;font-size:11.5px;color:var(--muted)">
            Created ${U.esc(U.fmtTime(t.createdAt))} &#183; updated ${U.esc(U.fmtTime(t.updatedAt))} &#183; in ${U.esc(list?list.name:'')}
          </div>
        </div>
      </div>`;

    const ta = el.querySelector('.dw-title');
    if (ta){ ta.style.height = 'auto'; ta.style.height = ta.scrollHeight + 'px'; }
  },

  // Re-render the drawer and the underlying view
  refresh(){ this.render(); App.render(); },

  handle(e){
    const t = this.task;
    if (!t) return;
    const el = e.target.closest('[data-dw]');
    if (!el) return;
    const act = el.getAttribute('data-dw');
    const id = el.getAttribute('data-id');

    // click-only actions
    if (e.type === 'click'){
      switch(act){
        case 'close': return this.close();
        case 'toggle': Store.toggleDone(t.id); return this.refresh();
        case 'del':
          if (confirm(`Delete "${t.name}"` + (Store.subtasks(t.id).length ? ' and its subtasks' : '') + '?')){
            Store.deleteTask(t.id); this.close(); App.render();
          }
          return;
        case 'dup': {
          const copy = JSON.parse(JSON.stringify(t));
          delete copy.id;
          copy.name = t.name + ' (copy)';
          copy.comments = [];
          const nt = Store.addTask(t.listId, copy);
          U.toast('Task duplicated');
          this.open(nt.id); App.render();
          return;
        }
        case 'timer': {
          const tm = Store.state.meta.timer;
          if (tm && tm.taskId === t.id){ const m = Store.stopTimer(); U.toast(`Logged ${U.dur(m) || 'under a minute'}`); }
          else { if (tm) Store.stopTimer(); Store.startTimer(t.id); U.toast('Timer started'); }
          App.tickTimer(); return this.refresh();
        }
        case 'assign': {
          const set = new Set(t.assignees || []);
          set.has(id) ? set.delete(id) : set.add(id);
          Store.updateTask(t.id, { assignees: Array.from(set) });
          return this.refresh();
        }
        case 'due-today': Store.updateTask(t.id, { dueDate: U.today() }); return this.refresh();
        case 'due-week':  Store.updateTask(t.id, { dueDate: U.addDays(t.dueDate || U.today(), 7) }); return this.refresh();
        case 'untag': {
          const i = Number(el.getAttribute('data-i'));
          const tags = (t.tags||[]).slice(); tags.splice(i,1);
          Store.updateTask(t.id, { tags }); return this.refresh();
        }
        case 'addtag': return this.addTagPrompt(t);
        case 'chk': {
          const c = t.checklist.find(x => x.id === id);
          if (c){ c.done = !c.done; Store.updateTask(t.id, { checklist: t.checklist }); }
          return this.refresh();
        }
        case 'chk-del':
          Store.updateTask(t.id, { checklist: t.checklist.filter(x => x.id !== id) });
          return this.refresh();
        case 'chk-edit': {
          const c = t.checklist.find(x => x.id === id);
          if (!c) return;
          const v = prompt('Checklist item', c.text);
          if (v !== null && v.trim()){ c.text = v.trim(); Store.updateTask(t.id, { checklist: t.checklist }); this.refresh(); }
          return;
        }
        case 'subtoggle': e.stopPropagation(); Store.toggleDone(id); return this.refresh();
        case 'opensub': return this.open(id);
        case 'cmt-del':
          Store.updateTask(t.id, { comments: (t.comments||[]).filter(c => c.id !== id) });
          return this.refresh();
      }
    }

    // change events
    if (e.type === 'change'){
      switch(act){
        case 'status': Store.updateTask(t.id, { statusId: el.value }); return this.refresh();
        case 'priority': Store.updateTask(t.id, { priority: el.value ? Number(el.value) : null }); return this.refresh();
        case 'start': Store.updateTask(t.id, { startDate: el.value || null }); return this.refresh();
        case 'due': Store.updateTask(t.id, { dueDate: el.value || null }); return this.refresh();
        case 'est': Store.updateTask(t.id, { timeEstimate: Math.max(0, Number(el.value) || 0) }); return this.refresh();
        case 'movelist': {
          const newList = el.value;
          const sts = Store.statusesFor(newList);
          const cur = Store.status(t.listId, t.statusId);
          const match = sts.find(s => s.name === cur.name) || sts[0];
          Store.updateTask(t.id, { listId: newList, statusId: match.id });
          Store.subtasks(t.id).forEach(s => Store.updateTask(s.id, { listId: newList, statusId: match.id }));
          U.toast('Task moved');
          return this.refresh();
        }
      }
    }

    // blur / input saves
    if (e.type === 'blur'){
      if (act === 'name'){
        const v = el.value.trim();
        if (v && v !== t.name){ Store.updateTask(t.id, { name: v }); App.render(); }
        else if (!v){ el.value = t.name; }
      }
      if (act === 'desc' && el.value !== t.description){
        Store.updateTask(t.id, { description: el.value });
      }
    }

    if (e.type === 'keydown' && e.key === 'Enter'){
      if (act === 'chk-add' && el.value.trim()){
        t.checklist.push({ id:U.uid('ck'), text:el.value.trim(), done:false });
        Store.updateTask(t.id, { checklist: t.checklist });
        el.value = ''; this.refresh();
        setTimeout(() => { const n = document.querySelector('[data-dw="chk-add"]'); if (n) n.focus(); }, 0);
        e.preventDefault();
      }
      if (act === 'sub-add' && el.value.trim()){
        Store.addTask(t.listId, { name: el.value.trim(), parentId: t.id, statusId: t.statusId });
        el.value = ''; this.refresh();
        setTimeout(() => { const n = document.querySelector('[data-dw="sub-add"]'); if (n) n.focus(); }, 0);
        e.preventDefault();
      }
      if (act === 'cmt-add' && el.value.trim()){
        t.comments = t.comments || [];
        t.comments.push({ id:U.uid('cm'), authorId: Store.me, text: el.value.trim(), ts: Date.now() });
        Store.updateTask(t.id, { comments: t.comments });
        el.value = ''; this.refresh();
        setTimeout(() => { const n = document.querySelector('[data-dw="cmt-add"]'); if (n) n.focus(); }, 0);
        e.preventDefault();
      }
      if (act === 'name'){ e.preventDefault(); el.blur(); }
    }

    if (e.type === 'input' && act === 'name'){
      el.style.height = 'auto'; el.style.height = el.scrollHeight + 'px';
    }
  },

  addTagPrompt(t){
    const existing = Store.allTags();
    App.modal({
      title:'Add a tag',
      body:`
        <div class="field"><label>Tag name</label><input type="text" id="tagName" placeholder="e.g. security" autofocus></div>
        <div class="field"><label>Color</label><div class="swatches" id="tagSw">
          ${PALETTE.map((c,i) => `<button class="sw-btn ${i===0?'on':''}" data-color="${c}" style="background:${c}"></button>`).join('')}
        </div></div>
        ${existing.length ? `<div class="field"><label>Existing tags</label><div class="swatches">
          ${existing.map(tg => `<button class="c2tag" data-existing="${U.esc(tg.name)}" data-color="${U.esc(tg.color)}"
            style="background:${U.esc(tg.color)}22;color:${U.esc(tg.color)};cursor:pointer;border:0">${U.esc(tg.name)}</button>`).join('')}
        </div></div>` : ''}`,
      okLabel:'Add tag',
      onMount(root){
        let color = PALETTE[0];
        root.querySelectorAll('#tagSw .sw-btn').forEach(b => b.onclick = () => {
          root.querySelectorAll('#tagSw .sw-btn').forEach(x => x.classList.remove('on'));
          b.classList.add('on'); color = b.getAttribute('data-color');
        });
        root.querySelectorAll('[data-existing]').forEach(b => b.onclick = () => {
          root.querySelector('#tagName').value = b.getAttribute('data-existing');
          color = b.getAttribute('data-color');
        });
        root._getColor = () => color;
      },
      onOk(root){
        const name = root.querySelector('#tagName').value.trim();
        if (!name) return false;
        const tags = (t.tags||[]).slice();
        if (!tags.some(x => x.name === name)) tags.push({ name, color: root._getColor() });
        Store.updateTask(t.id, { tags });
        Drawer.refresh();
      }
    });
  }
};

/* ============================== app.js =================================== */
/* ===== app.js - router, chrome, events ===== */

const VIEWS = [
  { id:'list',     label:'List',     ico:'&#9776;'   },
  { id:'board',    label:'Board',    ico:'&#9638;'   },
  { id:'table',    label:'Table',    ico:'&#9636;'   },
  { id:'calendar', label:'Calendar', ico:'&#128197;' },
  { id:'gantt',    label:'Gantt',    ico:'&#128200;' }
];

const App = {
  route: { name:'home', listId:null, view:'list' },
  ui: {
    group:'status',
    sort:'order',
    filters:{ search:'', assignee:'', priority:'', tag:'', due:'', showClosed:true },
    closedGroups:{},
    openSubs:{},
    calMonth:null
  },

  // ---------- routing ----------
  parseRoute(){
    const h = (location.hash || '#/home').replace(/^#\/?/, '');
    const parts = h.split('/').filter(Boolean);
    if (parts[0] === 'campaigns-v2') parts.shift();
    if (parts[0] === 'list' && parts[1]){
      const l = Store.list(parts[1]);
      if (!l){ this.go('#/home'); return; }
      const view = VIEWS.some(v => v.id === parts[2]) ? parts[2] : (l.defaultView || 'list');
      this.route = { name:'list', listId:l.id, view };
      this.ui.calMonth = this.ui.calMonth || U.today().slice(0,7);
    } else if (parts[0] === 'remediations'){
      this.route = { name:'remediations', listId:null, view:'remediations' };
      this.loadFindings();
    } else if (parts[0] === 'findings'){
      this.route = { name:'findings', listId:null, view:'findings' };
      this.loadFindings();
    } else if (['mytasks','everything','dashboard','home'].includes(parts[0])){
      this.route = { name:parts[0], listId:null, view: VIEWS.some(v => v.id === parts[1]) ? parts[1] : 'list' };
    } else {
      this.route = { name:'home', listId:null, view:'list' };
    }
    this.render();
  },

  go(hash){
    var sub = String(hash || '').replace(/^#\/?/, '');
    location.hash = sub ? '#/campaigns-v2/' + sub : '#/campaigns-v2';
    this.parseRoute();
  },

  findingsCache: [],
  exceptionsCache: [],
  remediationsCache: [],

  // Findings live in IndexedDB, not in the in-memory workspace model, so a route
  // change loads them once and renders from the cache.
  async loadFindings(){
    if (!Store.idbAvailable) return;
    this.findingsCache = await IDB.getAll('findings');
    const defs = await IDB.getAll('definitions');
    const byRef = new Map(defs.map(d => [d.definitionRef, d]));
    this.findingsCache.forEach(f => {
      const d = byRef.get(f.definitionRef);
      if (d){ f.name = d.name; f.cve = d.cve || f.cve || []; f.recurrenceExpected = d.recurrenceExpected; }
    });
    this.exceptionsCache = await IDB.getAll('exceptions');
    const assets = await IDB.getAll('assets');
    const assetsByKey = new Map(assets.map(a => [a.assetKey, a]));
    const stored = new Map((await IDB.getAll('remediations')).map(r => [r.key, r]));
    this.remediationsCache = Remediation.rollup(this.findingsCache, assetsByKey, stored, this.exceptionsCache);
    this.render();
  },

  // ---------- data for the current route ----------
  currentTasks(){
    const r = this.route;
    if (r.name === 'list'){
      return Store.tasksIn(r.listId, { includeSubs: this.ui.group !== 'status' ? false : false });
    }
    if (r.name === 'mytasks'){
      return Store.allTasks().filter(t => (t.assignees||[]).includes(Store.me));
    }
    if (r.name === 'everything'){
      return Store.allTasks().filter(t => !t.parentId);
    }
    return [];
  },

  // ---------- render ----------
  render(){
    this.renderSidebar();
    this.renderTopbar();
    this.renderViewbar();
    this.renderToolbar();
    this.renderContent();
    const c = document.getElementById('cv2-myTasksCount');
    if (c) c.textContent = Store.allTasks().filter(t => (t.assignees||[]).includes(Store.me) && !Store.isDone(t)).length;
    if (Drawer.taskId && Store.task(Drawer.taskId)) Drawer.render();
  },

  renderSidebar(){
    U.$$('.sb-link').forEach(a => {
      a.classList.toggle('active', a.getAttribute('data-route') === '#/' + this.route.name);
    });

    const tree = document.getElementById('cv2-spaceTree');
    let html = '';
    Store.state.spaces.forEach(sp => {
      const open = !sp.collapsed;
      const spTasks = Store.listsInSpace(sp.id).flatMap(l => Store.tasksIn(l.id)).filter(t => !Store.isDone(t)).length;
      html += `<div class="tree-row lvl-space" data-tree="space" data-id="${U.esc(sp.id)}" data-ctx="space">
        <span class="caret ${open?'open':''}">&#9654;</span>
        <span class="dot" style="background:${U.esc(sp.color)}"></span>
        <span class="tr-name">${U.esc(sp.name)}</span>
        <span class="tr-count">${spTasks}</span>
        <span class="tr-actions"><button class="icon-btn sm" data-add="space" data-id="${U.esc(sp.id)}" title="Add list or folder">+</button></span>
      </div>`;
      if (!open) return;
      html += '<div class="tree-kids">';
      Store.foldersInSpace(sp.id).forEach(f => {
        const fOpen = !f.collapsed;
        const fCount = Store.listsInFolder(f.id).flatMap(l => Store.tasksIn(l.id)).filter(t => !Store.isDone(t)).length;
        html += `<div class="tree-row" data-tree="folder" data-id="${U.esc(f.id)}" data-ctx="folder">
          <span class="caret ${fOpen?'open':''}">&#9654;</span>
          <span class="ico-sm">&#128193;</span>
          <span class="tr-name">${U.esc(f.name)}</span>
          <span class="tr-count">${fCount}</span>
          <span class="tr-actions"><button class="icon-btn sm" data-add="folder" data-id="${U.esc(f.id)}" title="Add list">+</button></span>
        </div>`;
        if (fOpen){
          html += '<div class="tree-kids">';
          Store.listsInFolder(f.id).forEach(l => { html += this.listRow(l); });
          html += '</div>';
        }
      });
      Store.rootLists(sp.id).forEach(l => { html += this.listRow(l); });
      html += '</div>';
    });
    if (!Store.state.spaces.length) html = '<div style="padding:14px;color:var(--muted);font-size:13px">No spaces yet. Use + above.</div>';
    tree.innerHTML = html;
  },

  listRow(l){
    const n = Store.tasksIn(l.id).filter(t => !Store.isDone(t)).length;
    const active = this.route.listId === l.id;
    return `<div class="tree-row ${active?'active':''}" data-tree="list" data-id="${U.esc(l.id)}" data-ctx="list">
      <span class="caret"></span><span class="ico-sm">&#9776;</span>
      <span class="tr-name">${U.esc(l.name)}</span>
      <span class="tr-count">${n}</span>
      <span class="tr-actions"><button class="icon-btn sm" data-add="task" data-id="${U.esc(l.id)}" title="Add task">+</button></span>
    </div>`;
  },

  renderTopbar(){
    const bc = document.getElementById('cv2-breadcrumb');
    const r = this.route;
    if (r.name === 'list'){
      const path = Store.listPath(r.listId);
      const tasks = Store.tasksIn(r.listId);
      bc.innerHTML = path.map((x,i) =>
        i === path.length-1
          ? `<b>${U.esc(x.name)}</b>`
          : `<span>${U.esc(x.name)}</span><span class="sep">/</span>`
      ).join('') + `<span class="c2pill" style="margin-left:6px">${tasks.filter(t=>!Store.isDone(t)).length} open</span>`;
    } else {
      const titles = { home:'Home', mytasks:'My Tasks', everything:'Everything', dashboard:'Dashboards', findings:'Findings', remediations:'Remediations' };
      bc.innerHTML = `<b>${U.esc(titles[r.name] || 'Home')}</b>`;
    }
  },

  renderViewbar(){
    const vb = document.getElementById('cv2-viewbar');
    const r = this.route;
    if (['home','dashboard','findings','remediations'].includes(r.name)){ vb.classList.add('hidden'); return; }
    vb.classList.remove('hidden');
    vb.innerHTML = VIEWS.map(v =>
      `<button class="vtab ${r.view===v.id?'active':''}" data-view="${v.id}"><span>${v.ico}</span>${v.label}</button>`
    ).join('') + (r.name === 'list'
      ? `<span style="flex:1"></span><button class="vtab" data-act="editstatuses">&#9881; Statuses</button>`
      : '');
  },

  renderToolbar(){
    const tb = document.getElementById('cv2-toolbar');
    const r = this.route;
    if (r.name === 'remediations'){
      tb.classList.remove('hidden');
      const rf = this.ui.remFilters || (this.ui.remFilters = { showDone:false });
      const rows = this.remediationsCache;
      const openN = rows.filter(x => x.derivedState !== 'DONE').length;
      const regressed = rows.filter(x => x.regressed).length;
      tb.innerHTML = `
        <span class="c2chip">${rows.length} fix action${rows.length===1?'':'s'} &#183; ${openN} open</span>
        ${regressed ? `<span class="c2chip" style="background:color-mix(in srgb,var(--red) 15%,transparent);color:var(--red)">${regressed} regressed</span>` : ''}
        <button class="tool ${rf.showDone?'on':''}" id="remDone">${rf.showDone?'Showing completed':'Hiding completed'}</button>
        <span class="tool-spacer"></span>
        <button class="tool" data-act="open-import">&#11014; Import scan</button>`;
      return;
    }
    if (r.name === 'findings'){
      tb.classList.remove('hidden');
      const f = this.ui.findingFilters || (this.ui.findingFilters = { showClosed:false, showSuppressed:false, state:'', q:'' });
      const open = this.findingsCache.filter(x => Lifecycle.isOpen(x)).length;
      tb.innerHTML = `
        <div class="tool"><span>State</span><select id="fState">
          <option value="">All</option>
          ${DETECTION_STATES.map(v=>`<option value="${v}" ${f.state===v?'selected':''}>${v}</option>`).join('')}
        </select></div>
        <button class="tool ${f.showClosed?'on':''}" id="fClosed">${f.showClosed?'Showing closed':'Open only'}</button>
        <button class="tool ${f.showSuppressed?'on':''}" id="fSupp">${f.showSuppressed?'Showing accepted':'Hiding accepted'}</button>
        <span class="c2chip">${this.findingsCache.length} findings &#183; ${open} open</span>
        <span class="tool-spacer"></span>
        <button class="tool" data-act="open-import">&#11014; Import scan</button>
        <button class="tool" data-act="storage-info">&#128190; Storage</button>`;
      return;
    }
    if (r.name === 'home' || r.name === 'dashboard'){ tb.classList.add('hidden'); return; }
    tb.classList.remove('hidden');
    const f = this.ui.filters;
    const members = Store.state.members;
    const tags = Store.allTags();

    const chips = [];
    if (f.assignee){ const m = Store.member(f.assignee); chips.push(['assignee', 'Assignee: ' + (m?m.name:'')]); }
    if (f.priority) chips.push(['priority', 'Priority: ' + PRIORITIES[f.priority].name]);
    if (f.tag) chips.push(['tag', 'Tag: ' + f.tag]);
    if (f.due) chips.push(['due', 'Due: ' + ({overdue:'Overdue',today:'Today',week:'Next 7 days',none:'No date'})[f.due]]);
    if (f.search) chips.push(['search', 'Search: ' + f.search]);

    tb.innerHTML = `
      <div class="tool"><span>Group</span>
        <select id="groupSel">
          ${[['status','Status'],['assignee','Assignee'],['priority','Priority'],['due','Due date'],['list','List'],['none','None']]
            .map(([v,l]) => `<option value="${v}" ${this.ui.group===v?'selected':''}>${l}</option>`).join('')}
        </select></div>
      <div class="tool"><span>Sort</span>
        <select id="sortSel">
          ${[['order','Manual'],['due','Due date'],['priority','Priority'],['name','Name'],['updated','Updated'],['created','Created']]
            .map(([v,l]) => `<option value="${v}" ${this.ui.sort===v?'selected':''}>${l}</option>`).join('')}
        </select></div>
      <div class="tool"><span>Assignee</span>
        <select id="asgSel"><option value="">Anyone</option>
          ${members.map(m => `<option value="${U.esc(m.id)}" ${f.assignee===m.id?'selected':''}>${U.esc(m.name)}</option>`).join('')}
        </select></div>
      <div class="tool"><span>Priority</span>
        <select id="prioSel"><option value="">Any</option>
          ${[1,2,3,4].map(p => `<option value="${p}" ${String(f.priority)===String(p)?'selected':''}>${PRIORITIES[p].name}</option>`).join('')}
        </select></div>
      <div class="tool"><span>Due</span>
        <select id="dueSel"><option value="">Any</option>
          ${[['overdue','Overdue'],['today','Today'],['week','Next 7 days'],['none','No date']]
            .map(([v,l]) => `<option value="${v}" ${f.due===v?'selected':''}>${l}</option>`).join('')}
        </select></div>
      ${tags.length ? `<div class="tool"><span>Tag</span>
        <select id="tagSel"><option value="">Any</option>
          ${tags.map(t => `<option value="${U.esc(t.name)}" ${f.tag===t.name?'selected':''}>${U.esc(t.name)}</option>`).join('')}
        </select></div>` : ''}
      <button class="tool ${f.showClosed?'':'on'}" id="closedBtn" title="Show or hide completed tasks">
        ${f.showClosed ? '&#128065; Showing closed' : '&#128584; Hiding closed'}</button>
      ${chips.length ? `<span style="width:1px;height:18px;background:var(--border)"></span>` : ''}
      ${chips.map(([k,label]) => `<span class="c2chip">${U.esc(label)}<button data-clear="${k}">&#10005;</button></span>`).join('')}
      ${chips.length ? `<button class="tool" data-clear="all">Clear all</button>` : ''}
      <span class="tool-spacer"></span>
      <button class="tool" data-act="export-csv">&#11015; CSV</button>`;
  },

  renderContent(){
    const c = document.getElementById('cv2-content');
    const r = this.route;
    if (r.name === 'home'){ c.innerHTML = V.renderHome(); return; }
    if (r.name === 'dashboard'){ c.innerHTML = V.renderDashboard(); return; }
    if (r.name === 'findings'){ c.innerHTML = V.renderFindings(); return; }
    if (r.name === 'remediations'){ c.innerHTML = V.renderRemediations(); return; }

    let tasks = V.applyFilters(this.currentTasks());
    if (r.view === 'board') c.innerHTML = V.renderBoard(tasks, r.listId);
    else if (r.view === 'table') c.innerHTML = V.renderTable(tasks);
    else if (r.view === 'calendar') c.innerHTML = V.renderCalendar(tasks);
    else if (r.view === 'gantt') c.innerHTML = V.renderGantt(tasks);
    else c.innerHTML = V.renderList(tasks, r.listId);

    if (r.view === 'board') this.wireDnD();
  },

  // ---------- drag & drop (board) ----------
  wireDnD(){
    let dragId = null;
    U.$$('#cv2-content .card').forEach(card => {
      card.addEventListener('dragstart', e => {
        dragId = card.getAttribute('data-task');
        card.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        try { e.dataTransfer.setData('text/plain', dragId); } catch(_){}
      });
      card.addEventListener('dragend', () => { card.classList.remove('dragging'); dragId = null; });
    });
    U.$$('#cv2-content .bcol-body').forEach(body => {
      body.addEventListener('dragover', e => { e.preventDefault(); body.parentElement.classList.add('dragover'); });
      body.addEventListener('dragleave', () => body.parentElement.classList.remove('dragover'));
      body.addEventListener('drop', e => {
        e.preventDefault();
        body.parentElement.classList.remove('dragover');
        const id = dragId || e.dataTransfer.getData('text/plain');
        const key = body.getAttribute('data-drop');
        const t = Store.task(id);
        if (!t || !key) return;
        if (this.ui.group === 'status' || this.route.name === 'list'){
          const st = Store.statusesFor(t.listId).find(s => s.id === key)
                  || Store.statusesFor(t.listId).find(s => s.name === (Store.statusesFor(this.route.listId).find(x=>x.id===key)||{}).name);
          if (st) Store.updateTask(id, { statusId: st.id });
        } else if (this.ui.group === 'assignee'){
          Store.updateTask(id, { assignees: key === 'none' ? [] : [key] });
        } else if (this.ui.group === 'priority'){
          Store.updateTask(id, { priority: key === 'pnone' ? null : Number(key.replace('p','')) });
        }
        this.render();
      });
    });
  },

  // ---------- timer chip ----------
  tickTimer(){
    const chip = document.getElementById('cv2-timerChip');
    const tm = Store.state.meta.timer;
    if (!tm || !Store.task(tm.taskId)){ chip.classList.add('hidden'); return; }
    const mins = Math.floor((Date.now() - tm.startedAt) / 60000);
    const t = Store.task(tm.taskId);
    chip.classList.remove('hidden');
    chip.innerHTML = `&#9209; <span>${U.esc(t.name.slice(0,26))}${t.name.length>26?'&hellip;':''}</span>
      <b>${Math.floor(mins/60)}:${String(mins%60).padStart(2,'0')}</b>`;
    chip.onclick = () => { const m = Store.stopTimer(); U.toast(`Logged ${U.dur(m) || 'under a minute'}`); this.tickTimer(); this.render(); };
  },

  // ---------- modal ----------
  modal(cfg){
    const scrim = document.getElementById('cv2-modalScrim');
    const m = document.getElementById('cv2-modal');
    m.innerHTML = `<h3>${U.esc(cfg.title||'')}</h3>
      ${cfg.sub ? `<p class="sub">${U.esc(cfg.sub)}</p>` : ''}
      <div id="modalBody">${cfg.body||''}</div>
      <div class="modal-actions">
        ${cfg.extra || ''}
        <button class="btn ghost" data-modal="cancel">${U.esc(cfg.cancelLabel||'Cancel')}</button>
        ${cfg.okLabel === null ? '' : `<button class="btn primary" data-modal="ok">${U.esc(cfg.okLabel||'Save')}</button>`}
      </div>`;
    scrim.classList.remove('hidden');
    if (cfg.onMount) cfg.onMount(m);
    const first = m.querySelector('input,textarea,select');
    if (first) setTimeout(() => first.focus(), 30);

    const close = () => { scrim.classList.add('hidden'); m.innerHTML = ''; };
    m.onclick = e => {
      const b = e.target.closest('[data-modal]');
      if (!b) return;
      if (b.getAttribute('data-modal') === 'cancel'){ if (cfg.onCancel) cfg.onCancel(m); close(); return App.render(); }
      if (cfg.onOk && cfg.onOk(m) === false) return;
      close();
      App.render();
    };
    m.onkeydown = e => {
      if (e.key === 'Enter' && e.target.tagName === 'INPUT'){
        e.preventDefault();
        if (cfg.onOk && cfg.onOk(m) === false) return;
        close(); App.render();
      }
    };
    scrim.onclick = e => { if (e.target === scrim){ if (cfg.onCancel) cfg.onCancel(m); close(); App.render(); } };
    this._closeModal = close;
  },

  // ---------- context menu ----------
  ctx(x, y, items){
    const menu = document.getElementById('cv2-ctxMenu');
    menu.innerHTML = items.map((it,i) => it === '-'
      ? '<div class="ctx-sep"></div>'
      : `<div class="ctx-item ${it.danger?'danger':''}" data-i="${i}">${it.ico?it.ico+' ':''}${U.esc(it.label)}</div>`).join('');
    menu.classList.remove('hidden');
    const w = 200, h = menu.offsetHeight;
    menu.style.left = Math.min(x, innerWidth - w - 8) + 'px';
    menu.style.top = Math.min(y, innerHeight - h - 8) + 'px';
    menu.onclick = e => {
      const el = e.target.closest('.ctx-item');
      if (!el) return;
      const it = items[Number(el.getAttribute('data-i'))];
      menu.classList.add('hidden');
      if (it && it.fn) it.fn();
    };
  },
  hideCtx(){ document.getElementById('cv2-ctxMenu').classList.add('hidden'); },

  // ---------- quick add ----------
  quickAdd(listId, statusId, anchorEl){
    const list = Store.list(listId);
    if (!list) return;
    const sts = Store.statusesFor(listId);
    const st = sts.find(s => s.id === statusId) || sts[0];

    if (anchorEl){
      anchorEl.innerHTML = `<span>+</span><input placeholder="Task name, then Enter" autofocus>`;
      const input = anchorEl.querySelector('input');
      input.focus();
      const done = (keepOpen) => {
        const v = input.value.trim();
        if (v){
          const t = Store.addTask(listId, { name:v, statusId: st.id });
          if (!keepOpen) { this.render(); return t; }
          input.value = '';
          U.toast('Task added');
          this.render();
          setTimeout(() => {
            const again = document.querySelector(`[data-act="quickadd"][data-list="${listId}"][data-status="${st.id}"]`);
            if (again) this.quickAdd(listId, st.id, again);
          }, 0);
          return t;
        }
        this.render();
      };
      input.onkeydown = e => {
        if (e.key === 'Enter'){ e.preventDefault(); done(true); }
        if (e.key === 'Escape'){ this.render(); }
      };
      input.onblur = () => setTimeout(() => { if (document.body.contains(input)) done(false); }, 120);
      return;
    }

    this.modal({
      title:'New task',
      sub:`in ${Store.listPath(listId).map(p=>p.name).join(' / ')}`,
      body:`
        <div class="field"><label>Task name</label><input type="text" id="ntName" placeholder="What needs doing?"></div>
        <div class="field"><label>Status</label><select id="ntStatus">${sts.map(s=>`<option value="${U.esc(s.id)}" ${s.id===st.id?'selected':''}>${U.esc(s.name)}</option>`).join('')}</select></div>
        <div class="field"><label>Priority</label><select id="ntPrio"><option value="">No priority</option>
          ${[1,2,3,4].map(p=>`<option value="${p}">${PRIORITIES[p].name}</option>`).join('')}</select></div>
        <div class="field"><label>Assignee</label><select id="ntAsg"><option value="">Unassigned</option>
          ${Store.state.members.map(m=>`<option value="${U.esc(m.id)}">${U.esc(m.name)}</option>`).join('')}</select></div>
        <div class="field"><label>Due date</label><input type="date" id="ntDue"></div>`,
      okLabel:'Create task',
      onOk(root){
        const name = root.querySelector('#ntName').value.trim();
        if (!name) return false;
        const asg = root.querySelector('#ntAsg').value;
        const t = Store.addTask(listId, {
          name,
          statusId: root.querySelector('#ntStatus').value,
          priority: root.querySelector('#ntPrio').value ? Number(root.querySelector('#ntPrio').value) : null,
          assignees: asg ? [asg] : [],
          dueDate: root.querySelector('#ntDue').value || null
        });
        U.toast('Task created', 'Open', () => Drawer.open(t.id));
      }
    });
  },

  // ---------- status editor ----------
  editStatuses(listId){
    const list = Store.list(listId);
    if (!list) return;
    const sts = Store.statusesFor(listId).map(s => Object.assign({}, s));
    this.modal({
      title:'Statuses for ' + list.name,
      sub:'Tasks in a "Closed" status count as complete.',
      body:`<div id="stRows">${sts.map((s,i)=>`
        <div class="status-editor" data-i="${i}">
          <input type="color" value="${U.esc(s.color)}" data-f="color" style="width:34px;height:30px;border:0;background:none;cursor:pointer">
          <input type="text" value="${U.esc(s.name)}" data-f="name">
          <select data-f="type" class="sel">
            ${['open','active','closed'].map(x=>`<option value="${x}" ${s.type===x?'selected':''}>${x}</option>`).join('')}
          </select>
          <button class="icon-btn" data-del="${i}" title="Remove">&#10005;</button>
        </div>`).join('')}</div>
        <button class="btn ghost sm" id="addStatus">+ Add status</button>`,
      okLabel:'Save statuses',
      onMount(root){
        root.querySelector('#addStatus').onclick = () => {
          const wrap = root.querySelector('#stRows');
          const i = wrap.children.length;
          const div = document.createElement('div');
          div.className = 'status-editor';
          div.innerHTML = `<input type="color" value="#7b68ee" data-f="color" style="width:34px;height:30px;border:0;background:none;cursor:pointer">
            <input type="text" value="New status" data-f="name">
            <select data-f="type" class="sel"><option value="open">open</option><option value="active" selected>active</option><option value="closed">closed</option></select>
            <button class="icon-btn" data-del="${i}">&#10005;</button>`;
          wrap.appendChild(div);
        };
        root.querySelector('#stRows').onclick = e => {
          const b = e.target.closest('[data-del]');
          if (b && root.querySelectorAll('.status-editor').length > 1) b.parentElement.remove();
        };
      },
      onOk(root){
        const rows = Array.from(root.querySelectorAll('.status-editor'));
        const next = rows.map((r,i) => {
          const name = r.querySelector('[data-f="name"]').value.trim() || 'Status';
          const old = sts[i];
          return { id: old ? old.id : U.uid('st'), name, color: r.querySelector('[data-f="color"]').value, type: r.querySelector('[data-f="type"]').value };
        });
        if (!next.some(s => s.type === 'closed')){ U.toast('Keep at least one closed status'); return false; }
        const validIds = new Set(next.map(s => s.id));
        list.statuses = next;
        Store.state.tasks.filter(t => t.listId === listId && !validIds.has(t.statusId))
          .forEach(t => { t.statusId = next[0].id; });
        Store.save();
        U.toast('Statuses updated');
      }
    });
  },

  // ---------- data modal ----------
  dataModal(){
    this.modal({
      title:'Your data',
      sub:'Everything lives in this browser only. Nothing is sent anywhere.',
      body:`<p style="font-size:13.5px;color:var(--text-2);line-height:1.6;margin:0 0 14px">
          ${Store.allTasks().length} tasks across ${Store.state.lists.length} lists in ${Store.state.spaces.length} spaces.</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn" id="expJson">&#11015; Export JSON</button>
          <button class="btn" id="expCsv">&#11015; Export CSV</button>
          <button class="btn" id="impBtn">&#11014; Import JSON</button>
          <button class="btn danger" id="resetBtn">Reset to demo data</button>
        </div>
        <input type="file" id="impFile" accept="application/json,.json" style="display:none">`,
      okLabel:null,
      cancelLabel:'Close',
      onMount(root){
        root.querySelector('#expJson').onclick = () => {
          U.download(`vulnerability-manager-${U.today()}.json`, Store.exportJSON());
          U.toast('Exported JSON');
        };
        root.querySelector('#expCsv').onclick = () => { App.exportCSV(); };
        root.querySelector('#impBtn').onclick = () => root.querySelector('#impFile').click();
        root.querySelector('#impFile').onchange = e => {
          const f = e.target.files[0];
          if (!f) return;
          const fr = new FileReader();
          fr.onload = () => {
            try {
              Store.importJSON(String(fr.result));
              U.toast('Data imported');
              App._closeModal && App._closeModal();
              App.go('#/home');
            } catch(err){ alert('Import failed: ' + err.message); }
          };
          fr.readAsText(f);
        };
        root.querySelector('#resetBtn').onclick = () => {
          if (confirm('Replace everything with the demo data? Your current tasks will be lost.')){
            Store.reset(); App._closeModal && App._closeModal();
            App.go('#/home');
            U.toast('Reset to demo data');
          }
        };
      }
    });
  },

  exportCSV(){
    const rows = [['Task','List','Space','Status','Assignees','Priority','Start','Due','Estimate (min)','Tracked (min)','Tags','Description']];
    const scope = this.route.name === 'list' ? Store.tasksIn(this.route.listId, { includeSubs:true }) : Store.allTasks();
    scope.forEach(t => {
      const l = Store.list(t.listId), sp = l ? Store.space(l.spaceId) : null;
      rows.push([
        t.name, l?l.name:'', sp?sp.name:'',
        Store.status(t.listId,t.statusId).name,
        (t.assignees||[]).map(id => (Store.member(id)||{}).name).filter(Boolean).join('; '),
        t.priority ? PRIORITIES[t.priority].name : '',
        t.startDate||'', t.dueDate||'', t.timeEstimate||0, t.timeSpent||0,
        (t.tags||[]).map(x=>x.name).join('; '), (t.description||'').replace(/\s+/g,' ')
      ]);
    });
    U.download(`vulnerability-manager-tasks-${U.today()}.csv`, rows.map(r => r.map(U.csvCell).join(',')).join('\r\n'), 'text/csv');
    U.toast('Exported CSV');
  },

  // ---------- settings: branding + themes ----------
  settingsModal(){
    const b = Brand.cfg;
    const cur = Theme.cfg;
    const startPreset = cur.preset;
    const startCustom = cur.custom ? JSON.parse(JSON.stringify(cur.custom)) : null;

    const presetCards = THEMES.map(t => `
      <button class="theme-card ${cur.preset===t.id?'on':''}" data-preset="${U.esc(t.id)}" title="${U.esc(t.name)}">
        <span class="theme-sw">${t.swatch.map(c=>`<i style="background:${U.esc(c)}"></i>`).join('')}</span>
        <span class="theme-nm">${U.esc(t.name)}</span>
      </button>`).join('');

    this.modal({
      title:'Settings',
      sub:'Branding and appearance. Everything here is stored in this browser only.',
      body:`
        <div class="set-sec">
          <h4>Branding</h4>
          <div class="field"><label>App name</label>
            <input type="text" id="brName" maxlength="40" value="${U.esc(b.name||'')}" placeholder="Vulnerability Manager"></div>
          <div class="field"><label>Badge text or emoji <span style="font-weight:400;color:var(--muted)">(up to 3 characters, blank uses initials)</span></label>
            <input type="text" id="brIcon" maxlength="3" value="${U.esc(b.icon||'')}" placeholder="VM"></div>
          <div class="brand-preview">
            <span class="ws-avatar" id="bpAvatar">VM</span>
            <span id="bpName" style="font-weight:650"></span>
          </div>
        </div>

        <div class="set-sec">
          <h4>Theme</h4>
          <div class="theme-grid">${presetCards}</div>
        </div>

        <div class="set-sec">
          <h4>Custom theme</h4>
          <div class="field"><label>Base</label>
            <select id="cuBase">
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
            <div style="font-size:11.5px;color:var(--muted);margin-top:5px">
              The base decides shadows and contrast defaults. Tones between your colours are derived automatically.</div>
          </div>
          <div class="color-grid">
            ${[['cuBg','Background','bg'],['cuPanel','Panel','panel'],['cuSidebar','Sidebar','sidebar'],
               ['cuText','Text','text'],['cuAccent','Accent','accent'],['cuAccent2','Accent 2','accent-2'],
               ['cuAccent3','Accent 3','accent-3']].map(([id,label]) =>
              `<label class="color-row"><span>${label}</span><input type="color" id="${id}"></label>`).join('')}
          </div>
          <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
            <button class="btn primary sm" id="cuApply">Apply custom theme</button>
            <button class="btn ghost sm" id="cuFromCurrent">Load current theme</button>
          </div>
        </div>`,
      okLabel:'Done',
      cancelLabel:'Cancel',
      onMount(root){
        // --- branding live preview ---
        const nameI = root.querySelector('#brName'), iconI = root.querySelector('#brIcon');
        const pvName = root.querySelector('#bpName'), pvAv = root.querySelector('#bpAvatar');
        const syncPreview = () => {
          const nm = nameI.value.trim() || 'Vulnerability Manager';
          pvName.textContent = nm;
          const ic = iconI.value.trim() || U.initials(nm);
          pvAv.textContent = ic.slice(0,3);
          pvAv.style.fontSize = ic.length > 2 ? '10px' : '11px';
        };
        nameI.addEventListener('input', syncPreview);
        iconI.addEventListener('input', syncPreview);
        syncPreview();

        // --- preset cards apply live ---
        root.querySelectorAll('[data-preset]').forEach(btn => btn.onclick = () => {
          root.querySelectorAll('[data-preset]').forEach(x => x.classList.remove('on'));
          btn.classList.add('on');
          Theme.set(btn.getAttribute('data-preset'));
        });

        // --- custom theme controls ---
        const ids = { base:'#cuBase', bg:'#cuBg', panel:'#cuPanel', sidebar:'#cuSidebar',
                      text:'#cuText', accent:'#cuAccent', accent2:'#cuAccent2', accent3:'#cuAccent3' };
        const fill = (c) => {
          root.querySelector(ids.base).value = c.base;
          ['bg','panel','sidebar','text','accent','accent2','accent3'].forEach(k => {
            const el = root.querySelector(ids[k]);
            const v = String(c[k] || '#000000').trim();
            el.value = /^#[0-9a-fA-F]{6}$/.test(v) ? v : '#000000';
          });
        };
        const read = () => ({
          base: root.querySelector(ids.base).value,
          bg: root.querySelector(ids.bg).value,
          panel: root.querySelector(ids.panel).value,
          sidebar: root.querySelector(ids.sidebar).value,
          text: root.querySelector(ids.text).value,
          accent: root.querySelector(ids.accent).value,
          accent2: root.querySelector(ids.accent2).value,
          accent3: root.querySelector(ids.accent3).value
        });
        fill(startCustom || Theme.defaultCustom());

        root.querySelector('#cuFromCurrent').onclick = () => { fill(Theme.defaultCustom()); U.toast('Loaded the active theme'); };
        root.querySelector('#cuApply').onclick = () => {
          Theme.setCustom(read());
          root.querySelectorAll('[data-preset]').forEach(x => x.classList.remove('on'));
          U.toast('Custom theme applied');
        };
        root._readCustom = read;
        root._revert = () => {
          Theme.cfg.preset = startPreset;
          Theme.cfg.custom = startCustom;
          Store.save();
          Theme.apply();
        };
      },
      onCancel(root){ if (root._revert) root._revert(); },
      onOk(root){
        Brand.set({
          name: root.querySelector('#brName').value.trim() || 'Vulnerability Manager',
          icon: root.querySelector('#brIcon').value.trim()
        });
        U.toast('Settings saved');
      }
    });
  },

  // ---------- scan import ----------
  importModal(){
    if (!Store.idbAvailable){
      return this.modal({
        title:'Import unavailable',
        sub:'IndexedDB is not available in this browser session.',
        body:`<p style="font-size:13.5px;line-height:1.6;color:var(--text-2)">
          Scan data needs IndexedDB. A single credentialed scan produces far more findings than
          localStorage can hold, so importing into it would fail partway and lose data.
          Private browsing is the usual cause.</p>
          <p style="font-size:12.5px;color:var(--muted)">Reported reason: ${U.esc(IDB.reason || 'unknown')}</p>`,
        okLabel:null, cancelLabel:'Close'
      });
    }
    this.modal({
      title:'Import scan data',
      sub:'Parsed in this browser. Nothing is uploaded anywhere.',
      body:`
        <div class="field"><label>Tenable VM export (.jsonl)</label>
          <input type="file" id="impScan" accept=".jsonl,.json,.txt"></div>
        <div id="impStatus" style="font-size:13px;color:var(--text-2);min-height:22px"></div>
        <div class="bar-track" style="margin-top:8px"><div class="bar-fill" id="impBar" style="width:0%;background:var(--accent)"></div></div>
        <p style="font-size:12px;color:var(--muted);margin-top:14px;line-height:1.6">
          Re-importing the same file is safe. Findings are keyed on source, asset and check id, so
          repeated rows update in place rather than duplicating, and a finding that returns after
          being fixed is marked reopened without losing its original discovery date.</p>`,
      okLabel:null, cancelLabel:'Close',
      onMount(root){
        const status = root.querySelector('#impStatus'), bar = root.querySelector('#impBar');
        root.querySelector('#impScan').onchange = async (e) => {
          const file = e.target.files[0];
          if (!file) return;
          status.textContent = `Reading ${file.name} (${(file.size/1048576).toFixed(1)} MB)...`;
          try {
            const text = await file.text();
            const rec = await TabSync.withImportLock(() => Importers.run(text, {
              fileName: file.name,
              onProgress: (p) => {
                if (p.total) bar.style.width = Math.round(p.done / p.total * 100) + '%';
                status.textContent = p.phase === 'parse'
                  ? `Parsing ${p.done.toLocaleString()} of ${p.total.toLocaleString()} rows...`
                  : p.phase === 'write' ? 'Writing to IndexedDB...' : 'Done.';
              }
            }));
            bar.style.width = '100%';
            status.innerHTML = `<b>Imported ${rec.findings.toLocaleString()} findings</b> from ${rec.rows.toLocaleString()} rows` +
              (rec.duplicateRows ? `, ${rec.duplicateRows.toLocaleString()} duplicate rows collapsed` : '') +
              `.<br>${rec.definitions.toLocaleString()} distinct checks, ${rec.assets.toLocaleString()} assets.`;
            await App.loadFindings();
            U.toast(`Imported ${rec.findings.toLocaleString()} findings`);
          } catch(err){
            status.innerHTML = `<span style="color:var(--red)">${U.esc(err.message)}</span>`;
          }
        };
      }
    });
  },

  // ---------- accept risk ----------
  exceptionModal(findingUid){
    const f = this.findingsCache.find(x => x.findingUid === findingUid);
    if (!f) return;
    this.modal({
      title:'Accept risk',
      sub:U.esc(f.name || f.checkId) + ' on ' + U.esc(f.assetHostname || f.assetKey.slice(0,12)),
      body:`
        <div class="field"><label>Type</label><select id="excType">
          ${Object.keys(EXCEPTION_TYPES).map(k=>`<option value="${k}" ${k==='RISK_ACCEPTED'?'selected':''}>${U.esc(EXCEPTION_TYPES[k].label)}</option>`).join('')}
        </select><div style="font-size:11.5px;color:var(--muted);margin-top:5px" id="excVex"></div></div>
        <div class="field"><label>Scope</label><select id="excScope">
          <option value="finding">This finding only</option>
          <option value="asset">Every finding of this check on this asset</option>
          <option value="check">This check everywhere</option>
        </select><div style="font-size:11.5px;color:var(--muted);margin-top:5px" id="excCount"></div></div>
        <div class="field"><label>Reason (required)</label><input type="text" id="excReason" placeholder="Why is this acceptable?"></div>
        <div class="field"><label>Expires</label><input type="date" id="excExpires" value="${U.esc(U.addDays(U.today(),90))}">
          <div style="font-size:11.5px;color:var(--muted);margin-top:5px">Capped at 365 days. Renewal creates a new record rather than extending this one, so the history stays auditable.</div></div>`,
      okLabel:'Accept risk',
      onMount(root){
        const showVex = () => {
          const t = EXCEPTION_TYPES[root.querySelector('#excType').value];
          root.querySelector('#excVex').textContent =
            `VEX: ${t.vex}${t.justification ? ' / ' + t.justification : ''} · ` +
            (t.gross ? 'stays in gross risk' : 'removed from gross risk') + ', removed from net';
        };
        const showCount = () => {
          const mode = root.querySelector('#excScope').value;
          const scope = mode === 'finding' ? { findingUid:[f.findingUid] }
                      : mode === 'asset'   ? { assetKey:[f.assetKey], checkId:[String(f.checkId)] }
                                           : { checkId:[String(f.checkId)] };
          const probe = Exceptions.create({ scope });
          const n = Exceptions.preview(probe, App.findingsCache).length;
          root.querySelector('#excCount').textContent = `Would suppress ${n} finding${n===1?'':'s'} right now.`;
        };
        root.querySelector('#excType').onchange = showVex;
        root.querySelector('#excScope').onchange = showCount;
        showVex(); showCount();
      },
      onOk(root){
        const reason = root.querySelector('#excReason').value.trim();
        if (!reason){ U.toast('A reason is required'); return false; }
        const mode = root.querySelector('#excScope').value;
        const scope = mode === 'finding' ? { findingUid:[f.findingUid] }
                    : mode === 'asset'   ? { assetKey:[f.assetKey], checkId:[String(f.checkId)] }
                                         : { checkId:[String(f.checkId)] };
        const exc = Exceptions.create({
          scope, type: root.querySelector('#excType').value,
          reasonText: reason, expiresAt: root.querySelector('#excExpires').value || undefined
        });
        exc.matchCountAtSave = Exceptions.preview(exc, App.findingsCache).length;
        IDB.put('exceptions', exc).then(() => App.loadFindings());
        U.toast('Risk accepted until ' + exc.expiresAt);
      }
    });
  },

  // ---------- storage ----------
  async storageModal(){
    const stats = await IDB.stats();
    const q = await IDB.quota();
    const persisted = (navigator.storage && navigator.storage.persisted) ? await navigator.storage.persisted() : false;
    const mb = n => (n/1048576).toFixed(1) + ' MB';
    this.modal({
      title:'Storage',
      sub:'Everything is stored on this machine, in this browser. Nothing is uploaded.',
      body:`
        <table style="width:100%;font-size:13px;border-collapse:collapse">
          ${Object.keys(stats).map(k=>`<tr><td style="padding:4px 0;color:var(--text-2)">${U.esc(k)}</td>
            <td style="padding:4px 0;text-align:right;font-weight:650">${stats[k].toLocaleString()}</td></tr>`).join('')}
        </table>
        <div style="margin-top:14px;font-size:13px">
          <div>Used: <b>${q ? mb(q.usage) : 'n/a'}</b> of <b>${q ? mb(q.quota) : 'n/a'}</b> available</div>
          <div style="margin-top:6px">Durable storage: <b style="color:${persisted?'var(--green)':'var(--amber)'}">${persisted ? 'granted' : 'not granted'}</b></div>
          ${persisted ? '' : `<p style="font-size:12px;color:var(--muted);margin:8px 0 0;line-height:1.6">
            Without this, the browser is free to evict your data when disk runs low. Safari also clears
            storage for sites unused for seven days.</p>
            <button class="btn sm" id="persistBtn" style="margin-top:8px">Request durable storage</button>`}
        </div>`,
      okLabel:null, cancelLabel:'Close',
      onMount(root){
        const b = root.querySelector('#persistBtn');
        if (b) b.onclick = async () => {
          const r = await IDB.requestPersistence();
          U.toast(r.granted ? 'Durable storage granted' : 'The browser declined durable storage');
        };
      }
    });
  },

  helpModal(){
    this.modal({
      title:'Keyboard shortcuts',
      body:`<div class="kbd-list">
        <span>Search tasks</span><kbd>/</kbd>
        <span>New task</span><kbd>N</kbd>
        <span>Home</span><kbd>G</kbd> <kbd>H</kbd>
        <span>My Tasks</span><kbd>G</kbd> <kbd>M</kbd>
        <span>Everything</span><kbd>G</kbd> <kbd>E</kbd>
        <span>Dashboards</span><kbd>G</kbd> <kbd>D</kbd>
        <span>Switch view <em style="color:var(--muted);font-style:normal">(not on Home or Dashboards)</em></span><kbd>1</kbd> &hellip; <kbd>5</kbd>
        <span>Toggle sidebar</span><kbd>[</kbd>
        <span>Toggle light and dark</span><kbd>T</kbd>
        <span>Close panel</span><kbd>Esc</kbd>
      </div>
      <p style="font-size:12.5px;color:var(--muted);margin:16px 0 0;line-height:1.6">
        Right click a space, folder, list, or task for more actions. Drag cards between board columns to change status.</p>`,
      okLabel:null, cancelLabel:'Got it'
    });
  },

  // ---------- events ----------
  bind(root, signal){
    // sidebar nav
    U.$$('.sb-link').forEach(a => a.onclick = () => this.go(a.getAttribute('data-route')));

    document.getElementById('cv2-collapseBtn').onclick = () => document.getElementById('cv2root').classList.toggle('sb-collapsed');
    document.getElementById('cv2-mobileMenuBtn').onclick = () => {
      const app = document.getElementById('cv2root');
      // on desktop this button is the way back out of the collapsed state
      if (window.innerWidth > 900) app.classList.remove('sb-collapsed');
      else app.classList.toggle('sb-open');
    };
    document.getElementById('cv2-settingsBtn').onclick = () => this.settingsModal();
    document.getElementById('cv2-dataBtn').onclick = () => this.dataModal();
    document.getElementById('cv2-helpBtn').onclick = () => this.helpModal();
    document.getElementById('cv2-addSpaceBtn').onclick = () => this.newSpace();
    document.getElementById('cv2-newTaskBtn').onclick = () => {
      const lid = this.route.listId || (Store.state.lists[0] || {}).id;
      if (lid) this.quickAdd(lid, null, null); else U.toast('Create a list first');
    };
    document.getElementById('cv2-meAvatar').onclick = () => this.switchUser();

    const search = document.getElementById('cv2-globalSearch');
    search.addEventListener('input', U.debounce(() => {
      this.ui.filters.search = search.value;
      if (this.route.name === 'home' || this.route.name === 'dashboard') this.go('#/everything');
      else this.render();
      const s = document.getElementById('cv2-globalSearch');
      if (s && document.activeElement !== s){ s.value = this.ui.filters.search; }
    }, 180));

    // sidebar tree
    document.getElementById('cv2-spaceTree').addEventListener('click', e => {
      const add = e.target.closest('[data-add]');
      if (add){
        e.stopPropagation();
        const kind = add.getAttribute('data-add'), id = add.getAttribute('data-id');
        if (kind === 'space') this.newInSpace(id);
        if (kind === 'folder') this.newList(Store.folder(id).spaceId, id);
        if (kind === 'task') this.quickAdd(id, null, null);
        return;
      }
      const row = e.target.closest('[data-tree]');
      if (!row) return;
      const kind = row.getAttribute('data-tree'), id = row.getAttribute('data-id');
      if (kind === 'list'){ this.go('#/list/' + id); document.getElementById('cv2root').classList.remove('sb-open'); }
      if (kind === 'space'){ const sp = Store.space(id); sp.collapsed = !sp.collapsed; Store.save(); this.renderSidebar(); }
      if (kind === 'folder'){ const f = Store.folder(id); f.collapsed = !f.collapsed; Store.save(); this.renderSidebar(); }
    });

    // viewbar
    document.getElementById('cv2-viewbar').addEventListener('click', e => {
      const v = e.target.closest('[data-view]');
      if (v){
        const view = v.getAttribute('data-view');
        if (this.route.name === 'list'){
          const l = Store.list(this.route.listId);
          if (l){ l.defaultView = view; Store.save(); }
          this.go(`#/list/${this.route.listId}/${view}`);
        } else {
          this.route.view = view; this.render();
        }
        return;
      }
      if (e.target.closest('[data-act="editstatuses"]')) this.editStatuses(this.route.listId);
    });

    // toolbar
    document.getElementById('cv2-toolbar').addEventListener('change', e => {
      const id = e.target.id;
      if (id === 'fState'){ this.ui.findingFilters.state = e.target.value; return this.render(); }
      if (id === 'groupSel') this.ui.group = e.target.value;
      if (id === 'sortSel') this.ui.sort = e.target.value;
      if (id === 'asgSel') this.ui.filters.assignee = e.target.value;
      if (id === 'prioSel') this.ui.filters.priority = e.target.value;
      if (id === 'dueSel') this.ui.filters.due = e.target.value;
      if (id === 'tagSel') this.ui.filters.tag = e.target.value;
      this.render();
    });
    document.getElementById('cv2-toolbar').addEventListener('click', e => {
      if (e.target.closest('#remDone')){ this.ui.remFilters.showDone = !this.ui.remFilters.showDone; return this.render(); }
      if (e.target.closest('#fClosed')){ this.ui.findingFilters.showClosed = !this.ui.findingFilters.showClosed; return this.render(); }
      if (e.target.closest('#fSupp')){ this.ui.findingFilters.showSuppressed = !this.ui.findingFilters.showSuppressed; return this.render(); }
      if (e.target.closest('[data-act="open-import"]')) return this.importModal();
      if (e.target.closest('[data-act="storage-info"]')) return this.storageModal();
      if (e.target.closest('#closedBtn')){ this.ui.filters.showClosed = !this.ui.filters.showClosed; return this.render(); }
      if (e.target.closest('[data-act="export-csv"]')) return this.exportCSV();
      const c = e.target.closest('[data-clear]');
      if (c){
        const k = c.getAttribute('data-clear');
        if (k === 'all') this.ui.filters = { search:'', assignee:'', priority:'', tag:'', due:'', showClosed:this.ui.filters.showClosed };
        else this.ui.filters[k] = '';
        if (k === 'search' || k === 'all') document.getElementById('cv2-globalSearch').value = '';
        this.render();
      }
    });

    // content
    const content = document.getElementById('cv2-content');
    content.addEventListener('change', async e => {
      const sel = e.target.closest('[data-act="rem-group-assign"]');
      if (!sel) return;
      await Remediation.saveGroup(sel.getAttribute('data-key'), sel.getAttribute('data-group'),
                                  { assignee: sel.value || null });
      U.toast('Group assigned');
      await this.loadFindings();
    });
    content.addEventListener('click', e => {
      const act = e.target.closest('[data-act]');
      if (act){
        const a = act.getAttribute('data-act');
        if (a === 'toggle'){ e.stopPropagation(); Store.toggleDone(act.getAttribute('data-id')); return this.render(); }
        if (a === 'subs'){ e.stopPropagation(); const id = act.getAttribute('data-id'); this.ui.openSubs[id] = !this.ui.openSubs[id]; return this.render(); }
        if (a === 'group'){ const k = act.getAttribute('data-key'); this.ui.closedGroups[k] = !this.ui.closedGroups[k]; return this.render(); }
        if (a === 'quickadd'){ return this.quickAdd(act.getAttribute('data-list'), act.getAttribute('data-status') || null, act.classList.contains('addrow') || act.classList.contains('bcol-add') ? act : null); }
        if (a === 'goto'){ return this.go('#/list/' + act.getAttribute('data-list')); }
        if (a === 'open-import'){ return this.importModal(); }
        if (a === 'rem-toggle'){
          const k = act.getAttribute('data-key');
          this.ui.openRem = this.ui.openRem || {};
          this.ui.openRem[k] = !this.ui.openRem[k];
          return this.render();
        }
        if (a === 'add-exception'){ e.stopPropagation(); return this.exceptionModal(act.getAttribute('data-id')); }
        if (a === 'calprev'){ return this.shiftMonth(-1); }
        if (a === 'calnext'){ return this.shiftMonth(1); }
        if (a === 'caltoday'){ this.ui.calMonth = U.today().slice(0,7); return this.render(); }
        if (a === 'calday'){
          if (e.target.closest('[data-task]')) return;
          if (this.route.listId){
            const t = Store.addTask(this.route.listId, { name:'New task', dueDate: act.getAttribute('data-date') });
            this.render(); Drawer.open(t.id);
          } else U.toast('Open a list to add a task on a date');
          return;
        }
      }
      const task = e.target.closest('[data-task]');
      if (task) Drawer.open(task.getAttribute('data-task'));
    });

    // context menus
    root.addEventListener('contextmenu', e => {
      const el = e.target.closest('[data-ctx]');
      if (!el) return;
      e.preventDefault();
      const kind = el.getAttribute('data-ctx');
      const id = el.getAttribute('data-id') || el.getAttribute('data-task');
      this.buildCtx(kind, id, e.clientX, e.clientY);
    }, { signal });
    root.addEventListener('click', e => { if (!e.target.closest('#cv2-ctxMenu')) this.hideCtx(); }, { signal });

    // drawer events
    const dw = document.getElementById('cv2drawer');
    ['click','change','blur','keydown','input'].forEach(evt =>
      dw.addEventListener(evt, e => Drawer.handle(e), true));
    document.getElementById('cv2drawerScrim').onclick = () => Drawer.close();

  },

  shiftMonth(n){
    const cur = this.ui.calMonth || U.today().slice(0,7);
    const [y,m] = cur.split('-').map(Number);
    const d = new Date(y, m-1+n, 1);
    this.ui.calMonth = U.ymd(d).slice(0,7);
    this.render();
  },

  toggleTheme(){ Theme.toggle(); },

  switchUser(){
    this.modal({
      title:'View as',
      sub:'Switches who counts as "me" for My Tasks and comments.',
      body:`<div class="field"><label>Member</label><select id="whoSel">
        ${Store.state.members.map(m => `<option value="${U.esc(m.id)}" ${m.id===Store.me?'selected':''}>${U.esc(m.name)}</option>`).join('')}
      </select></div>`,
      okLabel:'Switch',
      onOk(root){
        Store.state.meta.currentUser = root.querySelector('#whoSel').value;
        Store.save();
        const m = Store.member(Store.me);
        document.getElementById('cv2-meAvatar').textContent = U.initials(m.name);
        document.getElementById('cv2-meAvatar').style.background = m.color;
      }
    });
  },

  newSpace(){
    this.modal({
      title:'New Space',
      body:`<div class="field"><label>Name</label><input type="text" id="spName" placeholder="e.g. Marketing"></div>
        <div class="field"><label>Color</label><div class="swatches" id="spSw">
          ${PALETTE.map((c,i)=>`<button class="sw-btn ${i===0?'on':''}" data-color="${c}" style="background:${c}"></button>`).join('')}
        </div></div>`,
      okLabel:'Create Space',
      onMount(root){
        let color = PALETTE[0];
        root.querySelectorAll('#spSw .sw-btn').forEach(b => b.onclick = () => {
          root.querySelectorAll('#spSw .sw-btn').forEach(x => x.classList.remove('on'));
          b.classList.add('on'); color = b.getAttribute('data-color');
        });
        root._color = () => color;
      },
      onOk(root){
        const n = root.querySelector('#spName').value.trim();
        if (!n) return false;
        const sp = Store.addSpace(n, root._color());
        const l = Store.addList(sp.id, null, 'List');
        U.toast('Space created');
        setTimeout(() => App.go('#/list/' + l.id), 0);
      }
    });
  },

  newInSpace(spaceId){
    this.ctxCenter([
      { label:'New List', ico:'&#9776;', fn:() => this.newList(spaceId, null) },
      { label:'New Folder', ico:'&#128193;', fn:() => this.newFolder(spaceId) }
    ]);
  },

  ctxCenter(items){
    this.modal({
      title:'Create',
      body:`<div>${items.map((it,i)=>`<div class="ctx-item" data-i="${i}" style="padding:11px 10px">${it.ico||''} ${U.esc(it.label)}</div>`).join('')}</div>`,
      okLabel:null, cancelLabel:'Cancel',
      onMount(root){
        root.querySelectorAll('.ctx-item').forEach(el => el.onclick = () => {
          const it = items[Number(el.getAttribute('data-i'))];
          App._closeModal && App._closeModal();
          setTimeout(() => it.fn(), 20);
        });
      }
    });
  },

  newList(spaceId, folderId){
    this.modal({
      title:'New List',
      body:`<div class="field"><label>Name</label><input type="text" id="liName" placeholder="e.g. Sprint 25"></div>`,
      okLabel:'Create List',
      onOk(root){
        const n = root.querySelector('#liName').value.trim();
        if (!n) return false;
        const l = Store.addList(spaceId, folderId, n);
        setTimeout(() => App.go('#/list/' + l.id), 0);
        U.toast('List created');
      }
    });
  },

  newFolder(spaceId){
    this.modal({
      title:'New Folder',
      body:`<div class="field"><label>Name</label><input type="text" id="foName" placeholder="e.g. Engineering"></div>`,
      okLabel:'Create Folder',
      onOk(root){
        const n = root.querySelector('#foName').value.trim();
        if (!n) return false;
        const f = Store.addFolder(spaceId, n);
        Store.addList(spaceId, f.id, 'List');
        U.toast('Folder created');
      }
    });
  },

  rename(kind, id){
    const obj = kind === 'space' ? Store.space(id) : kind === 'folder' ? Store.folder(id) : Store.list(id);
    if (!obj) return;
    this.modal({
      title:'Rename',
      body:`<div class="field"><label>Name</label><input type="text" id="rnName" value="${U.esc(obj.name)}"></div>`,
      okLabel:'Save',
      onOk(root){
        const n = root.querySelector('#rnName').value.trim();
        if (!n) return false;
        obj.name = n; Store.save();
      }
    });
  },

  buildCtx(kind, id, x, y){
    if (kind === 'task'){
      const t = Store.task(id);
      if (!t) return;
      const sts = Store.statusesFor(t.listId);
      const items = [
        { label:'Open', ico:'&#128194;', fn:() => Drawer.open(id) },
        { label: Store.isDone(t) ? 'Mark not complete' : 'Mark complete', ico:'&#10003;', fn:() => { Store.toggleDone(id); this.render(); } },
        '-',
        ...sts.map(s => ({ label:'Status: ' + s.name, fn:() => { Store.updateTask(id, { statusId:s.id }); this.render(); } })),
        '-',
        ...[1,2,3,4].map(p => ({ label:'Priority: ' + PRIORITIES[p].name, fn:() => { Store.updateTask(id, { priority:p }); this.render(); } })),
        { label:'Clear priority', fn:() => { Store.updateTask(id, { priority:null }); this.render(); } },
        '-',
        { label:'Due today', fn:() => { Store.updateTask(id, { dueDate:U.today() }); this.render(); } },
        { label:'Due tomorrow', fn:() => { Store.updateTask(id, { dueDate:U.addDays(U.today(),1) }); this.render(); } },
        { label:'Clear due date', fn:() => { Store.updateTask(id, { dueDate:null }); this.render(); } },
        '-',
        { label:'Duplicate', ico:'&#128203;', fn:() => {
            const copy = JSON.parse(JSON.stringify(t)); delete copy.id;
            copy.name = t.name + ' (copy)'; copy.comments = [];
            Store.addTask(t.listId, copy); this.render(); U.toast('Duplicated');
          } },
        { label:'Delete task', ico:'&#128465;', danger:true, fn:() => { Store.deleteTask(id); if (Drawer.taskId === id) Drawer.close(); this.render(); } }
      ];
      return this.ctx(x, y, items);
    }
    if (kind === 'list'){
      const l = Store.list(id);
      return this.ctx(x, y, [
        { label:'Open', fn:() => this.go('#/list/' + id) },
        { label:'Add task', ico:'+', fn:() => this.quickAdd(id, null, null) },
        { label:'Rename', ico:'&#9998;', fn:() => this.rename('list', id) },
        { label:'Edit statuses', ico:'&#9881;', fn:() => this.editStatuses(id) },
        '-',
        { label:'Delete list', ico:'&#128465;', danger:true, fn:() => {
            if (confirm(`Delete list "${l.name}" and its ${Store.tasksIn(id,{includeSubs:true}).length} tasks?`)){
              Store.deleteList(id);
              if (this.route.listId === id) this.go('#/home'); else this.render();
            }
          } }
      ]);
    }
    if (kind === 'folder'){
      const f = Store.folder(id);
      return this.ctx(x, y, [
        { label:'New list here', ico:'+', fn:() => this.newList(f.spaceId, id) },
        { label:'Rename', ico:'&#9998;', fn:() => this.rename('folder', id) },
        '-',
        { label:'Delete folder', ico:'&#128465;', danger:true, fn:() => {
            if (confirm(`Delete folder "${f.name}" and everything in it?`)){ Store.deleteFolder(id); this.go('#/home'); }
          } }
      ]);
    }
    if (kind === 'space'){
      const sp = Store.space(id);
      return this.ctx(x, y, [
        { label:'New list', ico:'&#9776;', fn:() => this.newList(id, null) },
        { label:'New folder', ico:'&#128193;', fn:() => this.newFolder(id) },
        { label:'Rename', ico:'&#9998;', fn:() => this.rename('space', id) },
        '-',
        { label:'Delete space', ico:'&#128465;', danger:true, fn:() => {
            if (confirm(`Delete space "${sp.name}" and everything in it?`)){ Store.deleteSpace(id); this.go('#/home'); }
          } }
      ]);
    }
  }
};


/* ============================================================================
 * Global (hash-guarded) keydown — the ONLY document-level listener the clone
 * keeps. Registered once in CV2.boot(). Drops keys the console owns:
 * '/', 't', Escape, and any Cmd/Ctrl (Cmd/Ctrl-K palette). Keeps n, [, g-nav,
 * and 1-5 view switches, scoped to the #/campaigns-v2 route.
 * ==========================================================================*/
function cv2Keydown(e){
  if (!/^#\/campaigns-v2(\/|$)/.test(location.hash)) return;   // inert off-route, never throws
  if (e.metaKey || e.ctrlKey || e.altKey) return;               // let the console own Cmd/Ctrl-K etc.
  var ae = document.activeElement;
  var typing = ae && (/^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName) || ae.isContentEditable);
  if (typing) return;
  if (e.key.toLowerCase() === 'n'){ e.preventDefault(); var b = document.getElementById('cv2-newTaskBtn'); if (b) b.click(); return; }
  if (e.key === '['){ var r = document.getElementById('cv2root'); if (r) r.classList.toggle('sb-collapsed'); return; }
  if (e.key.toLowerCase() === 'g'){ App._g = true; setTimeout(function(){ App._g = false; }, 900); return; }
  if (App._g){
    var map = { h:'#/home', m:'#/mytasks', e:'#/everything', d:'#/dashboard' };
    var dest = map[e.key.toLowerCase()];
    if (dest){ App._g = false; return App.go(dest); }
  }
  if (/^[1-5]$/.test(e.key) && App.route.name !== 'home' && App.route.name !== 'dashboard'){
    var v = VIEWS[Number(e.key) - 1];
    if (v){
      if (App.route.name === 'list') App.go('#/list/' + App.route.listId + '/' + v.id);
      else { App.route.view = v.id; App.render(); }
    }
  }
}

/* ============================================================================
 * FIXTURE store — a self-contained in-memory workspace used ONLY when the
 * console hands us an inert stub (no .state / no .tasksIn). Implements the full
 * method surface the kept files call, seeded with 1 space + 2 lists + a handful
 * of tasks across the 4 default statuses so the chrome renders with content.
 * The real shared-data adapter (window.VMOPS.cv2Store) arrives in P5.
 * ==========================================================================*/
const CV2_DEFAULT_STATUSES = [
  { id:'st_new',     name:'New',            color:'#868a96', type:'open'   },
  { id:'st_triaged', name:'Triaged',        color:'#7b68ee', type:'open'   },
  { id:'st_active',  name:'In Remediation', color:'#49ccf9', type:'active' },
  { id:'st_done',    name:'Resolved',       color:'#2ecc8f', type:'closed' }
];
function cv2Fixture(){
  const now = Date.now();
  const day = 86400000;
  const statuses = () => CV2_DEFAULT_STATUSES.map(s => Object.assign({}, s));
  const mk = (o) => Object.assign({
    id:o.id, listId:o.listId, parentId:null, name:o.name, statusId:o.statusId,
    priority:o.priority||null, assignees:o.assignees||[], description:o.description||'',
    dueDate:o.dueDate||null, tags:o.tags||[], checklist:o.checklist||[], comments:o.comments||[],
    startDate:o.startDate||null, timeEstimate:o.timeEstimate||0, timeSpent:o.timeSpent||0,
    archived:false, order:o.order||0, createdAt:o.createdAt||now, updatedAt:o.updatedAt||now
  }, {});
  const state = {
    meta: { currentUser:'own_joe', timer:null },
    members: [
      { id:'own_joe',  name:'Joe Cook',     color:'#7b68ee' },
      { id:'own_alex', name:'Alex Rivera',  color:'#49ccf9' },
      { id:'own_sam',  name:'Sam Ortiz',    color:'#2ecc8f' }
    ],
    spaces: [ { id:'sp_campaigns', name:'Campaigns', color:'#7b68ee', collapsed:false } ],
    folders: [],
    lists: [
      { id:'li_q3',  spaceId:'sp_campaigns', folderId:null, name:'Q3 Critical Patching', defaultView:'list',  statuses:statuses() },
      { id:'li_kev', spaceId:'sp_campaigns', folderId:null, name:'KEV Remediation',      defaultView:'board', statuses:statuses() }
    ],
    tasks: [
      mk({ id:'tk1', listId:'li_q3',  name:'CVE-2024-3400 PAN-OS command injection', statusId:'st_new',     priority:1, assignees:['own_joe'],  dueDate:U.addDays(U.today(),2),  tags:[{name:'Critical',color:'#e8506e'},{name:'KEV',color:'#f5a623'}], order:0 }),
      mk({ id:'tk2', listId:'li_q3',  name:'Patch Log4j on 14 app servers',          statusId:'st_triaged', priority:2, assignees:['own_alex'], dueDate:U.addDays(U.today(),5),  tags:[{name:'High',color:'#fd71af'}], checklist:[{id:'c1',text:'Inventory affected hosts',done:true},{id:'c2',text:'Schedule maintenance window',done:false}], order:1 }),
      mk({ id:'tk3', listId:'li_q3',  name:'Upgrade OpenSSL 3.0.x fleet-wide',       statusId:'st_active',  priority:2, assignees:['own_sam'],  dueDate:U.addDays(U.today(),-1), order:2 }),
      mk({ id:'tk4', listId:'li_q3',  name:'Verify MS Exchange cumulative update',   statusId:'st_done',    priority:3, assignees:['own_joe'],  order:3 }),
      mk({ id:'tk5', listId:'li_kev', name:'Citrix NetScaler CVE-2023-4966 (Bleed)', statusId:'st_new',     priority:1, assignees:['own_alex'], dueDate:U.today(), tags:[{name:'KEV',color:'#f5a623'}], order:0 }),
      mk({ id:'tk6', listId:'li_kev', name:'MOVEit Transfer SQLi remediation',        statusId:'st_active',  priority:1, assignees:['own_sam','own_joe'], dueDate:U.addDays(U.today(),3), order:1 }),
      mk({ id:'tk7', listId:'li_kev', name:'Confirm Fortinet SSL-VPN patched',        statusId:'st_done',    priority:2, assignees:['own_joe'],  order:2 })
    ]
  };

  const store = {
    state,
    get me(){ return state.meta.currentUser; },
    get idbAvailable(){ return true; },
    get staleSeed(){ return false; },
    load(){ return this; },
    save(){ return true; },
    readFromIdb(){ return Promise.resolve(state); },
    list(id){ return state.lists.find(l => l.id === id) || null; },
    space(id){ return state.spaces.find(s => s.id === id) || null; },
    folder(id){ return state.folders.find(f => f.id === id) || null; },
    member(id){ return state.members.find(m => m.id === id) || null; },
    task(id){ return state.tasks.find(t => t.id === id) || null; },
    listsInSpace(spaceId){ return state.lists.filter(l => l.spaceId === spaceId); },
    listsInFolder(folderId){ return state.lists.filter(l => l.folderId === folderId); },
    foldersInSpace(spaceId){ return state.folders.filter(f => f.spaceId === spaceId); },
    rootLists(spaceId){ return state.lists.filter(l => l.spaceId === spaceId && !l.folderId); },
    tasksIn(listId){ return state.tasks.filter(t => t.listId === listId && !t.parentId); },
    allTasks(){ return state.tasks.slice(); },
    subtasks(){ return []; },
    statusesFor(listId){ const l = this.list(listId); return (l && l.statuses) || CV2_DEFAULT_STATUSES; },
    status(listId, statusId){
      const sts = this.statusesFor(listId);
      return sts.find(s => s.id === statusId) || sts[0] || { name:'', color:'#868a96', type:'open' };
    },
    isDone(t){ if (!t) return false; const s = this.status(t.listId, t.statusId); return !!s && s.type === 'closed'; },
    listPath(listId){
      const l = this.list(listId); if (!l) return [];
      const out = []; const sp = this.space(l.spaceId); if (sp) out.push(sp);
      const f = l.folderId ? this.folder(l.folderId) : null; if (f) out.push(f);
      out.push(l); return out;
    },
    allTags(){
      const seen = new Map();
      state.tasks.forEach(t => (t.tags || []).forEach(tg => { if (!seen.has(tg.name)) seen.set(tg.name, tg); }));
      return Array.from(seen.values());
    },
    updateTask(id, patch){
      const t = this.task(id); if (!t) return null;
      Object.assign(t, patch); t.updatedAt = Date.now(); return t;
    },
    toggleDone(id){
      const t = this.task(id); if (!t) return;
      const sts = this.statusesFor(t.listId);
      const cur = this.status(t.listId, t.statusId);
      const next = cur.type === 'closed' ? (sts.find(s => s.type !== 'closed') || sts[0])
                                         : (sts.find(s => s.type === 'closed') || sts[sts.length-1]);
      if (next){ t.statusId = next.id; t.updatedAt = Date.now(); }
    },
    addTask(listId, patch){
      const first = (this.statusesFor(listId)[0] || {}).id;
      const t = mk(Object.assign({ id:U.uid('tk'), listId:listId, name:'', statusId:first, order:state.tasks.length }, patch || {}));
      state.tasks.push(t); return t;
    },
    deleteTask(id){ const i = state.tasks.findIndex(t => t.id === id); if (i >= 0) state.tasks.splice(i, 1); },
    startTimer(){ /* no-op in fixture */ },
    stopTimer(){ return 0; },
    reset(){ U.toast('Reset is disabled in the Campaigns v2 preview'); },
    importJSON(){ throw new Error('Import is disabled in the Campaigns v2 preview'); },
    exportJSON(){ return JSON.stringify(state, null, 2); },
    addList(){ return null; },
    addSpace(){ return null; },
    addFolder(){ return null; },
    deleteList(){ /* no-op */ },
    deleteSpace(){ /* no-op */ },
    deleteFolder(){ /* no-op */ }
  };
  return store;
}
const FIXTURE = cv2Fixture();

/* ============================================================================
 * Shell markup injected into the mount root (cv2root). This is the clone's
 * index.html #app inner content (sidebar + main) PLUS the drawer/modal/ctx/
 * toast overlays, with the fixed id/class rename map applied. cv2root itself
 * plays the role of the old #app grid; the overlays live inside it so the
 * router's innerHTML wipe tears them down for free.
 * ==========================================================================*/
const SHELL_HTML = `
  <aside id="cv2-sidebar">
    <div class="sb-head">
      <div class="workspace" id="cv2-workspaceBtn" title="Workspace">
        <span class="ws-avatar">VM</span>
        <span class="ws-name" title="Campaigns">Campaigns</span>
      </div>
      <button class="icon-btn" id="cv2-collapseBtn" title="Collapse sidebar">&#9776;</button>
    </div>
    <div class="sb-search">
      <span class="sb-search-ico">&#128269;</span>
      <input type="search" id="cv2-globalSearch" placeholder="Search tasks..." autocomplete="off">
      <kbd>/</kbd>
    </div>
    <nav class="sb-nav">
      <a class="sb-link" data-route="#/home"><span class="ico">&#127968;</span>Home</a>
      <a class="sb-link" data-route="#/mytasks"><span class="ico">&#9989;</span>My Tasks <span class="c2pill" id="cv2-myTasksCount">0</span></a>
      <a class="sb-link" data-route="#/everything"><span class="ico">&#128506;</span>Everything</a>
      <a class="sb-link" data-route="#/findings"><span class="ico">&#128269;</span>Findings</a>
      <a class="sb-link" data-route="#/remediations"><span class="ico">&#128736;</span>Remediations</a>
      <a class="sb-link" data-route="#/dashboard"><span class="ico">&#128202;</span>Dashboards</a>
    </nav>
    <div class="sb-section-head">
      <span>Spaces</span>
      <button class="icon-btn sm" id="cv2-addSpaceBtn" title="New Space">+</button>
    </div>
    <div id="cv2-spaceTree" class="space-tree"></div>
    <div class="sb-foot">
      <button class="sb-foot-btn" id="cv2-settingsBtn" title="Branding and themes"><span class="ico">&#9881;</span><span>Settings</span></button>
      <button class="sb-foot-btn" id="cv2-dataBtn" title="Import / Export"><span class="ico">&#128190;</span><span>Data</span></button>
      <button class="sb-foot-btn" id="cv2-helpBtn" title="Keyboard shortcuts"><span class="ico">&#10067;</span><span>Help</span></button>
    </div>
  </aside>

  <main id="cv2-main">
    <header id="cv2-topbar">
      <div class="tb-left">
        <button class="icon-btn only-mobile" id="cv2-mobileMenuBtn" title="Show sidebar">&#9776;</button>
        <div id="cv2-breadcrumb" class="breadcrumb"></div>
      </div>
      <div class="tb-right">
        <div id="cv2-timerChip" class="timer-chip hidden"></div>
        <button class="btn primary" id="cv2-newTaskBtn"><span>+</span> New Task</button>
        <div class="avatar me" id="cv2-meAvatar" title="You">JC</div>
      </div>
    </header>
    <div id="cv2-viewbar" class="viewbar"></div>
    <div id="cv2-toolbar" class="c2toolbar"></div>
    <section id="cv2-content" class="content"></section>
  </main>

  <div id="cv2drawerScrim" class="scrim hidden"></div>
  <aside id="cv2drawer" class="c2drawer hidden" aria-label="Task detail"></aside>

  <div id="cv2-modalScrim" class="scrim hidden">
    <div id="cv2-modal" class="modal" role="dialog" aria-modal="true"></div>
  </div>

  <div id="cv2-ctxMenu" class="ctx-menu hidden"></div>
  <div id="cv2-toasts" class="toasts"></div>
`;

/* ============================================================================
 * window.CV2 — the contract the console router drives. boot() is one-time
 * global wiring; mount()/unmount() are per-view. Bare consts above never reach
 * window; only this object is exposed.
 * ==========================================================================*/
window.CV2 = {
  _booted: false,
  _root: null,
  _store: null,
  _abort: null,
  _timer: null,

  boot: function(){
    if (this._booted) return;
    this._booted = true;
    document.addEventListener('keydown', cv2Keydown);   // single, hash-guarded
  },

  mount: function(rootEl, store){
    this.boot();
    this._root = rootEl;
    // Adapter if it carries a real projection; else the in-memory FIXTURE.
    Store = (store && store.state && typeof store.tasksIn === 'function') ? store : FIXTURE;
    this._store = Store;

    rootEl.innerHTML = SHELL_HTML;

    this._abort = new AbortController();
    App.bind(rootEl, this._abort.signal);   // per-view wiring (contextmenu/click via signal)

    Theme.apply();                          // scoped to #cv2root, seeded from console light/dark
    Brand.apply();

    var me = Store.member(Store.me);
    if (me){
      var av = document.getElementById('cv2-meAvatar');
      if (av){ av.textContent = U.initials(me.name); av.style.background = me.color; }
    }

    App.parseRoute();                       // reads location.hash, renders
    App.tickTimer();
    this._timer = setInterval(function(){ App.tickTimer(); }, 30000);

    window._cv2Cleanup = function(){ if (window.CV2) window.CV2.unmount(); };
  },

  rerender: function(){ if (App && App.render) App.render(); },

  unmount: function(){
    if (this._abort){ try { this._abort.abort(); } catch(e){} this._abort = null; }
    if (this._timer){ clearInterval(this._timer); this._timer = null; }
    if (typeof Drawer !== 'undefined') Drawer.taskId = null;
    this._root = null;
    // DOM subtree (shell + overlays) is wiped by the console router's innerHTML reset.
  }
};

})();
