/* Tenable VM Dashboard — native VM Ops page. Renders into #app on #/tvd,
   wraps the original app so its functions persist (STATE held across navigation). */
(function(){
  var app=document.getElementById('app');
  var TVD_MARKUP='<div class="tvdapp">'+`<div class="tvdhead">
    <div class="overline">Tenable Dashboard</div>
    <h1>Your Tenable vulnerability program</h1>
    <p class="lede">Upload your Tenable SC exports for instant KPIs, severity and SLA trends, top findings, and one-click reports — all in your browser.</p>
  </div>
  <div class="tvdtools row noprint">
    <span class="priv">&#128274; 100% local — your data never leaves this browser</span>
    <select id="cbSel" class="hostinput" style="width:auto;padding:8px 10px" title="Color-blind-safe palette" aria-label="Color palette">
      <option value="default">Vivid</option>
      <option value="deuteranopia">Deuteranopia-safe</option>
      <option value="protanopia">Protanopia-safe</option>
      <option value="tritanopia">Tritanopia-safe</option>
    </select>
    <select id="exportSel" class="hostinput" style="width:auto;padding:8px 10px">
      <option value="report-html">Full report (HTML)</option>
      <option value="report-pdf">Full report (PDF / print)</option>
      <option value="full-csv">Full report (CSV)</option>
      <option value="full-xlsx">Full report (XLSX)</option>
      <option value="full-csv-clip">Full report (CSV → clipboard)</option>
      <option value="full-tsv-clip">Full report (Excel paste → clipboard)</option>
      <option value="full-img-clip">Full report (image → clipboard)</option>
      <option value="exec-md">Executive report (Markdown)</option>
      <option value="sla-csv">SLA summary (CSV)</option>
      <option value="sla-xlsx">SLA summary (XLSX)</option>
      <option value="topvulns-csv">Top exploitable vulns (CSV)</option>
      <option value="hosts-csv">Most-exposed hosts (CSV)</option>
      <option value="breakdowns-csv">Severity / OS / cloud breakdowns (CSV)</option>
      <option value="all-xlsx">All summaries (multi-sheet XLSX)</option>
      <option value="metrics-json">Computed metrics (JSON)</option>
      <option value="open-csv">Full open dataset (CSV)</option>
      <option value="mit-csv">Full mitigated dataset (CSV)</option>
    </select>
    <button class="btn ghost" id="exportBtn">Export</button>
    <button class="btn ghost" id="cfgSla">SLA</button>
    <button class="btn ghost" id="reset">Reset</button>
  </div>
<main>
  <div id="jumpBar" class="noprint" style="display:none;position:sticky;top:0;z-index:30;padding:10px 0;margin:0 0 10px;background:var(--bg);border-bottom:1px solid var(--line)">
    <div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap">
      <label class="sub" style="display:flex;align-items:center;gap:8px;margin:0">Segment
        <select id="segSel" class="hostinput" style="width:auto;padding:8px 10px" title="Filter the whole dashboard to one segment"></select></label>
      <label class="sub" style="display:flex;align-items:center;gap:8px;margin:0">Jump to section
        <select id="jumpSel" class="hostinput" style="width:auto;padding:8px 10px"></select></label>
    </div>
  </div>
  <section id="uploader">
    <div class="drop" id="drop">
      <h2>Load your Tenable SC analysis exports</h2>
      <p>Two CSV exports from the <code>/analysis</code> vulndetails view — one with <b>sourceType=cumulative</b> (open),
         one with <b>sourceType=patched</b> (mitigated). Or a single Excel workbook with both sheets.</p>
      <div class="row">
        <button class="btn" id="pickCum">Cumulative (open) CSV</button>
        <button class="btn" id="pickMit">Mitigated CSV</button>
        <button class="btn xlsx" id="pickWb">Workbook (.xlsx)</button>
        <button class="btn sample" id="loadSample">Load sample data</button>
      </div>
      <p id="loadState" class="sub" style="margin-top:12px"></p>
      <p class="sub" style="margin-top:4px;max-width:640px;margin-left:auto;margin-right:auto">
        Everything runs in your browser's memory, so file size is bounded by available RAM.
        On a 16&nbsp;GB laptop also running Excel, Word, Teams and Outlook, keep each CSV under
        roughly <b>100&nbsp;MB (~250,000 findings)</b> for smooth performance. Larger files still
        work but parse and render more slowly; close other heavy tabs first. <code>.xlsx</code>
        workbooks parse slower than CSV at the same row count.
      </p>
      <input type="file" id="fileCum" accept=".csv,.json" class="hidden" />
      <input type="file" id="fileMit" accept=".csv,.json" class="hidden" />
      <input type="file" id="fileWb" multiple accept=".xlsx,.xls,.csv,.json" class="hidden" />
    </div>
  </section>
  <section id="dashboard" class="hidden"></section>
  <div class="foot">
    Built for security teams who can't send scan data to a SaaS. Open the Network tab — there are no uploads.
    &nbsp;·&nbsp; <a href="https://github.com/cloudanimal/vm-ops-console" target="_blank" rel="noopener noreferrer">source on GitHub</a>
  </div>
</main>
<div id="tt" class="noprint" style="position:fixed;z-index:1000;pointer-events:none;max-width:340px;background:#0d1016;color:#f4f5f8;border:1px solid rgba(255,255,255,.16);border-radius:8px;padding:10px 13px;font-size:13.5px;font-weight:400;line-height:1.5;box-shadow:0 8px 26px rgba(0,0,0,.45);opacity:0;transition:opacity .1s;display:none"></div>
<div id="loading" class="noprint" style="position:fixed;inset:0;z-index:2000;display:none;align-items:center;justify-content:center;background:rgba(8,9,13,.8)">
  <div style="text-align:center;color:#f4f5f8">
    <div style="width:42px;height:42px;border:4px solid rgba(255,255,255,.2);border-top-color:#4f8cff;border-radius:50%;margin:0 auto 14px;animation:spin 1s linear infinite"></div>
    <div id="loadingMsg" style="font-size:14px">Loading…</div>
  </div>
</div>`+'</div>';
  var STATE;
  // Reset the render cache before each (re)boot: STATE/window._report persist across navigation,
  // so a stale window._report would make boot-time applyPalette() call render() before its module
  // consts (charts/EXPL/etc.) initialize (TDZ). End-of-boot render() rebuilds from persisted STATE.
  window.TVD={ open:function(){ window._report=null; app.className=''; app.innerHTML=TVD_MARKUP; boot(); } };
  function boot(){

const SLA = 0.25;                       // exploitable vulns per host
if(window.Chart) Chart.defaults.animation = false;   // faster first render on slow machines
const nextPaint = () => new Promise(r=>setTimeout(r, 30));
function showLoading(m){ const l=document.getElementById('loading'); if(!l) return; document.getElementById('loadingMsg').textContent=m||'Loading…'; l.style.display='flex'; }
function hideLoading(){ const l=document.getElementById('loading'); if(l) l.style.display='none'; }
const $ = s => document.querySelector(s);
const DEFAULT_SLA_DAYS = { Critical: 30, High: 30, Medium: 90, Low: 120 };
if(!STATE) STATE = { cumulative: [], mitigated: [], hostOverride: {}, topN: 5, summaryN: 5, cbTheme: 'protanopia', topSev: 'all', hostsN: 10, hostsSev: 'all', segFilter: 'all',
  slaDays: { ...DEFAULT_SLA_DAYS } };
const PALS_DEFAULT = {crit:'#e24b4a', high:'#ef9f27', med:'#378add', low:'#888780', info:'#5a5f6e', ok:'#3bb273', accent:'#4f8cff'};
const PALS_CB = {
  deuteranopia: {
    dark:  {crit:'#cc3311', high:'#ee7733', med:'#0077bb', low:'#33bbee', info:'#999999', ok:'#009988', accent:'#0077bb'},
    light: {crit:'#a82a0e', high:'#a85f08', med:'#005a8c', low:'#1a78a8', info:'#5f6670', ok:'#00706a', accent:'#005a8c', bg:'#e9ecf1', panel:'#ffffff'}
  },
  protanopia: {
    dark:  {crit:'#bb5566', high:'#ddaa33', med:'#4f8fcf', low:'#88ccee', info:'#999999', ok:'#44bb99', accent:'#4f8fcf'},
    light: {crit:'#7a3340', high:'#8f6a13', med:'#003f73', low:'#356699', info:'#5f6670', ok:'#0f663a', accent:'#003f73', bg:'#e9ecf1', panel:'#ffffff'}
  },
  tritanopia: {
    dark:  {crit:'#ee3377', high:'#f57c00', med:'#9a4ec2', low:'#bdbdbd', info:'#d0d0d0', ok:'#19a3a3', accent:'#ee3377'},
    light: {crit:'#b0144d', high:'#bd5800', med:'#5e1a8a', low:'#6b6b6b', info:'#8a8a8a', ok:'#006b67', accent:'#b0144d', bg:'#f1ecef', panel:'#ffffff'}
  }
};
const tvdRoot = () => document.querySelector('.tvdapp') || document.documentElement;
const curMode = () => { var t=document.documentElement.dataset.theme; if(t) return t==='light'?'light':'dark'; return (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light'; };
const PAL = () => STATE.cbTheme==='default' ? PALS_DEFAULT : PALS_CB[STATE.cbTheme][curMode()];
function applyPalette(name){
  STATE.cbTheme = PALS_CB[name] ? name : 'default';
  const root = tvdRoot().style;   // scope palette overrides to .tvdapp so they never leak to the shell
  ['--crit','--high','--med','--low','--ok','--accent','--bg','--panel'].forEach(k=>root.removeProperty(k));
  if(STATE.cbTheme!=='default'){ const p=PAL();
    root.setProperty('--crit',p.crit); root.setProperty('--high',p.high); root.setProperty('--med',p.med);
    root.setProperty('--low',p.low); root.setProperty('--ok',p.ok); root.setProperty('--accent',p.accent);
    if(p.bg) root.setProperty('--bg',p.bg); if(p.panel) root.setProperty('--panel',p.panel);
  }
  try{ localStorage.setItem('tvd-cb', STATE.cbTheme); }catch(e){}
  const sel=document.getElementById('cbSel'); if(sel) sel.value=STATE.cbTheme;
  if(window._report) render();
}
let charts = [];
let EXPL = [];

// ---------- ingest ----------
const drop = $('#drop');
['dragover','dragenter'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.add('hover')}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.remove('hover')}));
drop.addEventListener('drop', ev => handleFiles(ev.dataTransfer.files));
$('#pickCum').addEventListener('click', ()=>$('#fileCum').click());
$('#pickMit').addEventListener('click', ()=>$('#fileMit').click());
$('#pickWb').addEventListener('click', ()=>$('#fileWb').click());
$('#fileCum').addEventListener('change', e=>handleFiles(e.target.files,'cumulative'));
$('#fileMit').addEventListener('change', e=>handleFiles(e.target.files,'mitigated'));
$('#fileWb').addEventListener('change', e=>handleFiles(e.target.files));
$('#loadSample').addEventListener('click', loadSample);
// Convenience: ?autosample=1 loads the bundled sample on page load (handy for demo links / screenshots).
if(/[?&]autosample=1/.test(location.search)) window.addEventListener('load', loadSample);
$('#reset').addEventListener('click', ()=>location.reload());
$('#exportBtn').addEventListener('click', ()=>doExport($('#exportSel').value));
$('#jumpSel').addEventListener('change', e=>{ if(e.target.value){ const el=document.getElementById(e.target.value);
  if(el) el.scrollIntoView({behavior:'smooth',block:'start'}); e.target.value=''; } });
$('#segSel').addEventListener('change', e=>{ STATE.segFilter=e.target.value; if(window._report) render(); });
$('#cbSel').addEventListener('change', e=>applyPalette(e.target.value));
applyPalette((function(){ try{ return localStorage.getItem('tvd-cb'); }catch(e){ return null; } })() || 'protanopia');
$('#cfgSla').addEventListener('click', ()=>{ const el=document.getElementById('slaConfig');
  if(el){ el.scrollIntoView({behavior:'smooth',block:'start'}); const inp=el.querySelector('.slainp'); if(inp) setTimeout(()=>inp.focus(),300); }
  else alert('Load your Tenable data first to configure SLAs.'); });
function tc(){ return getComputedStyle(tvdRoot()).getPropertyValue('--muted').trim()||'#9aa3b2'; }
function gc(){ return getComputedStyle(tvdRoot()).getPropertyValue('--line').trim()||(curMode()==='light'?'rgba(0,0,0,.10)':'#2a2f3e'); }
function setState(){ const s=$('#loadState'); if(s) s.textContent =
  `Loaded: ${STATE.cumulative.length} open · ${STATE.mitigated.length} mitigated`; }

function isDataSheet(rows){
  return rows.length && rows.some(r => ('pluginID' in r) || ('exploitAvailable' in r) || ('severity' in r));
}
const isMitigated = r => String(r.hasBeenMitigated).toLowerCase()==='yes';
function classify(rows, name){
  const n = (name||'').toLowerCase();
  if(n.includes('mitigat') || n.includes('patch')) return 'mitigated';
  if(n.includes('cumulat') || n.includes('vuln')) return rows.some(isMitigated)?'mitigated':'cumulative';
  return rows.some(isMitigated) ? 'mitigated' : 'cumulative';
}
function addRows(rows, name, forcedKind){
  if(!rows.length) return;
  const kind = forcedKind || classify(rows, name);
  STATE[kind] = STATE[kind].concat(rows);
}
async function handleFiles(fileList, forcedKind){
  if(!fileList || !fileList.length) return;
  showLoading('Reading file…'); await nextPaint();
  try{
  for(const f of fileList){
    const ext = f.name.split('.').pop().toLowerCase();
    if(ext==='xlsx'||ext==='xls'){
      const wb = XLSX.read(await f.arrayBuffer(), {type:'array'});
      wb.SheetNames.forEach(sn=>{
        const rows = XLSX.utils.sheet_to_json(wb.Sheets[sn], {defval:''});
        if(isDataSheet(rows)) addRows(rows, sn);
      });
    } else if(ext==='csv'){
      const rows = Papa.parse(await f.text(), {header:true, skipEmptyLines:true, dynamicTyping:false}).data;
      addRows(rows, f.name, forcedKind);
    } else if(ext==='json'){
      let data = JSON.parse(await f.text());
      if(!Array.isArray(data)) data = data.results || data.response?.results || [];
      addRows(data, f.name, forcedKind);
    }
  }
  setState();
  showLoading('Building dashboard…'); await nextPaint();
  if(STATE.cumulative.length || STATE.mitigated.length) render();
  } finally { hideLoading(); }
}
async function loadSample(){
  const note=document.getElementById('loadState');
  const warn = html => { if(note){ note.innerHTML=html; note.style.color='var(--warn)'; } };
  // Browsers block fetch() of local files, so the bundled sample can't auto-load from file://
  if(location.protocol==='file:'){
    warn('⚠️ The bundled sample can’t auto-load when this page is opened directly as a file (<code>file://</code>) — browsers block reading the local CSVs. '
       + 'Run a quick local server in this folder — <code>python3 -m http.server</code> — then reload, or drag your own Tenable exports into the buttons above (manual uploads work fine from <code>file://</code>). '
       + 'The live demo also has it built in: <b>cloudanimal.github.io/vm-ops-console</b>');
    return;
  }
  try{
    showLoading('Loading sample data…'); await nextPaint();
    const parseCsv = (text, kind) => {
      const rows = Papa.parse(text, {header:true, skipEmptyLines:true, dynamicTyping:false}).data;
      addRows(rows, kind, kind);
    };
    const [cum, mit] = await Promise.all([
      fetch('https://cloudanimal.github.io/tenable-vm-dashboard/sample-data/cumulative.csv').then(r=>r.text()),
      fetch('https://cloudanimal.github.io/tenable-vm-dashboard/sample-data/mitigated.csv').then(r=>r.text())
    ]);
    showLoading('Parsing findings…'); await nextPaint();
    parseCsv(cum, 'cumulative'); parseCsv(mit, 'mitigated');
    setState();
    showLoading('Building dashboard…'); await nextPaint();
    render();
  }catch(e){ warn('⚠️ Could not load the bundled sample (' + (e&&e.message||e) + '). '
       + 'Serve the page over http — <code>python3 -m http.server</code> — or drag your own exports into the buttons above.'); }
  finally{ hideLoading(); }
}

// ---------- helpers ----------
const isExpl = r => String(r.exploitAvailable).toLowerCase()==='yes';
const bu = r => r.repository || r.repositoryID || 'unknown';
const sevOrder = {Critical:4,High:3,Medium:2,Low:1,Info:0};
function uniqHosts(rows){ return new Set(rows.map(r=>r.ip||r.dnsName)).size; }
function groupCount(rows, keyfn){ const m={}; rows.forEach(r=>{const k=keyfn(r); m[k]=(m[k]||0)+1}); return m; }
function fmtNum(n){ return (n||0).toLocaleString(); }
function daysBetween(a,b){ const da=new Date(a), db=new Date(b); return (db-da)/86400000; }

// ---------- render ----------
function render(){
  $('#uploader').classList.add('hidden');
  const d = $('#dashboard'); d.classList.remove('hidden'); d.innerHTML='';
  charts.forEach(c=>c.destroy()); charts=[];
  const segOK = r => STATE.segFilter==='all' || bu(r)===STATE.segFilter;
  const cum = STATE.cumulative.filter(segOK), mit = STATE.mitigated.filter(segOK);
  const expl = cum.filter(isExpl); EXPL = expl;
  const buses = [...new Set([...cum,...mit].map(bu))].sort();

  // host denominators (override-able)
  const hostsByBu = {}; buses.forEach(b=>{
    const detected = uniqHosts([...cum,...mit].filter(r=>bu(r)===b));
    hostsByBu[b] = STATE.hostOverride[b] || detected;
  });
  const totalHosts = Object.values(hostsByBu).reduce((a,b)=>a+b,0);
  const ipCount = new Set([...cum, ...mit].map(r=>r.ip).filter(Boolean)).size;
  const explPerHost = expl.length/Math.max(totalHosts,1);

  // MTTR from mitigated (kept for export; not shown — a 30-day mitigated window can't yield a true org MTTR)
  const mttrVals = mit.map(r=> (r.firstSeen&&r.lastSeen)? daysBetween(r.firstSeen,r.lastSeen):null).filter(v=>v!=null&&v>=0);
  const mttr = mttrVals.length? mttrVals.reduce((a,b)=>a+b,0)/mttrVals.length : null;

  // Open age: how long currently-open findings have been open (now − firstSeen). Honest single-export backlog metric.
  const openAgeVals = cum.map(r=> r.firstSeen? daysBetween(r.firstSeen, Date.now()):null).filter(v=>v!=null&&v>=0).sort((a,b)=>a-b);
  const median = a => a.length? (a.length%2? a[(a.length-1)/2] : (a[a.length/2-1]+a[a.length/2])/2) : null;
  const openAgeMedian = median(openAgeVals);
  const openAgeMean = openAgeVals.length? openAgeVals.reduce((a,b)=>a+b,0)/openAgeVals.length : null;

  // vulnerabilities published more than 1 year ago (by vuln publication date)
  const oneYrAgo = Date.now() - 365*86400000;
  const oldPub = cum.filter(r=> r.vulnPubDate && new Date(r.vulnPubDate).getTime() < oneYrAgo).length;
  // findings first detected (firstSeen) more than 1 year ago
  const oldSeen = cum.filter(r=> r.firstSeen && new Date(r.firstSeen).getTime() < oneYrAgo).length;
  // findings referencing Log4j (plugin name / synopsis / description / cve / output)
  const log4j = cum.filter(r=> /log4j/i.test([r.pluginName,r.synopsis,r.description,r.cve,r.pluginText].join(' '))).length;

  d.appendChild(html(`
    <div class="cards">
      ${kpi('IP Addresses', fmtNum(ipCount), null, null, 'Count of unique IP addresses in the IP column (open + mitigated data).')}
      ${kpi('Total Vulnerabilities', fmtNum(cum.length), null, null, 'All open vulnerability findings (cumulative export). One row = one plugin finding on one host:port.')}
      ${kpi('Total Exploitable', `<span style="color:var(--crit)">${fmtNum(expl.length)}</span>`, null, null, 'Open findings flagged exploitAvailable = Yes.')}
      <div class="card" title="Open findings (all severities) past their remediation SLA. Driven by the SLA day targets in the config panel."><div class="l">Total past SLA</div>
        <div class="v" id="kpiPastTotal" style="color:var(--crit)">0</div></div>
      <div class="card" title="Exploitable findings past their remediation SLA ÷ unique IPs. Turns red over the ${SLA} per-IP threshold. Driven by the SLA day targets in the config panel."><div class="l">Avg Past SLA</div>
        <div class="v" id="kpiPastPer">0.000</div>
        <div class="sub" id="kpiPastSub" style="color:var(--ok)">SLA ${SLA}</div></div>
      ${kpi('Published &gt; 1 yr ago', fmtNum(oldPub), null, null, 'Open findings whose vulnerability publish date (vulnPubDate) is older than 1 year.')}
      ${kpi('1st seen &gt; 1 yr ago', fmtNum(oldSeen), null, null, 'Open findings first detected in your environment (firstSeen) more than 1 year ago.')}
      ${kpi('Log4j', `<span style="color:var(--crit)">${fmtNum(log4j)}</span>`, null, null, 'Open findings referencing Log4j (plugin name, synopsis, description, CVE, or output).')}
      ${kpi('Mitigated findings', fmtNum(mit.length), null, null, 'Remediated / no-longer-detected findings from the mitigated (patched) export.')}
      ${kpi('Open age (median)', openAgeMedian!=null? Math.round(openAgeMedian)+' d':'—', null, null, `How long currently-open findings have been open: median of (today − firstSeen) across the open dataset. Mean is ${openAgeMean!=null?Math.round(openAgeMean)+' d':'n/a'} (pulled up by a long tail). This is a backlog-age metric, not remediation time — a true MTTR needs two scans (compare mode) since Tenable.sc exports no remediation timestamp.`)}
    </div>`));

  // (Exploitable-vulnerability SLA by segment is built at the end — see buildSlaSegment)
  const slaRows = buses.map(b=>{
    const e = expl.filter(r=>bu(r)===b).length;
    const h = hostsByBu[b];
    const ratio = e/Math.max(h,1);
    return {b, e, h, ratio, over: ratio>SLA,
      non: cum.filter(r=>bu(r)===b&&!isExpl(r)).length,
      mitE: mit.filter(r=>bu(r)===b&&isExpl(r)).length};
  });

  // vulnerabilities past remediation SLA (aging from vulnPubDate; editable day targets per severity)
  const sevList = ['Critical','High','Medium','Low'];
  const pastSla = r => { const sd=STATE.slaDays[r.severity]; if(sd==null||!r.vulnPubDate) return false;
    return (Date.now()-new Date(r.vulnPubDate).getTime())/86400000 > sd; };
  const slaCounts = () => { const c={total:0,Critical:0,High:0,Medium:0,Low:0,expl:0};
    cum.forEach(r=>{ if(pastSla(r)){ c.total++; if(c[r.severity]!=null) c[r.severity]++; if(isExpl(r)) c.expl++; } }); return c; };
  const slaCard = (label,id,col,tip) => `<div class="card"${tip?` title="${tip}"`:''}><div class="l">${label}</div><div class="v" id="${id}" style="color:${col}">0</div></div>`;
  d.appendChild(html(`<div class="panel" id="slaConfig">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
      <h3 style="margin:0">Vulnerabilities past remediation SLA</h3>
      <button id="slaDaysReset" class="noprint" style="font-size:12px;padding:5px 11px;border-radius:6px;background:var(--panel2);border:1px solid var(--line);color:var(--txt);cursor:pointer">Reset</button>
    </div>
    <p class="sub" style="margin-top:8px">Aging measured from vulnerability publish date (vulnPubDate).</p>
    <p class="sub"><b style="color:var(--accent)">Edit the day values below</b> to set your remediation SLA per severity — every metric recalculates instantly:</p>
    <div class="noprint" style="display:flex;flex-wrap:wrap;gap:16px;margin:10px 0 2px;align-items:center">
      ${sevList.map(s=>`<label style="display:flex;align-items:center;gap:6px;font-size:13px"><span class="sev-${s}">${s}</span>
        <input class="slainp" data-sev="${s}" type="number" min="0" value="${STATE.slaDays[s]}" style="width:62px"> days</label>`).join('')}
    </div>
    <div class="cards" style="margin:14px 0 0;grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">
      ${slaCard('Total past SLA','sla-total','var(--crit)','Open findings (all severities) past their per-severity SLA, aged from vulnPubDate.')}
      ${slaCard('Critical past SLA','sla-Critical','var(--crit)','Critical open findings past SLA (count).')}
      ${slaCard('High past SLA','sla-High','var(--high)','High open findings past SLA (count).')}
      ${slaCard('Medium past SLA','sla-Medium','var(--med)','Medium open findings past SLA (count).')}
      ${slaCard('Low past SLA','sla-Low','var(--low)','Low open findings past SLA (count).')}
      ${slaCard('Avg Past SLA','sla-expl-per','var(--txt)','Exploitable findings past SLA ÷ unique IPs.')}
      ${slaCard('Avg Past Critical SLA','sla-avg-Critical','var(--crit)','Critical findings past SLA ÷ unique IPs.')}
      ${slaCard('Avg Past High SLA','sla-avg-High','var(--high)','High findings past SLA ÷ unique IPs.')}
      ${slaCard('Avg Past Medium SLA','sla-avg-Medium','var(--med)','Medium findings past SLA ÷ unique IPs.')}
      ${slaCard('Avg Past Low SLA','sla-avg-Low','var(--low)','Low findings past SLA ÷ unique IPs.')}
    </div></div>`));
  const uniqIp = new Set([...cum,...mit].map(r=>r.ip).filter(Boolean)).size;
  let summaryRefresh = null, topRefresh = null, osRefresh = null;
  const fillSla = () => { const c=slaCounts(); document.getElementById('sla-total').textContent=fmtNum(c.total);
    { const kt=document.getElementById('kpiPastTotal'); if(kt) kt.textContent=fmtNum(c.total); }
    sevList.forEach(s=>document.getElementById('sla-'+s).textContent=fmtNum(c[s]));
    sevList.forEach(s=>{ const el=document.getElementById('sla-avg-'+s); if(el) el.textContent=(uniqIp? c[s]/uniqIp : 0).toFixed(3); });
    const ep = uniqIp? c.expl/uniqIp : 0; const epEl=document.getElementById('sla-expl-per');
    epEl.textContent=ep.toFixed(3); epEl.style.color = ep>SLA?'var(--crit)':'var(--ok)';
    const kp=document.getElementById('kpiPastPer'), ks=document.getElementById('kpiPastSub');
    if(kp){ const col=ep>SLA?'var(--crit)':'var(--ok)'; kp.textContent=ep.toFixed(3); kp.style.color=col;
      ks.textContent=`SLA ${SLA} · ${Math.round(ep/SLA*100)}% of SLA`; ks.style.color=col; }
    if(summaryRefresh) summaryRefresh(); if(topRefresh) topRefresh(); if(osRefresh) osRefresh(); };
  fillSla();
  d.querySelectorAll('.slainp').forEach(inp=>inp.addEventListener('input',e=>{
    const v=parseInt(e.target.value); STATE.slaDays[e.target.dataset.sev]= isNaN(v)?0:Math.max(0,v); fillSla(); }));
  document.getElementById('slaDaysReset').addEventListener('click',()=>{
    STATE.slaDays = { ...DEFAULT_SLA_DAYS };
    d.querySelectorAll('.slainp').forEach(inp=>{ inp.value = STATE.slaDays[inp.dataset.sev]; });
    fillSla(); });

  // KPI - Exploitable-vulnerability SLA by segment — heat-mapped what-if table
  const wifInput = (i,k,v)=>`<input class="wif" data-i="${i}" data-k="${k}" value="${v}">`;
  d.appendChild(html(`<div class="panel">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
      <h3 style="margin:0">KPI - Exploitable vulnerability SLA by segment</h3>
      <button id="slaReset" class="noprint" style="font-size:12px;padding:5px 11px;border-radius:6px;background:var(--panel2);border:1px solid var(--line);color:var(--txt);cursor:pointer">Reset</button>
    </div>
    <table style="margin-top:12px"><thead><tr><th>Segment</th><th class="num">Assets</th><th class="num">Exploitable open</th>
    <th class="num">Per asset</th><th class="num">% of SLA</th><th>Status</th><th class="num">Non-exploitable</th>
    <th class="num">Exploitable mitigated</th></tr></thead><tbody>
    <tr style="border-bottom:2px solid var(--line)"><td style="font-weight:600">ALL</td>
      <td class="num">${wifInput('T','h','')}</td>
      <td class="num">${wifInput('T','e','')}</td>
      <td class="num" id="sla-per-T"></td><td class="num" id="sla-pct-T"></td><td id="sla-st-T"></td>
      <td class="num">${wifInput('T','non','')}</td>
      <td class="num">${wifInput('T','mitE','')}</td></tr>
    ${slaRows.map((r,i)=>`<tr><td>${r.b}</td>
      <td class="num">${wifInput(i,'h',r.h)}</td>
      <td class="num">${wifInput(i,'e',r.e)}</td>
      <td class="num" id="sla-per-${i}">${r.ratio.toFixed(3)}</td>
      <td class="num" id="sla-pct-${i}">${Math.round(r.ratio/SLA*100)}%</td>
      <td id="sla-st-${i}"><span class="pill ${r.over?'over':'ok'}">${r.over?'Over SLA':'Within SLA'}</span></td>
      <td class="num">${wifInput(i,'non',r.non)}</td>
      <td class="num">${wifInput(i,'mitE',r.mitE)}</td></tr>`).join('')}
    </tbody></table>
    <p class="sub"><b style="color:var(--accent)">SLA target: 0.25</b> — an average of no more than 0.25 vulnerabilities past SLA per system (Past SLA ÷ IP ≤ 0.25). Anything above 0.25 is over SLA.</p>
    <p class="sub noprint">What-if: Per asset and % of SLA show green when within the 0.25 SLA, red when over. Edit Assets, Exploitable open, Non-exploitable or Exploitable mitigated to recalculate live. "Reset" restores the data.</p>
    </div>`));
  const slaOrig = slaRows.map(r=>({h:r.h,e:r.e,non:r.non,mitE:r.mitE}));
  const wifVal = (i,k)=>{ const el=d.querySelector(`.wif[data-i="${i}"][data-k="${k}"]`); const v=parseFloat(el.value); return isNaN(v)?0:v; };
  const setVal = (i,k,v)=>{ const el=d.querySelector(`.wif[data-i="${i}"][data-k="${k}"]`); if(el) el.value=v; };
  const statusHTML = over=>`<span class="pill ${over?'over':'ok'}">${over?'Over SLA':'Within SLA'}</span>`;
  const rowDerived = (id,h,e)=>{ const per=h? e/h:0, over=per>SLA;
    const pe=document.getElementById('sla-per-'+id), pc=document.getElementById('sla-pct-'+id);
    pe.textContent=per.toFixed(3); pc.textContent=Math.round(per/SLA*100)+'%';
    const col = over ? 'var(--crit)' : 'var(--ok)';
    pe.style.color=pc.style.color=col; pe.style.fontWeight=pc.style.fontWeight=600;
    document.getElementById('sla-st-'+id).innerHTML=statusHTML(over); };
  function recalcSla(fromRollup){
    let TH=0,TE=0,TN=0,TM=0;
    slaRows.forEach((r,i)=>{
      const h=wifVal(i,'h'), e=wifVal(i,'e');
      rowDerived(i,h,e); TH+=h;TE+=e;TN+=wifVal(i,'non');TM+=wifVal(i,'mitE');
    });
    if(!fromRollup){ setVal('T','h',TH); setVal('T','e',TE); setVal('T','non',TN); setVal('T','mitE',TM); }
    rowDerived('T', wifVal('T','h'), wifVal('T','e'));
  }
  recalcSla(false);
  d.querySelectorAll('.wif').forEach(inp=>inp.addEventListener('input',e=>recalcSla(e.target.dataset.i==='T')));
  document.getElementById('slaReset').addEventListener('click',()=>{
    slaRows.forEach((r,i)=>{ const o=slaOrig[i];
      setVal(i,'h',o.h); setVal(i,'e',o.e); setVal(i,'non',o.non); setVal(i,'mitE',o.mitE); });
    recalcSla(false);
  });

  // vulnerability summary by segment: plugins (rows) x segments (columns), open finding counts
  const segShort = s => String(s).replace(/_Repo$/,'');
  const sevRank = {Critical:4,High:3,Medium:2,Low:1,Info:0};
  let pRows = [];
  const computeP = () => { const pmap={};
    cum.forEach(r=>{ if(!pastSla(r)) return; const p=r.pluginName||'(unknown)';
      (pmap[p]=pmap[p]||{sev:r.severity,total:0,by:{}}); pmap[p].by[bu(r)]=(pmap[p].by[bu(r)]||0)+1; pmap[p].total++; });
    pRows = Object.entries(pmap).sort((a,b)=> b[1].total-a[1].total || (sevRank[b[1].sev]||0)-(sevRank[a[1].sev]||0)); };
  computeP();
  const plugRow = ([name,o])=>`<tr><td>${name}</td><td class="sev-${o.sev}">${o.sev}</td>
    ${buses.map(b=>`<td class="num">${o.by[b]?fmtNum(o.by[b]):'<span style="color:var(--muted)">—</span>'}</td>`).join('')}
    <td class="num" style="font-weight:600">${fmtNum(o.total)}</td></tr>`;
  const sMax = Math.max(new Set(cum.map(r=>r.pluginName||'(unknown)')).size,1); const sLabel = v=>v>=sMax?'ALL':v;
  d.appendChild(html(`<div class="panel">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
      <h3 style="margin:0">Vulnerabilities past remediation SLA by segment</h3>
      <label class="sub noprint" style="display:flex;align-items:center;gap:10px">Show top
        <input id="sumN" type="range" min="1" max="${sMax}" value="${Math.min(STATE.summaryN,sMax)}" style="width:150px;accent-color:var(--accent)">
        <span id="sumNval" style="color:var(--txt);font-weight:500;min-width:2.2em;text-align:right">${sLabel(Math.min(STATE.summaryN,sMax))}</span>
        <span id="sumOf" style="color:var(--muted)">of ${pRows.length}</span></label>
    </div>
    <div class="scrollwrap" style="margin-top:12px;max-height:440px">
    <table><thead><tr><th>Plugin</th><th>Severity</th>
      ${buses.map(b=>`<th class="num">${segShort(b)}</th>`).join('')}<th class="num">Total</th></tr></thead>
    <tbody id="summaryBody"></tbody></table></div>
    <p class="sub noprint">Open findings past their remediation SLA per Tenable plugin across segments — driven by the SLA day targets above (sorted by Total, greatest to smallest).</p></div>`));
  const fillSummary = ()=>{ const n=Math.min(STATE.summaryN,sMax); const vis=pRows.slice(0,n);
    const segTot={}; buses.forEach(b=>segTot[b]=0); let grand=0;
    vis.forEach(([name,o])=>{ buses.forEach(b=>segTot[b]+=(o.by[b]||0)); grand+=o.total; });
    const totals=`<tr style="border-top:2px solid var(--line)"><td style="font-weight:600">All plugins</td><td></td>
      ${buses.map(b=>`<td class="num" style="font-weight:600">${fmtNum(segTot[b])}</td>`).join('')}
      <td class="num" style="font-weight:600">${fmtNum(grand)}</td></tr>`;
    document.getElementById('summaryBody').innerHTML = vis.map(plugRow).join('') + totals; };
  fillSummary();
  summaryRefresh = ()=>{ computeP(); const of=document.getElementById('sumOf'); if(of) of.textContent='of '+pRows.length; fillSummary(); };
  document.getElementById('sumN').addEventListener('input',e=>{ const v=Math.max(1,Math.min(parseInt(e.target.value)||1,sMax));
    STATE.summaryN=v; document.getElementById('sumNval').textContent=sLabel(v); fillSummary(); });

  // charts row: severity + exploitable by BU
  d.appendChild(html(`<div class="grid2">
    <div class="panel"><h3>Open findings by severity</h3><div class="chartbox"><canvas id="cSev"></canvas></div></div>
    <div class="panel"><h3>Exploitable vulnerabilities by SLA, and segment</h3><div class="chartbox"><canvas id="cBu"></canvas></div></div>
  </div>`));
  const sevCount = groupCount(cum, r=>r.severity);
  donut('cSev', ['Critical','High','Medium','Low','Info'].filter(s=>sevCount[s]),
        ['Critical','High','Medium','Low','Info'].filter(s=>sevCount[s]).map(s=>sevCount[s]),
        {Critical:PAL().crit,High:PAL().high,Medium:PAL().med,Low:PAL().low,Info:PAL().info});
  bar('cBu', slaRows.map(r=>r.b), [
    {label:'Past SLA', data:slaRows.map(r=>r.e), backgroundColor:PAL().crit},
    {label:'SLA threshold', data:slaRows.map(r=>Math.round(r.h*SLA)), backgroundColor:PAL().ok}
  ]);

  // (Removed the "Top vulnerabilities past SLA" panel — it duplicated the plugin × segment matrix.
  //  R.topVulns is still computed for the CSV / full-report exports.)

  // vulnerabilities by OS, stacked by SLA status (within SLA + past-SLA by severity)
  const osTot={}; cum.forEach(r=>{ const o=r.operatingSystem||'Unknown'; osTot[o]=(osTot[o]||0)+1; });
  const osOrder=Object.keys(osTot).sort((a,b)=>osTot[b]-osTot[a]);
  const osCat={within:{},Critical:{},High:{},Medium:{},Low:{}};
  cum.forEach(r=>{ const o=r.operatingSystem||'Unknown';
    if(!pastSla(r)) osCat.within[o]=(osCat.within[o]||0)+1;
    else if(osCat[r.severity]) osCat[r.severity][o]=(osCat[r.severity][o]||0)+1; });
  const osShort=k=>k.replace('Microsoft ','').replace('Red Hat Enterprise Linux','RHEL');
  const osSeries=[['Within SLA','within',PAL().ok],['Critical past SLA','Critical',PAL().crit],
    ['High past SLA','High',PAL().high],['Medium past SLA','Medium',PAL().med],['Low past SLA','Low',PAL().low]];
  d.appendChild(html(`<div class="panel"><h3>Vulnerabilities by operating system and SLA status</h3>
    <div style="display:flex;flex-wrap:wrap;gap:14px;margin:0 0 8px;font-size:12px;color:var(--muted)">
      ${osSeries.map(([l,,c])=>`<span style="display:flex;align-items:center;gap:5px"><span style="width:11px;height:11px;border-radius:2px;background:${c}"></span>${l}</span>`).join('')}
    </div>
    <div class="chartbox" style="height:330px"><canvas id="cOs"></canvas></div></div>`));
  stackedHBar('cOs', osOrder.map(osShort),
    osSeries.map(([l,k,c])=>({label:l, data:osOrder.map(o=>osCat[k][o]||0), backgroundColor:c})));
  osRefresh = ()=>{ const oc={within:{},Critical:{},High:{},Medium:{},Low:{}};
    cum.forEach(r=>{ const o=r.operatingSystem||'Unknown';
      if(!pastSla(r)) oc.within[o]=(oc.within[o]||0)+1;
      else if(oc[r.severity]) oc[r.severity][o]=(oc[r.severity][o]||0)+1; });
    const ch=charts.find(c=>c.canvas&&c.canvas.id==='cOs'); if(!ch) return;
    osSeries.forEach(([l,k],idx)=>{ ch.data.datasets[idx].data = osOrder.map(o=>oc[k][o]||0); });
    ch.update('none'); };

  // mitigated-by-month (kept for export only; chart removed)
  const byMonth = {};
  mit.forEach(r=>{ if(r.lastSeen){ const m=String(r.lastSeen).slice(0,7); byMonth[m]=(byMonth[m]||0)+1; }});

  // most exposed hosts
  const hostData = sev => { const m={};
    cum.filter(r=>pastSla(r) && (sev==='all'||r.severity===sev)).forEach(r=>{ const h=r.dnsName||r.ip;
      (m[h]=m[h]||{n:0,bu:bu(r),os:r.operatingSystem,ip:r.ip}).n++; });
    return Object.entries(m).sort((a,b)=>b[1].n-a[1].n); };
  const topHosts = hostData('all').slice(0,12);
  const hMax = Math.max(hostData('all').length,1); const hLabel = v=>v>=hMax?'ALL':v;
  d.appendChild(html(`<div class="panel">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
      <h3 style="margin:0">Most-exposed hosts (by vulnerabilities past SLA)</h3>
      <label class="sub noprint" style="display:flex;align-items:center;gap:10px">
        <select id="hostSev" class="hostinput" style="width:auto;text-align:left" title="Filter by Tenable severity">
          <option value="all">All severities</option>
          <option value="Critical">Critical</option><option value="High">High</option>
          <option value="Medium">Medium</option><option value="Low">Low</option>
        </select>
        Show top
        <input id="hostN" type="range" min="1" max="${hMax}" value="${Math.min(STATE.hostsN,hMax)}" style="width:130px;accent-color:var(--accent)">
        <span id="hostNval" style="color:var(--txt);font-weight:500;min-width:2.2em;text-align:right">${hLabel(Math.min(STATE.hostsN,hMax))}</span>
        <span id="hostOf" style="color:var(--muted)">of ${hostData('all').length}</span></label>
    </div>
    <div id="hostWrap" class="scrollwrap" style="margin-top:12px">
    <table><thead><tr><th>Host</th><th>Segment</th><th>OS</th><th>IP</th><th class="num">Past SLA</th></tr></thead><tbody id="hostBody"></tbody></table></div></div>`));
  const sevR={Critical:4,High:3,Medium:2,Low:1,Info:0};
  function fillHosts(){
    const data = hostData(STATE.hostsSev);
    const ofEl=document.getElementById('hostOf'); if(ofEl) ofEl.textContent='of '+data.length;
    document.getElementById('hostBody').innerHTML = data.slice(0, Math.min(STATE.hostsN,hMax)).map(([h,o])=>`<tr class="hostrow" data-host="${h}" style="cursor:pointer">
      <td><span class="chev" style="display:inline-block;width:12px;color:var(--muted)">▸</span>${h}</td><td>${o.bu}</td>
      <td style="font-size:12px">${(o.os||'').replace('Microsoft ','')}</td><td style="font-size:12px">${o.ip||''}</td>
      <td class="num">${fmtNum(o.n)}</td></tr>`).join('');
    const wrap=document.getElementById('hostWrap'), tb=document.getElementById('hostBody'), rs=tb.querySelectorAll('tr');
    if(rs.length>10){ const th=wrap.querySelector('thead'); let h=th?th.offsetHeight:0;
      for(let i=0;i<10;i++) h+=rs[i].offsetHeight; wrap.style.maxHeight=(h+2)+'px'; }
    else wrap.style.maxHeight='';
  }
  const findingSort = (a,b)=>(sevR[b.severity]||0)-(sevR[a.severity]||0) || (String(a.pluginName)>String(b.pluginName)?1:-1);
  const hostFindings = h => { const sev=STATE.hostsSev;
    return cum.filter(r=>(r.dnsName||r.ip)===h && (sev==='all'||r.severity===sev)).sort(findingSort); };
  const escTxt = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  function hostDetailHTML(h){
    const sev=STATE.hostsSev; const rows=hostFindings(h);
    const inner=rows.map((r,i)=>{ const hasText=!!(r.pluginText||r.description||r.solution);
      return `<tr class="findingrow" data-host="${h}" data-fidx="${i}" style="cursor:${hasText?'pointer':'default'}">
      <td class="sev-${r.severity}" style="white-space:nowrap">${hasText?'<span class="fchev" style="display:inline-block;width:11px;color:var(--muted)">▸</span>':'<span style="display:inline-block;width:11px"></span>'}${r.severity}</td>
      <td>${r.pluginName}</td><td style="font-size:12px">${r.cve||'—'}</td>
      <td style="font-size:12px">${r.port}/${r.protocol}</td>
      <td>${isExpl(r)?'<span class="pill over">Exploit</span>':'—'}</td>
      <td>${pastSla(r)?'<span class="pill over">Past SLA</span>':'<span class="pill ok">Within</span>'}</td></tr>`; }).join('');
    return `<tr class="hostdetail"><td colspan="5" style="background:var(--panel2);padding:0">
      <div style="padding:8px 12px 10px 26px">
        <div class="sub" style="margin:0 0 6px">${rows.length} open finding${rows.length===1?'':'s'} on ${h}${sev!=='all'?' · '+sev:''} · click a finding for plugin output</div>
        <table style="font-size:13px"><thead><tr><th>Severity</th><th>Plugin</th><th>CVE</th><th>Port</th><th>Exploit</th><th>SLA</th></tr></thead>
        <tbody>${inner}</tbody></table></div></td></tr>`;
  }
  function findingDetailHTML(h, idx){
    const r=hostFindings(h)[idx]; if(!r) return '';
    const block=(label,txt)=> txt? `<div style="margin-top:6px"><div class="sub" style="text-transform:uppercase;letter-spacing:.04em;font-size:10.5px;margin-bottom:2px">${label}</div><pre style="white-space:pre-wrap;word-break:break-word;font-size:12px;margin:0;max-height:240px;overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:8px;color:var(--txt)">${escTxt(txt)}</pre></div>`:'';
    const body = block('Plugin output', r.pluginText) + block('Description', r.description) + block('Solution', r.solution);
    return `<tr class="findingdetail"><td colspan="6" style="background:var(--panel);padding:6px 12px 10px 30px">${body||'<span class="sub">No additional detail in this export.</span>'}</td></tr>`;
  }
  document.getElementById('hostBody').addEventListener('click', e=>{
    const frow=e.target.closest('tr.findingrow');
    if(frow){ const chev=frow.querySelector('.fchev'); if(!chev) return;   // only rows with detail text expand
      const next=frow.nextElementSibling;
      if(next && next.classList.contains('findingdetail')){ next.remove(); chev.textContent='▸'; }
      else { frow.insertAdjacentHTML('afterend', findingDetailHTML(frow.dataset.host, +frow.dataset.fidx)); chev.textContent='▾'; }
      return; }
    const row=e.target.closest('tr.hostrow'); if(!row) return;
    const chev=row.querySelector('.chev'), next=row.nextElementSibling;
    if(next && next.classList.contains('hostdetail')){ next.remove(); if(chev) chev.textContent='▸'; }
    else { row.insertAdjacentHTML('afterend', hostDetailHTML(row.dataset.host)); if(chev) chev.textContent='▾'; }
  });
  fillHosts();
  document.getElementById('hostN').addEventListener('input', e=>{ const v=Math.max(1,Math.min(parseInt(e.target.value)||1,hMax));
    STATE.hostsN=v; document.getElementById('hostNval').textContent=hLabel(v); fillHosts(); });
  document.getElementById('hostSev').value=STATE.hostsSev;
  document.getElementById('hostSev').addEventListener('change', e=>{ STATE.hostsSev=e.target.value; fillHosts(); });


  // per-card save control: format picker + Save button, always pinned top-right
  const attachSave = (p, forceName)=>{
    if(!p || p.querySelector('.savewrap')) return;
    const h=p.querySelector('h3');
    const name=(forceName || (h?h.textContent:'panel')).toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,'');
    const wrap=document.createElement('div'); wrap.className='savewrap noprint';
    const sel=document.createElement('select'); sel.title='Save as';
    [['png','PNG'],['jpeg','JPEG'],['webp','WEBP'],['gif','GIF'],['clipboard-img','Clipboard (image)'],['clipboard-text','Clipboard (text)']]
      .forEach(([v,l])=>{ const o=document.createElement('option'); o.value=v; o.textContent=l; sel.appendChild(o); });
    const b=document.createElement('button'); b.textContent='Save'; b.title='Save this card as an image';
    b.addEventListener('click', ()=>savePanel(p, name, sel.value, b));
    wrap.appendChild(sel); wrap.appendChild(b);
    // Reset only on cards that have adjustable controls (day targets, what-if inputs, severity/show-top filters)
    const hasControls = !!p.querySelector('.slainp, .wif, input[type=range]');
    if(hasControls){
      const rb=document.createElement('button'); rb.textContent='Reset'; rb.title='Reset this card to its default view';
      rb.addEventListener('click', ()=>{ if(typeof p._cardReset==='function') p._cardReset(); });
      wrap.appendChild(rb);
    }
    p.appendChild(wrap);
    // clear the top-right corner so the controls never overlap existing header controls — measured, not guessed
    const reserveW = (wrap.offsetWidth || 200) + 20;
    if(p.classList.contains('cards')){ p.style.position='relative'; p.style.paddingTop=((wrap.offsetHeight||26)+16)+'px'; }
    else { const hdr=[...p.children].find(c=>c.tagName==='DIV' && c.querySelector(':scope>h3'));
      if(hdr) hdr.style.paddingRight=reserveW+'px'; else if(h) h.style.paddingRight=reserveW+'px'; }
  };
  // larger report cards (charts + tables)
  d.querySelectorAll('.panel').forEach(p=>{ if(p.querySelector('canvas')||p.querySelector('table')) attachSave(p); });
  // clickable column-header sorting on data tables (skip editable tables with inputs)
  d.querySelectorAll('.panel table').forEach(t=>{ if(!t.querySelector('tbody input')) makeSortable(t); });
  // card-grid blocks with no table/canvas: executive KPI strip + per-severity SLA-aging cards
  attachSave(d.querySelector('.cards'), 'executive_kpis');
  attachSave(document.getElementById('slaConfig'));

  // per-card Reset handlers — only cards with adjustable controls; route through existing reset logic where it exists
  const regReset=(p,fn)=>{ if(p) p._cardReset=fn; };
  ['slaDaysReset','slaReset'].forEach(id=>{ const b=document.getElementById(id); if(b) b.style.display='none'; }); // fold the old in-header Resets into the top-right one
  regReset(document.getElementById('slaConfig'), ()=>{ const b=document.getElementById('slaDaysReset'); if(b) b.click(); });
  regReset(d.querySelector('.wif')?.closest('.panel'), ()=>{ const b=document.getElementById('slaReset'); if(b) b.click(); });
  regReset(document.getElementById('sumN')?.closest('.panel'), ()=>{ STATE.summaryN=5; const s=document.getElementById('sumN'); s.value=Math.min(5,sMax); document.getElementById('sumNval').textContent=sLabel(Math.min(5,sMax)); fillSummary(); });
  regReset(document.getElementById('hostN')?.closest('.panel'), ()=>{ STATE.hostsSev='all'; STATE.hostsN=10; const hs=document.getElementById('hostSev'); if(hs) hs.value='all'; const hn=document.getElementById('hostN'); hn.value=Math.min(10,hMax); document.getElementById('hostNval').textContent=hLabel(Math.min(10,hMax)); fillHosts(); });

  buildJumpNav();
  applyPanelTips();

  window._report = {
    sla: slaRows,
    metrics: { totalHosts, openFindings: cum.length, exploitableOpen: expl.length,
      exploitablePerAsset: +explPerHost.toFixed(4), sla: SLA, pctOfSla: Math.round(explPerHost/SLA*100),
      mitigated: mit.length, mttrDays: mttr!=null?+mttr.toFixed(1):null,
      publishedOver1yr: oldPub, firstSeenOver1yr: oldSeen, log4jRelated: log4j },
    slaPastDue: { slaDays: {...STATE.slaDays}, basis: 'vulnPubDate', counts: slaCounts() },
    topVulns: topBy(expl, r=>r.pluginName, STATE.topN).map(([name,rows])=>({plugin:name, pluginID:rows[0].pluginID, severity:rows[0].severity,
      cve:rows[0].cve, exploitFrameworks:rows[0].exploitFrameworks, instances:rows.length, hosts:uniqHosts(rows)})),
    hosts: topHosts.map(([h,o])=>({host:h, bu:o.bu, os:o.os, ip:o.ip, exploitable:o.n})),
    segMatrix: pRows.map(([plugin,o])=>{ const row={plugin, severity:o.sev}; buses.forEach(b=>row[segShort(b)]=o.by[b]||0); row.total=o.total; return row; }),
    severity: sevCount, os: osTot, byMonth,
    cumulative: cum, mitigated: mit
  };
}

// ---------- save a card as an image (chart canvas fast-path, or html2canvas for HTML cards) ----------
function panelBg(){ return getComputedStyle(tvdRoot()).getPropertyValue('--panel').trim() || '#171a23'; }

function toast(msg){ let t=document.querySelector('.toast'); if(!t){ t=document.createElement('div'); t.className='toast'; document.body.appendChild(t); }
  t.textContent=msg; t.classList.add('show'); clearTimeout(t._h); t._h=setTimeout(()=>t.classList.remove('show'),1800); }

// Rasterize a panel to a canvas. Charts (single canvas, no table) use the live canvas; HTML cards use html2canvas (this panel only).
async function rasterPanel(el){
  const bg = panelBg();
  const cv = el.querySelector('canvas');
  if(cv && el.querySelectorAll('canvas').length===1 && !el.querySelector('table')){
    const tmp=document.createElement('canvas'); tmp.width=cv.width; tmp.height=cv.height;
    const ctx=tmp.getContext('2d'); ctx.fillStyle=bg; ctx.fillRect(0,0,tmp.width,tmp.height); ctx.drawImage(cv,0,0);
    return tmp;
  }
  // HTML card: hide interactive controls (.noprint) + un-clip scroll regions so the full card renders cleanly
  const hidden=[...el.querySelectorAll('.noprint')]; const vis=hidden.map(n=>n.style.visibility); hidden.forEach(n=>n.style.visibility='hidden');
  const scrolls=[...el.querySelectorAll('.scrollwrap')]; const maxes=scrolls.map(s=>s.style.maxHeight); scrolls.forEach(s=>s.style.maxHeight='none');
  let canvas;
  try{ canvas = await html2canvas(el, {backgroundColor:bg, scale:2, logging:false, useCORS:true}); }
  finally{ scrolls.forEach((s,i)=>s.style.maxHeight=maxes[i]); hidden.forEach((n,i)=>n.style.visibility=vis[i]); }
  return canvas;
}

function canvasToBlob(canvas, mime, q){ return new Promise(res=>canvas.toBlob(res, mime, q)); }
function dlBlob(blob, filename){ const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=filename; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href),1000); }

// Build an HTML <table> from tab/newline text so spreadsheet apps (Numbers especially) split it into cells.
function tsvToHtmlTable(tsv){
  const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const rows=tsv.split('\n').map(line=>{
    if(line==='') return '<tr><td></td></tr>';
    return '<tr>'+line.split('\t').map(c=>`<td>${esc(c)}</td>`).join('')+'</tr>';
  }).join('');
  return `<table>${rows}</table>`;
}
// Per-column character widths across an aoa-sections list (used for HTML colgroup + XLSX !cols).
function colCharWidths(secs){
  const maxCols=Math.max(1,...secs.map(s=>Math.max(...s.aoa.map(r=>r.length))));
  const w=[]; for(let i=0;i<maxCols;i++){ let m=4;
    secs.forEach(s=>s.aoa.forEach(r=>{ if(r[i]!=null){ const L=String(r[i]).length; if(L>m) m=L; } })); w[i]=m; }
  return w;
}
// Richly-formatted HTML table for the full report: merged navy section bars, bold header rows, sized columns.
function sectionsToHtmlTable(secs){
  const esc=s=>String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const cw=colCharWidths(secs); const maxCols=cw.length;
  const colgroup='<colgroup>'+cw.map(c=>`<col style="width:${Math.min(Math.max(c*7+18,48),360)}px">`).join('')+'</colgroup>';
  const padTd='<td style="border:0"></td>';   // invisible filler so every row is maxCols wide (keeps the table rectangular)
  let rows='';
  secs.forEach((s,si)=>{
    if(si>0) rows+=`<tr><td colspan="${maxCols}" style="height:8px"></td></tr>`;
    rows+=`<tr><td colspan="${maxCols}" style="font-weight:bold;background:#28415d;color:#ffffff;padding:5px 8px;white-space:nowrap">${esc(s.name)}</td></tr>`;
    s.aoa.forEach((r,ri)=>{ const head=ri===0;
      const cells=r.map(c=>`<td style="${head?'font-weight:bold;background:#e9edf2;':''}padding:3px 8px;border:1px solid #c9cdd4;white-space:nowrap">${esc(c)}</td>`);
      while(cells.length<maxCols) cells.push(padTd);
      rows+='<tr>'+cells.join('')+'</tr>'; });
  });
  return `<table style="border-collapse:collapse;table-layout:fixed;font-family:-apple-system,Segoe UI,sans-serif;font-size:12px;color:#1b2530">${colgroup}${rows}</table>`;
}
// Copy tabular text to the clipboard as BOTH text/plain (TSV) and text/html (a table) — pastes cleanly into Excel AND Numbers.
function copyTable(tsv, okMsg, htmlOverride){
  const html = htmlOverride || tsvToHtmlTable(tsv);
  if(window.ClipboardItem && navigator.clipboard && navigator.clipboard.write){
    return navigator.clipboard.write([new ClipboardItem({
      'text/plain': new Blob([tsv], {type:'text/plain'}),
      'text/html':  new Blob([html], {type:'text/html'})
    })]).then(()=>toast(okMsg), e=>{ console.error('copyTable', e); toast('Clipboard write failed'); });
  }
  if(navigator.clipboard && navigator.clipboard.writeText){
    return navigator.clipboard.writeText(tsv).then(()=>toast(okMsg), ()=>toast('Clipboard write failed'));
  }
  toast('Clipboard not supported here'); return Promise.resolve();
}

function canvasToGifBlob(canvas){
  const g=window.gifenc; const {width,height}=canvas;
  const data=canvas.getContext('2d').getImageData(0,0,width,height).data;
  const palette=g.quantize(data,256); const index=g.applyPalette(data,palette);
  const enc=g.GIFEncoder(); enc.writeFrame(index,width,height,{palette}); enc.finish();
  return new Blob([enc.bytesView()],{type:'image/gif'});
}

// Extract a card's underlying data as tab-separated text (paste-ready for Excel): tables, KPI cards, or chart data.
function cardToText(p){
  const cellText = c => { const inp=c.querySelector('input'); return (inp?inp.value:c.textContent).trim().replace(/\s+/g,' '); };
  const tbl = p.querySelector('table');
  if(tbl){
    const rows=[...tbl.querySelectorAll(':scope > thead > tr, :scope > tbody > tr')].filter(r=>!r.classList.contains('hostdetail'));
    return rows.map(r=>[...r.children].map(cellText).join('\t')).join('\n');
  }
  const cv=p.querySelector('canvas');
  if(cv && window.Chart){ const ch=Chart.getChart(cv);
    if(ch){ const d=ch.data, ds=d.datasets||[];
      const head=['Label',...ds.map(x=>x.label||'Value')].join('\t');
      const body=(d.labels||[]).map((lab,i)=>[lab,...ds.map(x=>x.data[i])].join('\t')).join('\n');
      return head+'\n'+body; } }
  const cards=[...p.querySelectorAll('.card')];
  if(cards.length) return cards.map(c=>{ const l=c.querySelector('.l'), v=c.querySelector('.v');
    return ((l?l.textContent:'').trim().replace(/\s+/g,' '))+'\t'+((v?v.textContent:'').trim()); }).filter(x=>x.trim()!=='\t'&&x.trim()).join('\n');
  return '';
}

async function savePanel(el, name, fmt, btn){
  fmt = fmt || 'png';
  const stamp=new Date().toISOString().slice(0,10);
  if(btn){ btn.classList.add('saving'); btn.textContent='…'; }
  try{
    if(fmt==='clipboard-text'){
      const txt=cardToText(el);
      if(!txt){ toast('No data to copy from this card'); return; }
      await copyTable(txt, 'Data copied — paste into Excel or Numbers');
      return;
    }
    const canvas = await rasterPanel(el);
    if(fmt==='clipboard-img'){
      if(!(navigator.clipboard && window.ClipboardItem)){ toast('Clipboard not supported here'); return; }
      const blob=await canvasToBlob(canvas,'image/png');
      await navigator.clipboard.write([new ClipboardItem({'image/png':blob})]);
      toast('Image copied to clipboard'); return;
    }
    if(fmt==='gif'){ dlBlob(canvasToGifBlob(canvas), (name||'card')+'_'+stamp+'.gif'); return; }
    const mime='image/'+fmt; const q=(fmt==='jpeg'||fmt==='webp')?0.95:undefined;
    const blob=await canvasToBlob(canvas, mime, q);
    dlBlob(blob, (name||'card')+'_'+stamp+'.'+(fmt==='jpeg'?'jpg':fmt));
  }catch(err){ console.error('savePanel', err); toast('Save failed'); }
  finally{ if(btn){ btn.classList.remove('saving'); btn.textContent='Save'; } }
}

// ---------- clickable column-header sorting (generic, DOM-based) ----------
function makeSortable(table){
  if(!table || table._sortable) return; const thead=table.tHead, tbody=table.tBodies[0]; if(!thead||!tbody) return;
  table._sortable=true; const ths=[...thead.rows[0].cells];
  const numOf=s=>{ const n=parseFloat(String(s).replace(/[,$%\s]/g,'')); return isNaN(n)?null:n; };
  ths.forEach((th,idx)=>{ if(th.dataset.nosort!==undefined) return; th.style.cursor='pointer'; if(!th.title) th.title='Sort';
    th.addEventListener('click',()=>{
      const dir = th._dir = (th._dir===1?-1:1);
      ths.forEach(o=>{ if(o!==th){ o._dir=0; const s=o.querySelector('.sortind'); if(s) s.remove(); } });
      let ind=th.querySelector('.sortind'); if(!ind){ ind=document.createElement('span'); ind.className='sortind'; ind.style.cssText='margin-left:4px;opacity:.7'; th.appendChild(ind); }
      ind.textContent = dir===1?'▲':'▼';
      [...tbody.querySelectorAll('tr.hostdetail,tr.findingdetail')].forEach(r=>r.remove());           // collapse expansions
      tbody.querySelectorAll('.chev,.fchev').forEach(c=>c.textContent='▸');
      const rows=[...tbody.rows]; const pin=rows.filter(r=>/^all\s/i.test((r.cells[0]?.textContent||'').trim()));
      const data=rows.filter(r=>!pin.includes(r));
      const val=r=>{ const c=r.cells[idx]; return c? c.textContent.trim() : ''; };
      const allNum=data.length && data.every(r=>{ const t=val(r); return t===''||t==='—'||numOf(t)!==null; });
      data.sort((a,b)=>{ let x=val(a),y=val(b);
        if(allNum){ x=numOf(x); y=numOf(y); x=x==null?-Infinity:x; y=y==null?-Infinity:y; return (x-y)*dir; }
        return (x.toUpperCase()>y.toUpperCase()?1:x.toUpperCase()<y.toUpperCase()?-1:0)*dir; });
      data.concat(pin).forEach(r=>tbody.appendChild(r));
    });
  });
}

// ---------- export ----------
function dl(name, text, mime){ const b=new Blob([text],{type:mime||'text/plain'}); const a=document.createElement('a');
  a.href=URL.createObjectURL(b); a.download=name; a.click(); URL.revokeObjectURL(a.href); }
function toCsv(headers, rows){ const esc=v=>{ v=v==null?'':String(v); return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v; };
  return [headers.join(',')].concat(rows.map(r=>r.map(esc).join(','))).join('\n'); }
function objCsv(objs){ if(!objs.length) return ''; const cols=[...new Set(objs.flatMap(o=>Object.keys(o)))];
  return toCsv(cols, objs.map(o=>cols.map(c=>o[c]))); }
function slaTable(){ const r=window._report.sla;
  return { headers:['segment','assets','exploitable_open','exploitable_per_asset','pct_of_sla','status','non_exploitable_open','exploitable_mitigated'],
    rows:r.map(x=>[x.b,x.h,x.e,x.ratio.toFixed(4),Math.round(x.ratio/SLA*100)+'%',x.over?'Over SLA':'Within SLA',x.non,x.mitE]) }; }

// All report sections as {name, aoa} blocks — drives the Full report (CSV/XLSX) exports.
function reportSections(R){
  const kv = obj => Object.entries(obj).map(([k,v])=>[k,v]);
  const aoaObjs = objs => { if(!objs||!objs.length) return [['(no rows)']]; const cols=[...new Set(objs.flatMap(o=>Object.keys(o)))];
    return [cols, ...objs.map(o=>cols.map(c=>o[c]==null?'':o[c]))]; };
  const t=slaTable(); const pd=R.slaPastDue||{slaDays:{},counts:{}}; const dys=pd.slaDays||{}, c=pd.counts||{};
  return [
    {name:'Metrics', aoa:[['metric','value'],...kv(R.metrics)]},
    {name:'SLA by Segment', aoa:[t.headers,...t.rows]},
    {name:'Past SLA Counts', aoa:[['severity','day_target','past_sla_count'],
      ['Critical',dys.Critical,c.Critical],['High',dys.High,c.High],['Medium',dys.Medium,c.Medium],['Low',dys.Low,c.Low],
      ['Total','',c.total],['Exploitable past SLA','',c.expl]]},
    {name:'SLA by Plugin x Segment', aoa:aoaObjs(R.segMatrix)},
    {name:'Top Vulnerabilities', aoa:aoaObjs(R.topVulns)},
    {name:'Most Exposed Hosts', aoa:aoaObjs(R.hosts)},
    {name:'Severity', aoa:[['severity','count'],...kv(R.severity)]},
    {name:'Operating System', aoa:[['operatingSystem','count'],...kv(R.os)]},
    {name:'Mitigated by Month', aoa:[['month','count'],...kv(R.byMonth)]}
  ];
}

function doExport(kind){
  const R=window._report; if(!R){ alert('Load data first.'); return; }
  const stamp=new Date().toISOString().slice(0,10);
  if(kind==='report-pdf'){ window.print(); return; }
  if(kind==='full-csv'){
    const parts=reportSections(R).map(s=>`# ${s.name}\n`+toCsv(s.aoa[0]||[], s.aoa.slice(1)));
    dl(`vm_full_report_${stamp}.csv`, parts.join('\n\n\n'), 'text/csv'); return; }
  if(kind==='full-xlsx'){
    const wb=XLSX.utils.book_new();
    reportSections(R).forEach(s=>{ const ws=XLSX.utils.aoa_to_sheet(s.aoa);
      ws['!cols']=colCharWidths([s]).map(c=>({wch:Math.min(Math.max(c+2,8),60)}));   // auto-size each column to its content
      XLSX.utils.book_append_sheet(wb, ws, s.name.slice(0,31)); });
    XLSX.writeFile(wb, `vm_full_report_${stamp}.xlsx`); return; }
  if(kind==='full-csv-clip'){
    if(!(navigator.clipboard && navigator.clipboard.writeText)){ toast('Clipboard not supported here'); return; }
    const txt=reportSections(R).map(s=>`# ${s.name}\n`+toCsv(s.aoa[0]||[], s.aoa.slice(1))).join('\n\n\n');
    navigator.clipboard.writeText(txt).then(()=>toast('Full report CSV copied to clipboard'), ()=>toast('Clipboard write failed')); return; }
  if(kind==='full-tsv-clip'){
    const secs=reportSections(R); const cell=c=>String(c==null?'':c).replace(/[\t\r\n]+/g,' ');
    const txt=secs.map(s=>`# ${s.name}\n`+s.aoa.map(row=>row.map(cell).join('\t')).join('\n')).join('\n\n\n');
    copyTable(txt, 'Full report copied — paste into Excel or Numbers', sectionsToHtmlTable(secs)); return; }
  if(kind==='full-img-clip'){
    if(!(navigator.clipboard && window.ClipboardItem)){ toast('Clipboard not supported here'); return; }
    showLoading('Rendering full report image…');
    const safety=setTimeout(hideLoading, 12000);     // never let the overlay get stuck if the write stalls
    const done=()=>{ clearTimeout(safety); hideLoading(); };
    const blobP=(async()=>{ const c=await rasterPanel(document.getElementById('dashboard')); return await canvasToBlob(c,'image/png'); })();
    navigator.clipboard.write([new ClipboardItem({'image/png':blobP})])
      .then(()=>toast('Full report image copied to clipboard'))
      .catch(e=>{ console.error('full-img-clip', e); toast('Image copy failed'); })
      .finally(done);
    return; }
  if(kind==='report-html'){
    const bg=getComputedStyle(document.documentElement).getPropertyValue('--panel').trim()||'#171a23';
    const src=document.getElementById('dashboard');
    const liveCanvas=src.querySelectorAll('canvas');
    const clone=src.cloneNode(true);
    clone.querySelectorAll('canvas').forEach((c,i)=>{
      const live=liveCanvas[i]; const t=document.createElement('canvas'); t.width=live.width; t.height=live.height;
      const cx=t.getContext('2d'); cx.fillStyle=bg; cx.fillRect(0,0,t.width,t.height); cx.drawImage(live,0,0);
      const img=document.createElement('img'); img.src=t.toDataURL('image/png'); img.style.width='100%'; c.replaceWith(img);
    });
    clone.querySelectorAll('.noprint').forEach(e=>e.remove());
    clone.querySelectorAll('input').forEach(inp=>{ const s=document.createElement('span'); s.textContent=inp.value; inp.replaceWith(s); });
    const theme=document.documentElement.dataset.theme||'dark';
    const styles=document.querySelector('style').outerHTML;
    const html=`<!DOCTYPE html><html data-theme="${theme}"><head><meta charset="utf-8">`+
      `<meta name="viewport" content="width=device-width, initial-scale=1">`+
      `<title>Tenable Vulnerability Dashboard — report ${stamp}</title>${styles}</head>`+
      `<body><main style="padding:24px 28px"><h1>Tenable Vulnerability Dashboard</h1>`+
      `<p class="sub" style="color:var(--muted)">Generated ${stamp} · all analysis performed locally in-browser.</p>`+
      `${clone.outerHTML}</main></body></html>`;
    dl(`vm_report_${stamp}.html`, html, 'text/html'); return; }
  if(kind==='sla-csv'){ const t=slaTable(); dl(`sla_summary_${stamp}.csv`, toCsv(t.headers,t.rows), 'text/csv'); return; }
  if(kind==='topvulns-csv'){ dl(`top_exploitable_vulns_${stamp}.csv`, objCsv(R.topVulns), 'text/csv'); return; }
  if(kind==='hosts-csv'){ dl(`most_exposed_hosts_${stamp}.csv`, objCsv(R.hosts), 'text/csv'); return; }
  if(kind==='breakdowns-csv'){
    const rows=[]; const push=(cat,k,v)=>rows.push([cat,k,v]);
    Object.entries(R.severity).forEach(([k,v])=>push('severity',k,v));
    Object.entries(R.os).forEach(([k,v])=>push('operatingSystem (exploitable)',k,v));
    Object.entries(R.byMonth).forEach(([k,v])=>push('mitigated_by_month',k,v));
    dl(`breakdowns_${stamp}.csv`, toCsv(['category','key','count'],rows), 'text/csv'); return; }
  if(kind==='open-csv'){ dl(`cumulative_open_${stamp}.csv`, objCsv(R.cumulative), 'text/csv'); return; }
  if(kind==='mit-csv'){ dl(`mitigated_${stamp}.csv`, objCsv(R.mitigated), 'text/csv'); return; }
  if(kind==='metrics-json'){ dl(`vm_metrics_${stamp}.json`, JSON.stringify({metrics:R.metrics, sla:R.sla, severity:R.severity, os:R.os, byMonth:R.byMonth}, null, 2), 'application/json'); return; }
  if(kind==='sla-xlsx' || kind==='all-xlsx'){
    const wb=XLSX.utils.book_new();
    const t=slaTable(); XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([t.headers,...t.rows]), 'SLA Summary');
    if(kind==='all-xlsx'){
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(R.topVulns), 'Top Exploitable');
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(R.hosts), 'Most Exposed Hosts');
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(Object.entries(R.severity).map(([severity,count])=>({severity,count}))), 'Severity');
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet([R.metrics]), 'Metrics');
    }
    XLSX.writeFile(wb, kind==='all-xlsx'?`vm_report_${stamp}.xlsx`:`sla_summary_${stamp}.xlsx`); return; }
  if(kind==='exec-md'){
    const m=R.metrics; const t=slaTable();
    let md=`# Vulnerability Management Report\n\n_Generated ${stamp} · all analysis performed locally in-browser._\n\n`;
    md+=`## Executive summary\n\n`;
    md+=`- Assets analyzed: **${m.totalHosts.toLocaleString()}**\n- Open findings: **${m.openFindings.toLocaleString()}**\n`;
    md+=`- Exploitable open: **${m.exploitableOpen.toLocaleString()}**\n- Exploitable per asset: **${m.exploitablePerAsset}** (SLA ${m.sla}, ${m.pctOfSla}% of SLA)\n`;
    md+=`- Mitigated findings: **${m.mitigated.toLocaleString()}**\n- Mean time to remediate: **${m.mttrDays!=null?m.mttrDays+' days':'n/a'}**\n\n`;
    md+=`## Exploitable-vulnerability SLA by segment\n\n| ${t.headers.join(' | ')} |\n|${t.headers.map(()=>'---').join('|')}|\n`;
    t.rows.forEach(r=>md+=`| ${r.join(' | ')} |\n`);
    md+=`\n## Top exploitable vulnerabilities\n\n| Plugin | Severity | CVE | Instances | Hosts |\n|---|---|---|---|---|\n`;
    R.topVulns.forEach(v=>md+=`| ${v.plugin} | ${v.severity} | ${v.cve||'—'} | ${v.instances} | ${v.hosts} |\n`);
    dl(`vm_report_${stamp}.md`, md, 'text/markdown'); return; }
}

// ---------- chart helpers ----------
function donut(id,labels,data,colorMap){
  const ctx=document.getElementById(id);
  charts.push(new Chart(ctx,{type:'doughnut',
    data:{labels,datasets:[{data,backgroundColor:labels.map(l=>colorMap[l]||'#4f8cff'),borderWidth:0}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:tc()}}}}}));
}
function bar(id,labels,datasets){
  charts.push(new Chart(document.getElementById(id),{type:'bar',data:{labels,datasets},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:tc()}}},
      scales:{x:{ticks:{color:tc()},grid:{display:false}},y:{ticks:{color:tc()},grid:{color:gc()}}}}}));
}
function stackedHBar(id,labels,datasets){
  charts.push(new Chart(document.getElementById(id),{type:'bar',data:{labels,datasets},
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
      scales:{x:{stacked:true,ticks:{color:tc()},grid:{color:gc()}},y:{stacked:true,ticks:{color:tc()},grid:{display:false}}}}}));
}
function hbar(id,labels,data,color){
  charts.push(new Chart(document.getElementById(id),{type:'bar',
    data:{labels,datasets:[{data,backgroundColor:color}]},
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
      scales:{x:{ticks:{color:tc()},grid:{color:gc()}},y:{ticks:{color:tc()},grid:{display:false}}}}}));
}
function line(id,labels,data){
  charts.push(new Chart(document.getElementById(id),{type:'line',
    data:{labels,datasets:[{data,label:'Mitigated',borderColor:PAL().ok,backgroundColor:PAL().ok+'26',fill:true,tension:.3}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
      scales:{x:{ticks:{color:tc()},grid:{display:false}},y:{ticks:{color:tc()},grid:{color:gc()}}}}}));
}
function topBy(rows,keyfn,n){
  const m={}; rows.forEach(r=>{const k=keyfn(r);(m[k]=m[k]||[]).push(r)});
  return Object.entries(m).sort((a,b)=>b[1].length-a[1].length).slice(0,n);
}
function kpi(l,v,cls,sub,tip){ const txt=String(v).replace(/<[^>]*>/g,''); return `<div class="card"${tip?` title="${tip}"`:''}><div class="l">${l}</div>
  <div class="v ${txt.length>6?'s':''}">${v}</div>${sub?`<div class="sub" style="color:var(--${cls==='over'?'crit':'ok'})">${sub}</div>`:''}</div>`; }
function html(s){ const t=document.createElement('template'); t.innerHTML=s.trim(); return t.content.firstChild; }
(function(){ const tt=document.getElementById('tt'); let cur=null;
  document.addEventListener('mouseover', e=>{ const el=e.target.closest('[title],[data-tt]'); if(!el) return;
    if(el.hasAttribute('title')){ el.setAttribute('data-tt', el.getAttribute('title')); el.removeAttribute('title'); }
    const txt=el.getAttribute('data-tt'); if(!txt) return; cur=el; tt.textContent=txt; tt.style.display='block'; tt.style.opacity='1'; });
  document.addEventListener('mousemove', e=>{ if(tt.style.display!=='block') return;
    const r=tt.getBoundingClientRect(); let x=e.clientX+14, y=e.clientY+16;
    if(x+r.width>innerWidth-8) x=Math.max(8,e.clientX-14-r.width); if(y+r.height>innerHeight-8) y=Math.max(8,e.clientY-12-r.height);
    tt.style.left=x+'px'; tt.style.top=y+'px'; });
  document.addEventListener('mouseout', e=>{ if(cur && (!e.relatedTarget || !cur.contains(e.relatedTarget))){ tt.style.opacity='0'; tt.style.display='none'; cur=null; } });
})();
const PANEL_TIPS = {
  'Vulnerabilities past remediation SLA':'Set per-severity remediation SLA day targets (aged from vulnPubDate). The datapoints count and average findings past those targets.',
  'KPI - Exploitable vulnerability SLA by segment':'Editable what-if: per-segment exploitable findings ÷ assets vs the 0.25 SLA. Edit the basic values to see Per asset, % of SLA and Status recalculate; Per asset and % of SLA turn green within SLA, red when over.',
  'Vulnerabilities past remediation SLA by segment':'Plugin × segment counts of open findings past their remediation SLA — driven live by the SLA day targets above.',
  'Open findings by severity':'Severity breakdown of all open findings.',
  'Exploitable vulnerabilities by SLA, and segment':'Per-segment exploitable findings vs the per-segment SLA threshold (assets × 0.25).',
  'Vulnerabilities by operating system and SLA status':'Open findings per operating system, stacked by within-SLA and past-SLA (by severity).',
  'Most-exposed hosts (by exploitable findings)':'Hosts ranked by exploitable finding count. Filter by severity and choose how many to show.'
};
function applyPanelTips(){
  document.querySelectorAll('#dashboard .panel h3').forEach(h=>{ const t=PANEL_TIPS[h.textContent.trim()]; if(t){ h.title=t; h.style.cursor='help'; } });
}
function buildJumpNav(){
  const sel=document.getElementById('jumpSel'), bar=document.getElementById('jumpBar'), dash=document.getElementById('dashboard');
  if(!sel||!dash) return;
  const panels=[...dash.querySelectorAll('.panel')];
  panels.forEach((p,i)=>{ if(!p.id) p.id='sec-'+i; });
  sel.innerHTML='<option value="">Jump to section…</option>'+panels.map(p=>{ const h=p.querySelector('h3'); return `<option value="${p.id}">${h?h.textContent:p.id}</option>`; }).join('');
  const ss=document.getElementById('segSel');
  if(ss){ const segs=[...new Set([...STATE.cumulative,...STATE.mitigated].map(bu))].sort();
    ss.innerHTML='<option value="all">All segments</option>'+segs.map(s=>`<option value="${s}">${String(s).replace(/_Repo$/,'')}</option>`).join('');
    ss.value=STATE.segFilter; }
  if(bar) bar.style.display = panels.length ? 'block' : 'none';
}


    // Preload from the shared unified importer (VMStore). If it has data, it is the source
    // of truth (reset first to avoid duplicate concat); otherwise keep any in-session uploads.
    (function(){
      function rowsFrom(rec){ if(!rec||!rec.text) return null; try { if(rec.kind==='json'){ var d=JSON.parse(rec.text); if(!Array.isArray(d)) d=d.results||(d.response&&d.response.results)||[]; return d; } return Papa.parse(rec.text,{header:true,skipEmptyLines:true,dynamicTyping:false}).data; } catch(e){ return null; } }
      function done(){ if(STATE && (STATE.cumulative.length || STATE.mitigated.length)) render(); }
      if(!window.VMStore){ done(); return; }
      Promise.all([window.VMStore.get('tvd:cumulative').catch(function(){return null;}), window.VMStore.get('tvd:mitigated').catch(function(){return null;})])
        .then(function(r){
          var cum=rowsFrom(r[0]), mit=rowsFrom(r[1]);
          if(cum||mit){ STATE.cumulative=[]; STATE.mitigated=[]; if(cum)addRows(cum, (r[0]&&r[0].name)||'cumulative', 'cumulative'); if(mit)addRows(mit, (r[1]&&r[1].name)||'mitigated', 'mitigated'); if(typeof setState==='function') setState(); }
          done();
        }).catch(done);
    })();
  }
})();
