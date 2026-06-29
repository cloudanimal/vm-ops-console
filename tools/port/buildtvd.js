/* Build tvd.css + tvd.js (native Tenable VM Dashboard page for vm-ops-console-v2)
   from the standalone tenable-vm-dashboard/index.html. Mirrors buildacd.js. Re-runnable. */
const fs=require('fs');
const SRC='/Users/joe/Downloads/tenable-vm-dashboard';
const OUT='/Users/joe/Downloads/github-portfolio/vm-ops-console';
let html=fs.readFileSync(SRC+'/index.html','utf8');

// ---- 1. CSS -> tvd.css scoped under .tvdapp ----
let css=html.match(/<style>([\s\S]*?)<\/style>/)[1];
function scopeSelectors(sel){
  return sel.split(',').map(s=>{
    s=s.trim();
    if(!s) return s;
    if(/^(:root|html\[data-theme)/.test(s)){
      // token blocks stay global; compound 'html[data-theme="light"] .card' -> insert .tvdapp before the descendant
      return s.replace(/^(html\[data-theme="[^"]*"\])\s+(.+)$/, '$1 .tvdapp $2');
    }
    if(s==='*') return '.tvdapp *';
    if(s==='html'||s==='body') return '.tvdapp';
    return '.tvdapp '+s;
  }).join(', ');
}
let outcss='';
const re=/([^{}]+)\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}/g; let m;
while((m=re.exec(css))){
  let sel=m[1].trim(), body=m[2];
  if(/^@keyframes/.test(sel)){ outcss+=sel+'{'+body+'}\n'; continue; }
  if(/^@media/.test(sel)){
    let inner=body.replace(/([^{}]+)\{([^{}]*)\}/g,(mm,isel,ibody)=>scopeSelectors(isel)+'{'+ibody+'}');
    outcss+=sel+'{'+inner+'}\n'; continue;
  }
  if(/^:root/.test(sel) || /^html\[data-theme="[^"]*"\]$/.test(sel.trim())){ outcss+=sel+'{'+body+'}\n'; continue; }
  outcss+=scopeSelectors(sel)+'{'+body+'}\n';
}
// align with the app .wrap column + adopt the app's design tokens + Ops-Dashboard-style header
outcss=outcss.replace(/\.tvdapp main\{[^}]*\}/, '.tvdapp main{padding:24px 0;max-width:none;margin:0}');
outcss+='\n.tvdapp{ --bg:var(--paper); --panel:var(--surface); --panel2:color-mix(in srgb, var(--surface) 55%, var(--paper)); --txt:var(--ink); --muted:var(--soft); }\n'+
  '.tvdapp .tvdhead{padding:14px 0 4px}\n.tvdapp .tvdhead h1{font-family:var(--serif);font-weight:400;font-size:36px;letter-spacing:-0.5px;margin:0}\n'+
  '.tvdapp .tvdtools{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:0 0 14px;border-bottom:1px solid var(--line)}\n';
fs.writeFileSync(OUT+'/tvd.css', '/* Tenable VM Dashboard — native page styles, scoped under .tvdapp. */\n'+outcss);

// ---- 2. markup (body inner, minus scripts, minus the per-app theme toggle button) ----
let body=html.match(/<body>([\s\S]*?)<script>/)[1];
body=body.replace(/<button class="theme-toggle" id="themeBtn"[^>]*>[^<]*<\/button>\s*/,'');
// recast the header into the VM-Ops "view" style (overline + serif h1 + lede); controls drop into a toolbar
body=body.replace(/<header>\s*<div>\s*<h1>Tenable Vulnerability Dashboard<\/h1>\s*<div class="sub">[^<]*<\/div>\s*<\/div>\s*<div class="row noprint">/,
  '<div class="tvdhead"><div class="overline">Tenable Dashboard</div><h1>Your Tenable vulnerability program</h1><p class="lede">Upload your Tenable SC exports for instant KPIs, severity and SLA trends, top findings, and one-click reports — all in your browser.</p></div><div class="tvdtools row noprint">');
body=body.replace(/<\/div>\s*<\/header>/,'</div>');
// repoint the footer "source on GitHub" link to the umbrella repo (it's a native page here now)
body=body.replace(/https:\/\/github\.com\/cloudanimal\/tenable-vm-dashboard/g,'https://github.com/cloudanimal/vm-ops-console');
body=body.trim();

// ---- 3. inline JS -> boot(), STATE hoisted, theme wiring removed, sample live ----
let appjs=html.match(/<script>([\s\S]*?)<\/script>/)[1];
appjs=appjs.replace("let STATE = {","if(!STATE) STATE = {");
// remove the per-dashboard light/dark theme block (v2 owns the one global theme); palette picker stays
appjs=appjs.replace(/const themeBtn=\$\('#themeBtn'\);[\s\S]*?return 'dark'; \}\)\(\)\);\n/,'');
// sample data live (no stale copy bundled into v2)
appjs=appjs.replace(/fetch\('sample-data\//g,"fetch('https://cloudanimal.github.io/tenable-vm-dashboard/sample-data/");

const ESC = s=>s.replace(/\\/g,'\\\\').replace(/`/g,'\\`').replace(/\$\{/g,'\\${');
let out=`/* Tenable VM Dashboard — native VM Ops page. Renders into #app on #/tvd,
   wraps the original app so its functions persist (STATE held across navigation). */
(function(){
  var app=document.getElementById('app');
  var TVD_MARKUP='<div class="tvdapp">'+\`${ESC(body)}\`+'</div>';
  var STATE;
  // Reset the render cache before each (re)boot: STATE/window._report persist across navigation,
  // so a stale window._report would make boot-time applyPalette() call render() before its module
  // consts (charts/EXPL/etc.) initialize (TDZ). End-of-boot render() rebuilds from persisted STATE.
  window.TVD={ open:function(){ window._report=null; app.className=''; app.innerHTML=TVD_MARKUP; boot(); } };
  function boot(){
${appjs}
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
`;
fs.writeFileSync(OUT+'/tvd.js', out);
console.log('tvd.css',outcss.length,'bytes; tvd.js',out.length,'bytes');
