const fs=require('fs');
const SRC='/Users/joe/Downloads/agent-coverage-dashboard';
const OUT='/Users/joe/Downloads/github-portfolio/vm-ops-console';
let html=fs.readFileSync(SRC+'/index.html','utf8');
let appjs=fs.readFileSync(SRC+'/app.js','utf8');

// ---- 1. CSS -> acd.css scoped under .acdapp ----
let css=html.match(/<style>([\s\S]*?)<\/style>/)[1];
// split into rules at top level; prefix selectors with .acdapp (leave :root/html[data-theme]/@keyframes/@media token blocks global)
function scopeSelectors(sel){
  return sel.split(',').map(s=>{
    s=s.trim();
    if(!s) return s;
    if(/^(:root|html\[data-theme)/.test(s)){
      // token blocks stay global; but compound like 'html[data-theme="light"] .card' -> insert .acdapp before the descendant
      return s.replace(/^(html\[data-theme="[^"]*"\])\s+(.+)$/, '$1 .acdapp $2');
    }
    if(s==='*') return '.acdapp *';
    if(s==='body') return '.acdapp';
    return '.acdapp '+s;
  }).join(', ');
}
let outcss='', i=0;
// naive tokenizer over rules / at-rules
const re=/([^{}]+)\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}/g; let m;
while((m=re.exec(css))){
  let sel=m[1].trim(), body=m[2];
  if(/^@keyframes/.test(sel)){ outcss+=sel+'{'+body+'}\n'; continue; }
  if(/^@media/.test(sel)){
    // scope inner rules
    let inner=body.replace(/([^{}]+)\{([^{}]*)\}/g,(mm,isel,ibody)=>scopeSelectors(isel)+'{'+ibody+'}');
    outcss+=sel+'{'+inner+'}\n'; continue;
  }
  if(/^:root/.test(sel) || /^html\[data-theme="[^"]*"\]$/.test(sel.trim())){ outcss+=sel+'{'+body+'}\n'; continue; }
  outcss+=scopeSelectors(sel)+'{'+body+'}\n';
}
outcss=outcss.replace(/\.toast\b/g,'.acdtoast'); // rename toast to avoid shell collision
// embed override: force the 4 source slots onto one horizontal row (the app's .wrap is narrower
// than the standalone, where auto-fit wrapped them 2x2); collapse on small screens.
outcss=outcss.replace(/\.acdapp \.slots\{display:grid;grid-template-columns:repeat\(auto-fit,minmax\(220px,1fr\)\);gap:12px;margin:16px 0\}/,
  '.acdapp .slots{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}\n@media(max-width:860px){.acdapp .slots{grid-template-columns:repeat(2,1fr)}}\n@media(max-width:520px){.acdapp .slots{grid-template-columns:1fr}}');
// Ops-Dashboard-style header (overline + serif h1 + lede) + controls toolbar below
outcss+='\n.acdapp .acdhead{padding:14px 0 4px}\n.acdapp .acdtools{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:0 0 12px;border-bottom:1px solid var(--line)}\n';
// align AC content with the app .wrap column (no extra inset / centering)
outcss+='.acdapp main{padding:18px 0;max-width:none;margin:0}\n';
// remap chrome tokens to the app's design tokens so AC matches the rest of the console (auto light/dark)
outcss+='.acdapp{ --bg:var(--paper); --panel:var(--surface); --panel2:color-mix(in srgb, var(--surface) 55%, var(--paper)); --txt:var(--ink); --muted:var(--soft); }\n';
fs.writeFileSync(OUT+'/acd.css', '/* Agent Coverage Dashboard — native page styles, scoped under .acdapp. */\n'+outcss);

// ---- 2. markup (body inner, minus scripts, minus themeBtn/resetBtn), drawer ids renamed, wrapped ----
let body=html.match(/<body>([\s\S]*?)<script src="app\.js">/)[1];
body=body.replace(/<button class="theme-toggle" id="themeBtn"[^>]*>[^<]*<\/button>\s*/,'');
body=body.replace(/<button class="btn" id="resetBtn"[^>]*>[^<]*<\/button>\s*/,'');
body=body.replace(/id="drawerBack"/g,'id="acdDrawerBack"').replace(/id="drawerBody"/g,'id="acdDrawerBody"').replace(/id="drawer"/g,'id="acdDrawer"');
// drop the uploader subtitle — it duplicates the new header lede
body=body.replace(/\s*<p class="sub"[^>]*>Active Directory is the source of truth[\s\S]*?<\/p>/,'');
// recast the header into the VM-Ops "view" style (overline + serif h1 + lede), controls in a toolbar below
body=body.replace(/<header>[\s\S]*?<\/header>/,
  '<div class="acdhead"><div class="overline">Agent Coverage</div><h1>Reconcile your agent coverage</h1>'+
  '<p class="lede">Active Directory is the source of truth (the denominator); every host is matched back to it by hostname across ManageEngine, Tenable, and CrowdStrike — all in your browser.</p></div>'+
  '<div class="acdtools"><span class="priv">🔒 100% local — your data never leaves this browser</span><div class="spacer"></div>'+
  '<select id="cbSel" class="btn" style="padding:8px 10px" title="Color-blind-safe palette" aria-label="Color palette">'+
  '<option value="default">Vivid</option><option value="deuteranopia">Deuteranopia-safe</option><option value="protanopia">Protanopia-safe</option><option value="tritanopia">Tritanopia-safe</option></select>'+
  '<select id="exportSel" class="btn" style="padding:8px 10px"></select><button class="btn" id="exportBtn">Export</button></div>');
// repoint the footer "source on GitHub" link to the umbrella repo (it's a native page here now)
body=body.replace(/https:\/\/github\.com\/cloudanimal\/agent-coverage-dashboard/g,'https://github.com/cloudanimal/vm-ops-console');
body=body.trim();

// ---- 3. app.js -> boot(), STATE hoisted, theme wiring removed, ids/toast renamed, sample live, onclick fns global ----
appjs=appjs.replace("const STATE = {","if(!STATE) STATE = {");
// remove its own theme apply + themeBtn toggle wiring (v2 owns light/dark)
appjs=appjs.replace(/\(function\(\)\{ const s=localStorage\.getItem\('acd-theme'\); if\(s\) document\.documentElement\.dataset\.theme=s; \}\)\(\);\n/,'');
appjs=appjs.replace(/\$\('#themeBtn'\)\.addEventListener[\s\S]*?applyPalette\(STATE\.cbTheme\); \}\);\n/,'');
// drawer id renames + toast class rename
appjs=appjs.replace(/#drawerBack/g,'#acdDrawerBack').replace(/#drawerBody/g,'#acdDrawerBody').replace(/#drawerX/g,'#acdDrawerX').replace(/#drawer\b/g,'#acdDrawer');
appjs=appjs.replace(/querySelector\('\.toast'\)/g,"querySelector('.acdtoast')").replace(/t\.className='toast'/g,"t.className='acdtoast'");
// sample data live (no stale, no copy)
appjs=appjs.replace(/fetch\('sample-data\//g,"fetch('https://cloudanimal.github.io/agent-coverage-dashboard/sample-data/");

const ESC = s=>s.replace(/\\/g,'\\\\').replace(/`/g,'\\`').replace(/\$\{/g,'\\${');
let out=`/* Agent Coverage Dashboard — native VM Ops page. Renders into #app on #/agent-coverage,
   wraps the original app so its functions persist (STATE held across navigation). */
(function(){
  var app=document.getElementById('app');
  var ACD_MARKUP='<div class="acdapp">'+\`${ESC(body)}\`+'</div>';
  var STATE;
  // Reset 'built' before each (re)boot: STATE persists across navigation, so a stale built=true
  // would make boot-time applyPalette()/loadConfig() call render() before CHARTS/AKEYS init (TDZ).
  // End-of-boot render() rebuilds from persisted STATE and sets built=true again.
  window.ACD={ open:function(){ if(STATE) STATE.built=false; app.className=''; app.innerHTML=ACD_MARKUP; boot(); } };
  function boot(){
${appjs}
    // expose inline-onclick handlers (markup uses onclick="pick(..)" etc.)
    window.pick=pick; window.toggleSources=toggleSources; window.downloadFlat=downloadFlat; window.downloadFlatAd=downloadFlatAd;
    // Preload source data from the shared unified importer (VMStore), parsing with this
    // app's own logic so the format matches. Falls back to any in-session uploads.
    (function(){
      function parse(rec){ if(!rec||!rec.text) return null; try { return rec.kind==='json' ? flattenAd(rec.text) : Papa.parse(rec.text,{header:true,skipEmptyLines:true}).data; } catch(e){ return null; } }
      function done(){ if(STATE && STATE.ad && STATE.ad.length){ render(); } }
      if(!window.VMStore){ done(); return; }
      Promise.all(['acd:ad','acd:me','acd:tsc','acd:tio','acd:cs'].map(function(id){ return window.VMStore.get(id).catch(function(){return null;}); }))
        .then(function(r){
          var ad=parse(r[0]), me=parse(r[1]), tsc=parse(r[2]), tio=parse(r[3]), cs=parse(r[4]);
          if(ad){ STATE.ad=ad; STATE.adCols=unionCols(ad); STATE.src.ad=r[0].name; }
          if(me){ STATE.me=me; STATE.src.me=r[1].name; }
          var ten=[]; if(tsc)ten=ten.concat(tsc); if(tio)ten=ten.concat(tio);
          if(ten.length){ STATE.ten=ten; STATE.src.ten=[tsc&&r[2].name, tio&&r[3].name].filter(Boolean).join(' + '); }
          if(cs){ STATE.cs=cs; STATE.src.cs=r[4].name; }
          done();
        }).catch(done);
    })();
  }
})();
`;
fs.writeFileSync(OUT+'/acd.js', out);
console.log('acd.css',outcss.length,'bytes; acd.js',out.length,'bytes');
