/* Build pscan.css + pscan.js (native Prompt Scanner page for vm-ops-console)
   from agent-supply-chain-scanner/docs/index.html. Mirrors buildtvd.js. Re-runnable. */
const fs = require('fs');
const SRC = '/Users/joe/Downloads/github-portfolio/agent-supply-chain-scanner/docs/index.html';
const OUT = '/Users/joe/Downloads/github-portfolio/vm-ops-console';
let html = fs.readFileSync(SRC, 'utf8');

// ---- 1. CSS -> pscan.css scoped under .pscan; DROP :root + prefers-color-scheme
//         (vm-ops design tokens + data-theme already provide theming) ----
let css = html.match(/<style>([\s\S]*?)<\/style>/)[1];
function scopeSelectors(sel) {
  return sel.split(',').map(s => {
    s = s.trim(); if (!s) return s;
    if (s === '*') return '.pscan *';
    if (s === 'body' || s === 'html') return '.pscan';
    return '.pscan ' + s;
  }).join(', ');
}
let outcss = '';
const re = /([^{}]+)\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}/g; let m;
while ((m = re.exec(css))) {
  let sel = m[1].trim(), body = m[2];
  if (/^:root/.test(sel)) continue;                                  // drop token block (use vm-ops tokens)
  if (/^@media[^{]*prefers-color-scheme/.test(sel)) continue;        // drop OS-dark block (vm-ops owns theme)
  if (/^@keyframes/.test(sel)) { outcss += sel + '{' + body + '}\n'; continue; }
  if (/^@media/.test(sel)) { outcss += sel + '{' + body.replace(/([^{}]+)\{([^{}]*)\}/g, (mm, isel, ibody) => scopeSelectors(isel) + '{' + ibody + '}') + '}\n'; continue; }
  outcss += scopeSelectors(sel) + '{' + body + '}\n';
}
// embedded: don't force the narrow 880px reading column — fill the app's content width
outcss = outcss.replace(/\.pscan \.wrap\{[^}]*\}/, '.pscan .wrap{ max-width:none; margin:0; padding:0 0 60px; }');
fs.writeFileSync(OUT + '/pscan.css', '/* Prompt Scanner — native page styles, scoped under .pscan. */\n' + outcss);

// ---- 2. markup (body inner, minus the script) ----
let body = html.match(/<body>([\s\S]*?)<script>/)[1].trim();
// embed-only rename: the standalone demo is branded "Prompt Scanner"; in VM Ops it's "AI Prompt Scanner"
body = body.replace('<div class="brand">Prompt Scanner ', '<div class="brand">AI Prompt Scanner ');

// ---- 3. inline IIFE script -> runs inside boot() on each open ----
let appjs = html.match(/<script>([\s\S]*?)<\/script>/)[1];

const ESC = s => s.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${');
let out = `/* Prompt Scanner — native VM Ops page. Renders into #app on #/prompt-scanner.
   Client-side scan engine (parity with the agentscan Python CLI); nothing leaves the browser. */
(function(){
  var app=document.getElementById('app');
  var PSCAN_MARKUP='<div class="pscan">'+\`${ESC(body)}\`+'</div>';
  window.PSCAN={ open:function(){ app.className=''; app.innerHTML=PSCAN_MARKUP; boot(); } };
  function boot(){
${appjs}
  }
})();
`;
fs.writeFileSync(OUT + '/pscan.js', out);
console.log('pscan.css', outcss.length, 'bytes; pscan.js', out.length, 'bytes');
