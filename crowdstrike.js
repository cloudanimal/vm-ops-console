/* CrowdStrike Falcon Spotlight Dashboard — native VM Ops page, route #/crowdstrike.
   SYNTHETIC data shaped like the Falcon Spotlight `combined/vulnerabilities`
   API (agent-based, no scans: ExPRT.AI rating, exploit_status, host sensor,
   status lifecycle), so a future connector swaps in a live feed with no layout
   change. No network. */
(function () {
  var app = document.getElementById('app');

  // Vulnerabilities: mirrors Falcon Spotlight vulnerability records.
  // exprt = ExPRT.AI rating (CROWDSTRIKE's AI exploitability rating).
  // exploit = exploit_status band: Unproven / Available / Easily accessible / Actively used.
  var VULN = [
    cs('CVE-2021-44228', 'Apache Log4j2 JNDI RCE (Log4Shell)', 'CRITICAL', 10.0, 'Actively used', 'app01.corp.local', 'Linux', 'Ubuntu 20.04', 'open', 41, 'log4j-core 2.14.1', true),
    cs('CVE-2019-19781', 'Citrix ADC Directory Traversal', 'CRITICAL', 9.8, 'Actively used', 'file01.corp.local', 'Linux', 'Citrix ADC 13.0', 'reopened', 58, 'netscaler 13.0', true),
    cs('CVE-2020-1472', 'Netlogon Elevation (Zerologon)', 'CRITICAL', 10.0, 'Actively used', 'dc01.corp.local', 'Windows', 'Server 2019', 'open', 33, 'netlogon', true),
    cs('CVE-2022-42475', 'FortiOS SSL-VPN Heap Overflow', 'CRITICAL', 9.8, 'Easily accessible', 'mail01.corp.local', 'Linux', 'FortiOS 7.2.2', 'open', 12, 'fortios 7.2.2', true),
    cs('CVE-2021-26855', 'Exchange ProxyLogon SSRF', 'HIGH', 9.1, 'Actively used', 'app02.corp.local', 'Windows', 'Server 2019', 'open', 22, 'exchange 2019 cu8', true),
    cs('CVE-2023-34362', 'MOVEit Transfer SQL Injection', 'CRITICAL', 9.8, 'Actively used', 'vpn01.corp.local', 'Windows', 'Server 2022', 'open', 9, 'moveit 15.0', true),
    cs('CVE-2023-4911', 'glibc ld.so Overflow (Looney Tunables)', 'HIGH', 7.8, 'Available', 'app01.corp.local', 'Linux', 'Ubuntu 20.04', 'open', 27, 'glibc 2.34', false),
    cs('CVE-2023-44487', 'HTTP/2 Rapid Reset DoS', 'MEDIUM', 7.5, 'Available', 'web03.corp.local', 'Linux', 'Ubuntu 22.04', 'open', 15, 'nginx 1.25.2', false),
    cs('CVE-2023-38545', 'cURL SOCKS5 Heap Overflow', 'HIGH', 8.8, 'Unproven', 'web03.corp.local', 'Linux', 'Ubuntu 22.04', 'closed', 6, 'curl 8.3.0', false),
    cs('CVE-2022-1471', 'SnakeYAML Deserialization RCE', 'HIGH', 8.3, 'Available', 'app02.corp.local', 'Linux', 'Ubuntu 20.04', 'open', 19, 'snakeyaml 1.30', false),
    cs('CVE-2023-36884', 'Office / Windows HTML RCE', 'HIGH', 7.5, 'Actively used', 'ws-231.corp.local', 'Windows', 'Windows 11', 'open', 14, 'office 2019', true),
    cs('CVE-2021-3711', 'OpenSSL SM2 Decryption Overflow', 'HIGH', 9.8, 'Unproven', 'legacy01.corp.local', 'Linux', 'CentOS 7', 'reopened', 44, 'openssl 1.1.1k', false),
    cs('CVE-2024-3094', 'XZ Utils Backdoor', 'CRITICAL', 10.0, 'Available', 'build-runner-3', 'Linux', 'Debian 12', 'open', 3, 'xz 5.6.1', false),
    cs('CVE-2023-2650', 'OpenSSL OBJ_obj2txt DoS', 'MEDIUM', 6.5, 'Unproven', 'db01.corp.local', 'Linux', 'Ubuntu 22.04', 'open', 21, 'openssl 3.0.8', false),
    cs('CVE-2023-20198', 'Cisco IOS XE Web UI Priv Esc', 'CRITICAL', 10.0, 'Actively used', 'core-sw-01', 'Linux', 'IOS XE 17.6', 'open', 7, 'ios-xe 17.6', true)
  ];
  function cs(cve, title, exprt, base, exploit, host, platform, os, status, daysOpen, product, kev) {
    return { cve: cve, title: title, exprt: exprt, base: base, exploit: exploit, host: host,
      platform: platform, os: os, status: status, daysOpen: daysOpen, product: product, kev: kev };
  }

  var EXPRT_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  var EXPRT_TONE = { CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low' };
  var EXPRT_VAR = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)' };
  var EXPLOIT_ORDER = ['Actively used', 'Easily accessible', 'Available', 'Unproven'];
  var EXPLOIT_VAR = { 'Actively used': 'var(--crit)', 'Easily accessible': 'var(--high)', 'Available': 'var(--med)', 'Unproven': 'var(--low)' };
  var STATUS_ORDER = ['open', 'reopened', 'closed'];
  var STATUS_VAR = { open: 'var(--high)', reopened: 'var(--crit)', closed: 'var(--ok)' };
  var HOSTS_WITH_SENSOR = 461;

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]; }); }
  function by(arr, key) { var m = {}; arr.forEach(function (x) { var k = key(x); m[k] = (m[k] || 0) + 1; }); return m; }
  function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  function kpis() {
    var open = VULN.filter(function (v) { return v.status !== 'closed'; });
    var critExprt = VULN.filter(function (v) { return v.exprt === 'CRITICAL' && v.status !== 'closed'; }).length;
    var active = VULN.filter(function (v) { return v.exploit === 'Actively used' && v.status !== 'closed'; }).length;
    var reopened = VULN.filter(function (v) { return v.status === 'reopened'; }).length;
    var openList = open;
    var avgAge = Math.round(openList.reduce(function (a, v) { return a + v.daysOpen; }, 0) / openList.length);
    return { total: open.length, critExprt: critExprt, active: active, reopened: reopened, avgAge: avgAge };
  }
  function kpiCard(label, val, sub, tone) {
    return '<div class="sc-kpi' + (tone ? ' ' + tone : '') + '"><div class="sc-kpi-v">' + val + '</div><div class="sc-kpi-l">' + esc(label) + '</div>' + (sub ? '<div class="sc-kpi-s">' + esc(sub) + '</div>' : '') + '</div>';
  }
  function barRow(label, count, max, color, isHtml) {
    var pct = max ? Math.round(count / max * 100) : 0;
    return '<div class="sc-bar"><span class="sc-bar-l">' + (isHtml ? label : esc(label)) + '</span>'
      + '<span class="sc-bar-track"><span class="sc-bar-fill" style="width:' + pct + '%;background:' + color + '"></span></span>'
      + '<span class="sc-bar-n">' + count + '</span></div>';
  }
  function card(title, body, note) {
    return '<section class="sc-card"><h3>' + esc(title) + '</h3>' + (note ? '<div class="sc-cardnote">' + note + '</div>' : '') + body + '</section>';
  }

  var OPEN = VULN.filter(function (v) { return v.status !== 'closed'; });

  function exprtBlock() {
    var m = by(OPEN, function (v) { return v.exprt; });
    var max = Math.max.apply(null, EXPRT_ORDER.map(function (s) { return m[s] || 0; }));
    var rows = EXPRT_ORDER.map(function (s) { return barRow(cap(s.toLowerCase()), m[s] || 0, max, EXPRT_VAR[s]); }).join('');
    return card('Open vulnerabilities by ExPRT.AI rating', rows, 'ExPRT.AI is CrowdStrike’s AI rating of real-world exploitability — it often reprioritizes a high-CVSS CVE that is not actually being exploited.');
  }
  function exploitBlock() {
    var m = by(OPEN, function (v) { return v.exploit; });
    var max = Math.max.apply(null, EXPLOIT_ORDER.map(function (s) { return m[s] || 0; }));
    var rows = EXPLOIT_ORDER.map(function (s) { return barRow(s, m[s] || 0, max, EXPLOIT_VAR[s]); }).join('');
    return card('Exploit status', rows, 'Spotlight tracks each CVE from Unproven up to Actively Used in the wild, updated from CrowdStrike threat intel in real time.');
  }
  function platformBlock() {
    var m = by(OPEN, function (v) { return v.platform; });
    var keys = Object.keys(m).sort(function (a, b) { return m[b] - m[a]; });
    var max = Math.max.apply(null, keys.map(function (k) { return m[k]; }));
    var rows = keys.map(function (k) { return barRow(k, m[k], max, 'var(--accent)'); }).join('');
    return card('Open vulnerabilities by platform', rows);
  }
  function productBlock() {
    // Top vulnerable products (Spotlight `apps.product_name_version` rollup).
    var m = {};
    OPEN.forEach(function (v) {
      var name = v.product.replace(/\s+[\d.]+$/, '');
      if (!m[name]) m[name] = { name: name, n: 0 };
      m[name].n++;
    });
    var list = Object.keys(m).map(function (k) { return m[k]; }).sort(function (a, b) { return b.n - a.n; }).slice(0, 6);
    var max = Math.max.apply(null, list.map(function (x) { return x.n; }));
    var rows = list.map(function (x) { return barRow(x.name, x.n, max, 'var(--accent)'); }).join('');
    return card('Top vulnerable products', rows);
  }
  function topBlock() {
    var rank = { 'Actively used': 3, 'Easily accessible': 2, 'Available': 1, 'Unproven': 0 };
    var sorted = OPEN.slice().sort(function (a, b) {
      var e = EXPRT_ORDER.indexOf(a.exprt) - EXPRT_ORDER.indexOf(b.exprt);
      if (e !== 0) return e;
      return rank[b.exploit] - rank[a.exploit];
    }).slice(0, 10);
    var rows = sorted.map(function (v) {
      var aged = v.daysOpen >= 30;
      return '<tr><td><span class="sc-sev ' + EXPRT_TONE[v.exprt] + '">' + v.exprt.charAt(0) + '</span></td>'
        + '<td class="mono">' + esc(v.cve) + '</td>'
        + '<td>' + esc(v.title) + '</td>'
        + '<td class="mono">' + v.base.toFixed(1) + '</td>'
        + '<td style="color:' + EXPLOIT_VAR[v.exploit] + '">' + esc(v.exploit) + '</td>'
        + '<td>' + esc(v.host) + '<div class="sc-sub">' + esc(v.os) + '</div></td>'
        + '<td class="sc-risk" style="color:' + (aged ? 'var(--crit)' : 'var(--soft)') + '">' + v.daysOpen + 'd</td>'
        + '<td>' + (v.kev ? '<span class="sc-tag kev">KEV</span>' : '') + (v.status === 'reopened' ? '<span class="sc-tag status">Reopened</span>' : '') + '</td></tr>';
    }).join('');
    return card('Top open vulnerabilities by ExPRT.AI',
      '<table class="sc-table"><thead><tr><th>ExPRT</th><th>CVE</th><th>Title</th><th>CVSS</th><th>Exploit status</th><th>Host</th><th>Age</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>');
  }

  function render() {
    if (!app) return;
    app.className = '';
    var k = kpis();
    var html = '<div class="scapp">'
      + '<div class="schead"><div class="overline">CrowdStrike</div>'
      + '<h1>Falcon Spotlight vulnerabilities</h1>'
      + '<p class="lede">Agentless-to-you, sensor-based vulnerability management — no scans. ExPRT.AI exploitability ratings and real-time exploit status across every host with the Falcon sensor, cross-referenced with your Tenable, Qualys, Rapid7, Wiz, and KEV data in one place.</p></div>'
      + '<div class="sctools"><span class="sc-sample">Sample data — API-shaped preview</span>'
      + '<span class="priv">🔒 100% local — nothing leaves this browser</span></div>'
      + '<div class="sc-kpis">'
      + kpiCard('Open vulnerabilities', k.total, 'from Falcon sensors', '')
      + kpiCard('ExPRT Critical', k.critExprt, 'AI-rated critical', 'crit')
      + kpiCard('Actively used', k.active, 'exploited in the wild', 'crit')
      + kpiCard('Reopened', k.reopened, 'regressed after fix', 'high')
      + kpiCard('Avg age', k.avgAge + 'd', 'days open', 'high')
      + kpiCard('Hosts w/ sensor', HOSTS_WITH_SENSOR.toLocaleString(), 'real-time coverage', '')
      + '</div>'
      + '<div class="sc-grid2">' + exprtBlock() + exploitBlock() + '</div>'
      + '<div class="sc-grid2">' + platformBlock() + productBlock() + '</div>'
      + topBlock()
      + '<div class="sc-foot">Synthetic data modeled on the Falcon Spotlight combined-vulnerabilities API (ExPRT.AI rating, exploit_status, host sensor, status lifecycle). When a CrowdStrike connector is added, this dashboard reads the live tenant with no layout changes. See the roadmap for the connector.</div>'
      + '</div>';
    app.innerHTML = html;
  }

  window.CROWDSTRIKE = { open: render, data: { vulns: VULN } };
})();
