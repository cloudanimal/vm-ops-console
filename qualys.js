/* Qualys VMDR Dashboard — native VM Ops page, route #/qualys.
   SYNTHETIC data shaped like the Qualys VMDR Detection API (QID-based
   detections: severity 1-5, TruRisk score, detection status), so a future
   Qualys connector can swap in a live feed with no layout change. No network. */
(function () {
  var app = document.getElementById('app');

  // Detections: mirrors Qualys VMDR `/api/2.0/fo/asset/host/vm/detection` records.
  // sev = Qualys severity level 1-5 (5 = Critical/Urgent). truRisk = QID TruRisk score.
  var DET = [
    q(730001, 'CVE-2024-3400', 'Palo Alto PAN-OS GlobalProtect Command Injection', 5, 10.0, 98, 'fw01.corp.local', '10.4.1.1', 'PAN-OS', 'Active', true, true),
    q(730002, 'CVE-2025-0282', 'Ivanti Connect Secure Stack Overflow RCE', 5, 9.0, 96, 'vpn01.corp.local', '10.4.1.51', 'Ivanti ICS', 'New', true, true),
    q(730003, 'CVE-2024-47575', 'Fortinet FortiManager Missing Authentication (FortiJump)', 5, 9.8, 95, 'mail01.corp.local', '10.4.1.32', 'FortiManager', 'Active', true, true),
    q(730004, 'CVE-2024-1709', 'ConnectWise ScreenConnect Authentication Bypass', 5, 10.0, 97, 'app02.corp.local', '10.4.1.22', 'Windows Server', 'New', true, true),
    q(730005, 'CVE-2023-46604', 'Apache ActiveMQ OpenWire Deserialization RCE', 5, 10.0, 96, 'app01.corp.local', '10.4.1.21', 'Linux', 'Active', true, true),
    q(730006, 'CVE-2024-4577', 'PHP-CGI Argument Injection (Windows)', 5, 9.8, 94, 'web03.corp.local', '10.4.1.60', 'Windows Server', 'Active', true, true),
    q(730007, 'CVE-2024-27198', 'JetBrains TeamCity Authentication Bypass', 5, 9.8, 93, 'ci01.corp.local', '10.4.2.10', 'Linux', 'New', true, true),
    q(730008, 'CVE-2024-40711', 'Veeam Backup & Replication Deserialization RCE', 5, 9.8, 92, 'legacy01.corp.local', '10.4.1.80', 'Windows Server', 'Re-Opened', true, true),
    q(91785, 'CVE-2020-1472', 'Microsoft Netlogon Elevation (Zerologon)', 5, 10.0, 97, 'dc01.corp.local', '10.4.1.10', 'Windows Server', 'Active', true, true),
    q(376157, 'CVE-2021-44228', 'Apache Log4j Remote Code Execution (Log4Shell)', 5, 10.0, 98, 'app01.corp.local', '10.4.1.21', 'Linux', 'Active', true, true),
    q(730009, 'CVE-2024-24919', 'Check Point Security Gateway Information Disclosure', 4, 8.6, 78, 'fw01.corp.local', '10.4.1.1', 'Gaia', 'Active', true, true),
    q(730010, 'CVE-2024-38112', 'Microsoft Windows MSHTML Platform Spoofing', 4, 7.5, 74, 'ws-231.corp.local', '10.4.2.31', 'Windows 11', 'New', true, true),
    q(38773, 'CVE-2023-2650', 'OpenSSL OBJ_obj2txt DoS', 3, 6.5, 41, 'db01.corp.local', '10.4.1.70', 'Linux', 'Fixed', false, false),
    q(38143, 'CVE-2023-0464', 'OpenSSL X.509 Policy Constraints DoS', 3, 5.9, 38, 'db01.corp.local', '10.4.1.70', 'Linux', 'Active', false, false),
    q(38169, 'CVE-2016-2183', 'SSL/TLS 64-bit Block Cipher (SWEET32)', 2, 3.7, 18, 'legacy01.corp.local', '10.4.1.80', 'Linux', 'Active', false, false)
  ];
  function q(qid, cve, title, sev, cvss, truRisk, host, ip, os, status, patchable, kev) {
    return { qid: qid, cve: cve, title: title, sev: sev, cvss: cvss, truRisk: truRisk,
      host: host, ip: ip, os: os, status: status, patchable: patchable, kev: kev,
      type: sev >= 4 ? 'Confirmed' : 'Confirmed' };
  }

  var SEV_LABEL = { 5: 'Sev 5 — Critical', 4: 'Sev 4 — High', 3: 'Sev 3 — Medium', 2: 'Sev 2 — Low', 1: 'Sev 1 — Info' };
  var SEV_TONE = { 5: 'crit', 4: 'high', 3: 'med', 2: 'low', 1: 'low' };
  var SEV_VAR = { 5: 'var(--crit)', 4: 'var(--high)', 3: 'var(--med)', 2: 'var(--low)', 1: 'var(--low)' };
  var STATUS_ORDER = ['New', 'Active', 'Re-Opened', 'Fixed'];
  var STATUS_VAR = { New: 'var(--accent)', Active: 'var(--high)', 'Re-Opened': 'var(--crit)', Fixed: 'var(--ok)' };
  // Asset universe (mirrors Qualys host assets scanned).
  var ASSETS_SCANNED = 428;

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]; }); }
  function by(arr, key) { var m = {}; arr.forEach(function (x) { var k = key(x); m[k] = (m[k] || 0) + 1; }); return m; }

  function kpis() {
    var open = DET.filter(function (d) { return d.status !== 'Fixed'; });
    var sev5 = DET.filter(function (d) { return d.sev === 5; }).length;
    var avg = Math.round(DET.reduce(function (a, d) { return a + d.truRisk; }, 0) / DET.length);
    var reopened = DET.filter(function (d) { return d.status === 'Re-Opened'; }).length;
    var patchable = DET.filter(function (d) { return d.patchable && d.status !== 'Fixed'; }).length;
    return { total: DET.length, open: open.length, sev5: sev5, avg: avg, reopened: reopened, patchable: patchable };
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

  function sevBlock() {
    var m = by(DET, function (d) { return d.sev; });
    var levels = [5, 4, 3, 2, 1];
    var max = Math.max.apply(null, levels.map(function (s) { return m[s] || 0; }));
    var rows = levels.map(function (s) { return barRow(SEV_LABEL[s], m[s] || 0, max, SEV_VAR[s]); }).join('');
    return card('Detections by Qualys severity', rows, 'Qualys rates each QID on its 1–5 severity scale (5 = Critical). Distinct from raw CVSS.');
  }
  function statusBlock() {
    var m = by(DET, function (d) { return d.status; });
    var max = Math.max.apply(null, STATUS_ORDER.map(function (s) { return m[s] || 0; }));
    var rows = STATUS_ORDER.map(function (s) { return barRow(s, m[s] || 0, max, STATUS_VAR[s]); }).join('');
    return card('Detections by status', rows, 'VMDR tracks a detection lifecycle: New → Active, Fixed on remediation, and Re-Opened if it is detected again.');
  }
  function truRiskBlock() {
    var bands = [
      { l: 'Critical (90–100)', lo: 90, hi: 101, c: 'var(--crit)' },
      { l: 'High (70–89)', lo: 70, hi: 90, c: 'var(--high)' },
      { l: 'Medium (40–69)', lo: 40, hi: 70, c: 'var(--med)' },
      { l: 'Low (1–39)', lo: 1, hi: 40, c: 'var(--low)' }
    ];
    var max = Math.max.apply(null, bands.map(function (b) { return DET.filter(function (d) { return d.truRisk >= b.lo && d.truRisk < b.hi; }).length; }));
    var rows = bands.map(function (b) {
      var n = DET.filter(function (d) { return d.truRisk >= b.lo && d.truRisk < b.hi; }).length;
      return barRow(b.l, n, max, b.c);
    }).join('');
    return card('TruRisk score distribution', rows, 'Qualys TruRisk blends CVSS, threat intelligence, exploit maturity, and asset context into a single 0–100 score per detection.');
  }
  function osBlock() {
    var m = by(DET, function (d) { return d.os; });
    var keys = Object.keys(m).sort(function (a, b) { return m[b] - m[a]; });
    var max = Math.max.apply(null, keys.map(function (k) { return m[k]; }));
    var rows = keys.map(function (k) { return barRow(k, m[k], max, 'var(--accent)'); }).join('');
    return card('Detections by operating system', rows);
  }
  function topBlock() {
    var sorted = DET.slice().filter(function (d) { return d.status !== 'Fixed'; }).sort(function (a, b) { return b.truRisk - a.truRisk; }).slice(0, 10);
    var rows = sorted.map(function (d) {
      return '<tr><td><span class="sc-sev ' + SEV_TONE[d.sev] + '">' + d.sev + '</span></td>'
        + '<td class="mono">' + d.qid + '</td>'
        + '<td class="mono">' + esc(d.cve) + '</td>'
        + '<td>' + esc(d.title) + '</td>'
        + '<td class="sc-risk" style="color:' + SEV_VAR[Math.min(5, Math.max(2, Math.round(d.truRisk / 20)))] + '">' + d.truRisk + '</td>'
        + '<td>' + esc(d.host) + '<div class="sc-sub mono">' + esc(d.ip) + '</div></td>'
        + '<td><span class="sc-tag status">' + esc(d.status) + '</span></td>'
        + '<td>' + (d.kev ? '<span class="sc-tag kev">KEV</span>' : '') + (d.patchable ? '<span class="sc-tag exp">Patchable</span>' : '') + '</td></tr>';
    }).join('');
    return card('Top open detections by TruRisk',
      '<table class="sc-table"><thead><tr><th>Sev</th><th>QID</th><th>CVE</th><th>Title</th><th>TruRisk</th><th>Asset</th><th>Status</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>');
  }

  function render() {
    if (!app) return;
    app.className = '';
    var k = kpis();
    var html = '<div class="scapp">'
      + '<div class="schead"><div class="overline">Qualys</div>'
      + '<h1>VMDR vulnerability posture</h1>'
      + '<p class="lede">QID-based detections with Qualys severity (1–5), TruRisk scoring, and detection-status lifecycle, cross-referenced with your Tenable, Wiz, and KEV data in one place.</p></div>'
      + '<div class="sctools"><span class="sc-sample">Sample data — API-shaped preview</span>'
      + '<span class="priv">🔒 100% local — nothing leaves this browser</span></div>'
      + '<div class="sc-kpis">'
      + kpiCard('Detections', k.total, 'open QIDs across assets', '')
      + kpiCard('Severity 5', k.sev5, 'Qualys Critical', 'crit')
      + kpiCard('Re-Opened', k.reopened, 'regressed after fix', 'crit')
      + kpiCard('Avg TruRisk', k.avg, 'across detections', 'high')
      + kpiCard('Patchable', k.patchable, 'have a vendor patch', 'high')
      + kpiCard('Assets scanned', ASSETS_SCANNED.toLocaleString(), 'authenticated scan', '')
      + '</div>'
      + '<div class="sc-grid2">' + sevBlock() + statusBlock() + '</div>'
      + '<div class="sc-grid2">' + truRiskBlock() + osBlock() + '</div>'
      + topBlock()
      + '<div class="sc-foot">Synthetic data modeled on the Qualys VMDR Detection API (QID, severity 1–5, TruRisk, detection status). When a Qualys connector is added, this dashboard reads the live subscription with no layout changes. See the roadmap for the connector.</div>'
      + '</div>';
    app.innerHTML = html;
  }

  window.QUALYS = { open: render, data: { detections: DET } };
})();
