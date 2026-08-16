/* Rapid7 InsightVM Dashboard — native VM Ops page, route #/rapid7.
   SYNTHETIC data shaped like the Rapid7 InsightVM API (vulnerabilities with
   Real Risk Score 0-1000, Critical/Severe/Moderate severity, exploit + malware
   exposure, and remediation rollups), so a future connector swaps in a live
   feed with no layout change. No network. */
(function () {
  var app = document.getElementById('app');

  // Vulnerabilities: mirrors InsightVM `/api/3/vulnerabilities` + asset findings.
  // sev = Critical/Severe/Moderate (InsightVM's scale). risk = Real Risk Score (0-1000).
  var VULN = [
    r('panos-cve-2024-3400', 'CVE-2024-3400', 'PAN-OS GlobalProtect Command Injection', 'Critical', 10.0, 971, 'fw01.corp.local', '10.4.1.1', 'PAN-OS', true, true, true, 'Upgrade PAN-OS to a fixed 10.2/11.0/11.1 release'),
    r('ivanti-cve-2025-0282', 'CVE-2025-0282', 'Ivanti Connect Secure Stack Overflow RCE', 'Critical', 9.0, 948, 'vpn01.corp.local', '10.4.1.51', 'Ivanti ICS', true, true, true, 'Upgrade Connect Secure to 22.7R2.5+'),
    r('fortimgr-cve-2024-47575', 'CVE-2024-47575', 'FortiManager Missing Authentication (FortiJump)', 'Critical', 9.8, 940, 'mail01.corp.local', '10.4.1.32', 'FortiManager', true, false, true, 'Upgrade FortiManager to 7.4.5 / 7.2.8+'),
    r('screenconnect-cve-2024-1709', 'CVE-2024-1709', 'ConnectWise ScreenConnect Authentication Bypass', 'Critical', 10.0, 966, 'app02.corp.local', '10.4.1.22', 'Windows', true, true, true, 'Upgrade ScreenConnect to 23.9.8+'),
    r('activemq-cve-2023-46604', 'CVE-2023-46604', 'Apache ActiveMQ OpenWire RCE', 'Critical', 10.0, 958, 'app01.corp.local', '10.4.1.21', 'Linux', true, true, true, 'Upgrade ActiveMQ to 5.17.6 / 5.18.3+'),
    r('phpcgi-cve-2024-4577', 'CVE-2024-4577', 'PHP-CGI Argument Injection', 'Critical', 9.8, 934, 'web03.corp.local', '10.4.1.60', 'Windows', true, true, true, 'Upgrade PHP to 8.1.29 / 8.2.20 / 8.3.8+'),
    r('teamcity-cve-2024-27198', 'CVE-2024-27198', 'JetBrains TeamCity Authentication Bypass', 'Critical', 9.8, 930, 'ci01.corp.local', '10.4.2.10', 'Linux', true, false, true, 'Upgrade TeamCity to 2023.11.4+'),
    r('veeam-cve-2024-40711', 'CVE-2024-40711', 'Veeam Backup & Replication Deserialization RCE', 'Critical', 9.8, 928, 'legacy01.corp.local', '10.4.1.80', 'Windows', true, false, true, 'Upgrade Veeam Backup & Replication to 12.2+'),
    r('zerologon-cve-2020-1472', 'CVE-2020-1472', 'Netlogon Elevation of Privilege (Zerologon)', 'Critical', 10.0, 955, 'dc01.corp.local', '10.4.1.10', 'Windows', true, true, true, 'Apply August 2020 rollup + enforce mode'),
    r('log4j-cve-2021-44228', 'CVE-2021-44228', 'Apache Log4j2 JNDI RCE (Log4Shell)', 'Critical', 10.0, 968, 'app01.corp.local', '10.4.1.21', 'Linux', true, true, true, 'Upgrade log4j-core to 2.17.1+'),
    r('checkpoint-cve-2024-24919', 'CVE-2024-24919', 'Check Point Security Gateway Information Disclosure', 'Severe', 8.6, 742, 'fw01.corp.local', '10.4.1.1', 'Gaia', true, true, true, 'Apply the Check Point hotfix for CVE-2024-24919'),
    r('mshtml-cve-2024-38112', 'CVE-2024-38112', 'Windows MSHTML Platform Spoofing', 'Severe', 7.5, 760, 'ws-231.corp.local', '10.4.2.31', 'Windows', true, true, true, 'Apply the July 2024 cumulative update'),
    r('openssl-cve-2023-2650', 'CVE-2023-2650', 'OpenSSL OBJ_obj2txt DoS', 'Moderate', 6.5, 410, 'db01.corp.local', '10.4.1.70', 'Linux', false, false, false, 'Update OpenSSL to 3.0.9+'),
    r('sweet32-cve-2016-2183', 'CVE-2016-2183', 'TLS 64-bit Block Cipher (SWEET32)', 'Moderate', 3.7, 190, 'legacy01.corp.local', '10.4.1.80', 'Linux', false, false, false, 'Disable 3DES cipher suites')
  ];
  function r(id, cve, title, sev, cvss, risk, host, ip, os, msf, mal, kev, rem) {
    return { id: id, cve: cve, title: title, sev: sev, cvss: cvss, risk: risk, host: host, ip: ip, os: os,
      exploits: { metasploit: msf, malware: mal }, kev: kev, remediation: rem };
  }

  var SEV_ORDER = ['Critical', 'Severe', 'Moderate'];
  var SEV_TONE = { Critical: 'crit', Severe: 'high', Moderate: 'med' };
  var SEV_VAR = { Critical: 'var(--crit)', Severe: 'var(--high)', Moderate: 'var(--med)' };
  var ASSETS_SCANNED = 393;

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]; }); }
  function by(arr, key) { var m = {}; arr.forEach(function (x) { var k = key(x); m[k] = (m[k] || 0) + 1; }); return m; }

  function kpis() {
    var crit = VULN.filter(function (v) { return v.sev === 'Critical'; }).length;
    var avg = Math.round(VULN.reduce(function (a, v) { return a + v.risk; }, 0) / VULN.length);
    var msf = VULN.filter(function (v) { return v.exploits.metasploit; }).length;
    var mal = VULN.filter(function (v) { return v.exploits.malware; }).length;
    var assetsAffected = Object.keys(by(VULN, function (v) { return v.host; })).length;
    return { total: VULN.length, crit: crit, avg: avg, msf: msf, mal: mal, assets: assetsAffected };
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
    var m = by(VULN, function (v) { return v.sev; });
    var max = Math.max.apply(null, SEV_ORDER.map(function (s) { return m[s] || 0; }));
    var rows = SEV_ORDER.map(function (s) { return barRow(s, m[s] || 0, max, SEV_VAR[s]); }).join('');
    return card('Vulnerabilities by severity', rows, 'InsightVM buckets findings as Critical / Severe / Moderate.');
  }
  function exposureBlock() {
    var msf = VULN.filter(function (v) { return v.exploits.metasploit; }).length;
    var mal = VULN.filter(function (v) { return v.exploits.malware; }).length;
    var kev = VULN.filter(function (v) { return v.kev; }).length;
    var none = VULN.filter(function (v) { return !v.exploits.metasploit && !v.exploits.malware; }).length;
    var rows = [
      barRow('Metasploit module', msf, VULN.length, 'var(--crit)'),
      barRow('Malware kit', mal, VULN.length, 'var(--crit)'),
      barRow('In CISA KEV', kev, VULN.length, 'var(--high)'),
      barRow('No known exploit', none, VULN.length, 'var(--low)')
    ].join('');
    return card('Threat exposure', rows, 'Real Risk Score is amplified by active exploitability — Metasploit modules and malware kits are the heaviest multipliers.');
  }
  function riskBlock() {
    var bands = [
      { l: 'Critical (900–1000)', lo: 900, hi: 1001, c: 'var(--crit)' },
      { l: 'High (750–899)', lo: 750, hi: 900, c: 'var(--high)' },
      { l: 'Medium (500–749)', lo: 500, hi: 750, c: 'var(--med)' },
      { l: 'Low (0–499)', lo: 0, hi: 500, c: 'var(--low)' }
    ];
    var max = Math.max.apply(null, bands.map(function (b) { return VULN.filter(function (v) { return v.risk >= b.lo && v.risk < b.hi; }).length; }));
    var rows = bands.map(function (b) {
      var n = VULN.filter(function (v) { return v.risk >= b.lo && v.risk < b.hi; }).length;
      return barRow(b.l, n, max, b.c);
    }).join('');
    return card('Real Risk Score distribution', rows, 'Rapid7’s Real Risk Score (0–1000) weights CVSS by exploit exposure, malware, and vulnerability age.');
  }
  function remediationBlock() {
    // Group by the remediation action — InsightVM's "top remediations" rollup:
    // one fix that resolves the most risk across the most assets.
    var m = {};
    VULN.forEach(function (v) {
      var key = v.remediation;
      if (!m[key]) m[key] = { rem: key, vulns: 0, risk: 0, assets: {} };
      m[key].vulns++; m[key].risk += v.risk; m[key].assets[v.host] = 1;
    });
    var list = Object.keys(m).map(function (k) { return m[k]; })
      .sort(function (a, b) { return b.risk - a.risk; }).slice(0, 6);
    var rows = list.map(function (x) {
      var assets = Object.keys(x.assets).length;
      return '<div class="sc-rem"><div class="sc-rem-head"><span class="sc-rem-title">' + esc(x.rem) + '</span>'
        + '<span class="sc-rem-metric">' + x.risk.toLocaleString() + ' risk removed</span></div>'
        + '<div class="sc-rem-sub">Resolves <b>' + x.vulns + '</b> finding' + (x.vulns > 1 ? 's' : '') + ' across <b>' + assets + '</b> asset' + (assets > 1 ? 's' : '') + '</div></div>';
    }).join('');
    return card('Top remediations by risk removed', rows, 'InsightVM ranks fixes by total Real Risk eliminated per action, so one patch can clear the most exposure first.');
  }
  function topBlock() {
    var sorted = VULN.slice().sort(function (a, b) { return b.risk - a.risk; }).slice(0, 10);
    var rows = sorted.map(function (v) {
      var tags = (v.kev ? '<span class="sc-tag kev">KEV</span>' : '')
        + (v.exploits.metasploit ? '<span class="sc-tag exp">Metasploit</span>' : '')
        + (v.exploits.malware ? '<span class="sc-tag mal">Malware</span>' : '');
      return '<tr><td><span class="sc-sev ' + SEV_TONE[v.sev] + '">' + v.sev.charAt(0) + '</span></td>'
        + '<td class="mono">' + esc(v.cve) + '</td>'
        + '<td>' + esc(v.title) + '</td>'
        + '<td class="sc-risk" style="color:' + (v.risk >= 900 ? 'var(--crit)' : v.risk >= 750 ? 'var(--high)' : v.risk >= 500 ? 'var(--med)' : 'var(--low)') + '">' + v.risk + '</td>'
        + '<td class="mono">' + v.cvss.toFixed(1) + '</td>'
        + '<td>' + esc(v.host) + '<div class="sc-sub mono">' + esc(v.ip) + '</div></td>'
        + '<td>' + tags + '</td></tr>';
    }).join('');
    return card('Top vulnerabilities by Real Risk',
      '<table class="sc-table"><thead><tr><th>Sev</th><th>CVE</th><th>Title</th><th>Real Risk</th><th>CVSS</th><th>Asset</th><th>Exposure</th></tr></thead><tbody>' + rows + '</tbody></table>');
  }

  function render() {
    if (!app) return;
    app.className = '';
    var k = kpis();
    var html = '<div class="scapp">'
      + '<div class="schead"><div class="overline">Rapid7</div>'
      + '<h1>InsightVM risk posture</h1>'
      + '<p class="lede">Vulnerabilities ranked by Rapid7 Real Risk Score with exploit and malware exposure and remediation rollups, cross-referenced with your Tenable, Wiz, and KEV data in one place.</p></div>'
      + '<div class="sctools"><span class="sc-sample">Sample data — API-shaped preview</span>'
      + '<span class="priv">🔒 100% local — nothing leaves this browser</span></div>'
      + '<div class="sc-kpis">'
      + kpiCard('Vulnerabilities', k.total, 'across assets', '')
      + kpiCard('Critical', k.crit, 'InsightVM severity', 'crit')
      + kpiCard('Malware exposed', k.mal, 'active malware kit', 'crit')
      + kpiCard('Avg Real Risk', k.avg, 'of 1000', 'high')
      + kpiCard('Metasploit', k.msf, 'weaponized module', 'high')
      + kpiCard('Assets affected', k.assets, 'authenticated scan', '')
      + '</div>'
      + '<div class="sc-grid2">' + sevBlock() + exposureBlock() + '</div>'
      + '<div class="sc-grid2">' + riskBlock() + remediationBlock() + '</div>'
      + topBlock()
      + '<div class="sc-foot">Synthetic data modeled on the Rapid7 InsightVM API (Real Risk Score, Critical/Severe/Moderate severity, exploit + malware exposure, remediation rollups). When a Rapid7 connector is added, this dashboard reads the live console with no layout changes. See the roadmap for the connector.</div>'
      + '</div>';
    app.innerHTML = html;
  }

  window.RAPID7 = { open: render, data: { vulns: VULN } };
})();
