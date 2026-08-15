/* Wiz CNAPP Dashboard — native VM Ops page. Renders into #app on #/wiz.
   The data here is SYNTHETIC but shaped like the Wiz GraphQL API responses
   (VulnerabilityFinding, Issue/attack-path, and Graph resource entities), so
   when a Wiz connector is eventually added the same dashboard code can read a
   live feed with no rework. Nothing here calls out to the network. */
(function () {
  var app = document.getElementById('app');

  // ---- Synthetic data, shaped like the Wiz API ------------------------------
  // Vulnerability findings: mirrors Wiz `vulnerabilityFindings` GraphQL nodes.
  var FINDINGS = [
    mk('CVE-2021-44228', 'Log4Shell', 'CRITICAL', 10.0, true, true, 'log4j-core 2.14.1', 'prod-api-7f2', 'VIRTUAL_MACHINE', 'AWS', 'us-east-1', 'prod-payments'),
    mk('CVE-2023-4911', 'Looney Tunables (glibc)', 'HIGH', 7.8, true, false, 'glibc 2.34', 'prod-api-7f2', 'VIRTUAL_MACHINE', 'AWS', 'us-east-1', 'prod-payments'),
    mk('CVE-2022-42475', 'FortiOS SSL-VPN', 'CRITICAL', 9.8, true, true, 'fortios 7.2.2', 'edge-fw-01', 'VIRTUAL_MACHINE', 'AWS', 'us-east-1', 'prod-payments'),
    mk('CVE-2021-26855', 'Exchange ProxyLogon', 'CRITICAL', 9.1, true, true, 'exchange 2019 cu8', 'corp-exch-02', 'VIRTUAL_MACHINE', 'AZURE', 'eastus', 'corp-it'),
    mk('CVE-2023-34362', 'MOVEit Transfer SQLi', 'CRITICAL', 9.8, true, true, 'moveit 15.0', 'sftp-gw-01', 'VIRTUAL_MACHINE', 'AZURE', 'eastus', 'corp-it'),
    mk('CVE-2024-3094', 'XZ Utils backdoor', 'CRITICAL', 10.0, false, false, 'xz 5.6.1', 'build-runner-3', 'CONTAINER_IMAGE', 'GCP', 'us-central1', 'platform-ci'),
    mk('CVE-2023-44487', 'HTTP/2 Rapid Reset', 'HIGH', 7.5, true, false, 'nginx 1.25.2', 'ingress-nginx', 'CONTAINER_IMAGE', 'GCP', 'us-central1', 'platform-ci'),
    mk('CVE-2023-38545', 'curl SOCKS5 overflow', 'HIGH', 8.8, false, false, 'curl 8.3.0', 'ingress-nginx', 'CONTAINER_IMAGE', 'GCP', 'us-central1', 'platform-ci'),
    mk('CVE-2022-1471', 'SnakeYAML RCE', 'HIGH', 8.3, false, false, 'snakeyaml 1.30', 'orders-svc', 'CONTAINER_IMAGE', 'AWS', 'us-east-1', 'prod-payments'),
    mk('CVE-2023-2650', 'OpenSSL OBJ DoS', 'MEDIUM', 6.5, false, false, 'openssl 3.0.8', 'orders-svc', 'CONTAINER_IMAGE', 'AWS', 'us-east-1', 'prod-payments'),
    mk('CVE-2020-1472', 'Zerologon', 'CRITICAL', 10.0, true, true, 'netlogon', 'corp-dc-01', 'VIRTUAL_MACHINE', 'AZURE', 'eastus', 'corp-it'),
    mk('CVE-2019-19781', 'Citrix ADC path traversal', 'CRITICAL', 9.8, true, true, 'netscaler 13.0', 'vpn-adc-01', 'VIRTUAL_MACHINE', 'AZURE', 'westus2', 'corp-it'),
    mk('CVE-2023-0464', 'OpenSSL policy DoS', 'MEDIUM', 5.9, false, false, 'openssl 3.1.0', 'analytics-fn', 'SERVERLESS', 'GCP', 'us-central1', 'data-eng'),
    mk('CVE-2021-3711', 'OpenSSL SM2 overflow', 'HIGH', 9.8, false, false, 'openssl 1.1.1k', 'legacy-etl', 'VIRTUAL_MACHINE', 'AWS', 'us-west-2', 'data-eng'),
    mk('CVE-2016-2183', 'SWEET32 (3DES)', 'LOW', 3.7, false, false, 'openssl 1.0.2', 'legacy-etl', 'VIRTUAL_MACHINE', 'AWS', 'us-west-2', 'data-eng')
  ];
  function mk(cve, name, sev, score, exploit, kev, pkg, asset, atype, cloud, region, sub) {
    return {
      id: 'vf-' + cve, name: cve, detailedName: name, CVSSSeverity: sev, score: score,
      hasExploit: exploit, hasCisaKevExploit: kev, detectionMethod: 'PACKAGE',
      vulnerableAsset: { name: asset, type: atype, cloudPlatform: cloud, region: region, subscriptionExternalId: sub },
      remediation: pkg, firstDetectedAt: '2026-08-1' + (cve.length % 5)
    };
  }

  // Issues / attack paths: mirrors Wiz `issues` — toxic combinations that chain
  // exposure + vulnerability + identity into a real attack path.
  var PATHS = [
    { id: 'iss-1', severity: 'CRITICAL', status: 'OPEN', rule: 'Public VM with critical vuln and high-privilege role',
      entity: 'prod-api-7f2', cloud: 'AWS',
      chain: ['Internet-exposed (0.0.0.0/0 :443)', 'Critical vuln CVE-2021-44228', 'Instance role AdministratorAccess', 'Reaches RDS prod-payments-db'] },
    { id: 'iss-2', severity: 'CRITICAL', status: 'OPEN', rule: 'Public VM with KEV exploit reachable from internet',
      entity: 'edge-fw-01', cloud: 'AWS',
      chain: ['Internet-exposed (0.0.0.0/0 :443)', 'KEV CVE-2022-42475', 'Lateral path to prod subnet'] },
    { id: 'iss-3', severity: 'CRITICAL', status: 'OPEN', rule: 'Domain controller exposed with Zerologon',
      entity: 'corp-dc-01', cloud: 'AZURE',
      chain: ['Reachable from corp VPN', 'KEV CVE-2020-1472 (Zerologon)', 'Domain Admin takeover'] },
    { id: 'iss-4', severity: 'HIGH', status: 'OPEN', rule: 'Public container with vuln and secret in env',
      entity: 'ingress-nginx', cloud: 'GCP',
      chain: ['Internet-exposed LoadBalancer', 'High vuln CVE-2023-44487', 'GCP SA key mounted', 'Reaches BigQuery data-eng'] },
    { id: 'iss-5', severity: 'HIGH', status: 'IN_PROGRESS', rule: 'Public bucket readable by all authenticated users',
      entity: 'prod-payments-backups', cloud: 'AWS',
      chain: ['S3 ACL AuthenticatedUsers READ', 'Contains PII / card data', 'No default encryption'] },
    { id: 'iss-6', severity: 'MEDIUM', status: 'OPEN', rule: 'Serverless function with over-broad IAM',
      entity: 'analytics-fn', cloud: 'GCP',
      chain: ['Cloud Function public invoker', 'roles/editor on project', 'Reaches Cloud SQL analytics'] }
  ];

  // Cloud resource inventory: mirrors Wiz Graph entity counts by type.
  var INVENTORY = [
    { type: 'Virtual machines', count: 342, scanned: 342 },
    { type: 'Container images', count: 1180, scanned: 1094 },
    { type: 'Serverless functions', count: 96, scanned: 96 },
    { type: 'Storage buckets', count: 210, scanned: 210 },
    { type: 'Managed databases', count: 58, scanned: 58 },
    { type: 'Kubernetes clusters', count: 12, scanned: 12 }
  ];

  var SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  // Use the app's shared design tokens so this dashboard matches the others.
  var SEV_COLOR = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)' };
  var CLOUD_COLOR = { AWS: 'var(--high)', AZURE: 'var(--accent)', GCP: 'var(--ok)' };

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]; }); }
  function by(arr, key) { var m = {}; arr.forEach(function (x) { var k = key(x); m[k] = (m[k] || 0) + 1; }); return m; }

  function kpis() {
    var crit = FINDINGS.filter(function (f) { return f.CVSSSeverity === 'CRITICAL'; }).length;
    var kev = FINDINGS.filter(function (f) { return f.hasCisaKevExploit; }).length;
    var exploitable = FINDINGS.filter(function (f) { return f.hasExploit; }).length;
    var openPaths = PATHS.filter(function (p) { return p.status !== 'RESOLVED'; }).length;
    var resources = INVENTORY.reduce(function (a, r) { return a + r.count; }, 0);
    return { total: FINDINGS.length, crit: crit, kev: kev, exploitable: exploitable, paths: openPaths, resources: resources };
  }

  function kpiCard(label, val, sub, tone) {
    return '<div class="wiz-kpi' + (tone ? ' ' + tone : '') + '"><div class="wiz-kpi-v">' + val + '</div><div class="wiz-kpi-l">' + esc(label) + '</div>' + (sub ? '<div class="wiz-kpi-s">' + esc(sub) + '</div>' : '') + '</div>';
  }

  function barRow(label, count, max, color, isHtml) {
    var pct = max ? Math.round(count / max * 100) : 0;
    return '<div class="wiz-bar"><span class="wiz-bar-l">' + (isHtml ? label : esc(label)) + '</span>'
      + '<span class="wiz-bar-track"><span class="wiz-bar-fill" style="width:' + pct + '%;background:' + color + '"></span></span>'
      + '<span class="wiz-bar-n">' + count + '</span></div>';
  }

  function sevBlock() {
    var m = by(FINDINGS, function (f) { return f.CVSSSeverity; });
    var max = Math.max.apply(null, SEV_ORDER.map(function (s) { return m[s] || 0; }));
    var rows = SEV_ORDER.map(function (s) { return barRow(s.charAt(0) + s.slice(1).toLowerCase(), m[s] || 0, max, SEV_COLOR[s]); }).join('');
    return card('Findings by severity', rows);
  }

  function cloudBlock() {
    var m = by(FINDINGS, function (f) { return f.vulnerableAsset.cloudPlatform; });
    var order = ['AWS', 'AZURE', 'GCP'];
    var max = Math.max.apply(null, order.map(function (c) { return m[c] || 0; }));
    var rows = order.map(function (c) { return barRow(c, m[c] || 0, max, CLOUD_COLOR[c]); }).join('');
    return card('Findings by cloud provider', rows);
  }

  function inventoryBlock() {
    var max = Math.max.apply(null, INVENTORY.map(function (r) { return r.count; }));
    var rows = INVENTORY.map(function (r) {
      var gap = r.count - r.scanned;
      var lbl = esc(r.type) + (gap ? ' <span class="wiz-gap" title="' + gap + ' not yet scanned">' + gap + ' unscanned</span>' : '');
      return barRow(lbl, r.count, max, 'var(--accent)', true);
    }).join('');
    return card('Cloud resource inventory', rows + '<div class="wiz-note">Coverage is agentless (snapshot-based). Unscanned = newly created resources awaiting the next graph sync.</div>');
  }

  function pathsBlock() {
    var rows = PATHS.map(function (p) {
      var chips = p.chain.map(function (step, i) {
        return '<span class="wiz-step">' + esc(step) + '</span>' + (i < p.chain.length - 1 ? '<span class="wiz-arrow">&rarr;</span>' : '');
      }).join('');
      return '<div class="wiz-path wiz-' + p.severity.toLowerCase() + '">'
        + '<div class="wiz-path-head"><span class="wiz-sev wiz-' + p.severity.toLowerCase() + '">' + p.severity + '</span>'
        + '<span class="wiz-path-rule">' + esc(p.rule) + '</span>'
        + '<span class="wiz-cloud" style="color:' + CLOUD_COLOR[p.cloud] + '">' + esc(p.cloud) + '</span>'
        + '<span class="wiz-path-status">' + esc(p.status.replace('_', ' ')) + '</span></div>'
        + '<div class="wiz-path-entity">' + esc(p.entity) + '</div>'
        + '<div class="wiz-chain">' + chips + '</div></div>';
    }).join('');
    return card('Toxic-combination attack paths', rows, 'Wiz’s signature view: not just a vuln, but a vuln that is reachable and impactful. These chain internet exposure, a critical vulnerability, and identity into a real path an attacker could take.');
  }

  function topFindingsBlock() {
    var sorted = FINDINGS.slice().sort(function (a, b) {
      var s = SEV_ORDER.indexOf(a.CVSSSeverity) - SEV_ORDER.indexOf(b.CVSSSeverity);
      return s !== 0 ? s : b.score - a.score;
    }).slice(0, 10);
    var rows = sorted.map(function (f) {
      var a = f.vulnerableAsset;
      return '<tr><td><span class="wiz-sev wiz-' + f.CVSSSeverity.toLowerCase() + '">' + f.CVSSSeverity.charAt(0) + '</span></td>'
        + '<td class="mono">' + esc(f.name) + '</td>'
        + '<td>' + esc(f.detailedName) + '</td>'
        + '<td class="mono">' + f.score.toFixed(1) + '</td>'
        + '<td>' + esc(a.name) + ' <span class="wiz-atype">' + esc(a.type.replace(/_/g, ' ').toLowerCase()) + '</span></td>'
        + '<td style="color:' + CLOUD_COLOR[a.cloudPlatform] + '">' + esc(a.cloudPlatform) + ' / ' + esc(a.region) + '</td>'
        + '<td>' + (f.hasCisaKevExploit ? '<span class="wiz-tag kev">KEV</span>' : f.hasExploit ? '<span class="wiz-tag exp">Exploit</span>' : '') + '</td></tr>';
    }).join('');
    return card('Top vulnerable cloud resources',
      '<table class="wiz-table"><thead><tr><th></th><th>CVE</th><th>Name</th><th>CVSS</th><th>Resource</th><th>Cloud / region</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>');
  }

  function card(title, body, note) {
    return '<section class="wiz-card"><h3>' + esc(title) + '</h3>' + (note ? '<div class="wiz-cardnote">' + note + '</div>' : '') + body + '</section>';
  }

  function render() {
    if (!app) return;
    app.className = '';
    var k = kpis();
    var html = '<div class="wizapp">'
      + '<div class="wizhead"><div class="overline">Wiz</div>'
      + '<h1>Cloud security posture (CNAPP)</h1>'
      + '<p class="lede">Cloud vulnerabilities, toxic-combination attack paths, and resource inventory across AWS, Azure, and GCP, cross-referenced with your Tenable and KEV data in one place.</p></div>'
      + '<div class="wiztools"><span class="wiz-sample">Sample data — API-shaped preview</span>'
      + '<span class="priv">🔒 100% local — nothing leaves this browser</span></div>'
      + '<div class="wiz-kpis">'
      + kpiCard('Vulnerability findings', k.total, 'across cloud workloads', '')
      + kpiCard('Critical', k.crit, 'CVSS ≥ 9.0', 'crit')
      + kpiCard('Attack paths', k.paths, 'toxic combinations', 'crit')
      + kpiCard('KEV exploited', k.kev, 'in CISA catalog', 'high')
      + kpiCard('Exploit available', k.exploitable, 'public PoC or weaponized', 'high')
      + kpiCard('Resources scanned', k.resources.toLocaleString(), 'agentless snapshot', '')
      + '</div>'
      + '<div class="wiz-grid2">' + sevBlock() + cloudBlock() + '</div>'
      + pathsBlock()
      + '<div class="wiz-grid2">' + inventoryBlock() + topFindingsBlock() + '</div>'
      + '<div class="wiz-foot">Synthetic data modeled on the Wiz GraphQL API (VulnerabilityFinding, Issue, and Graph entity shapes). When a Wiz connector is added, this dashboard reads the live tenant with no layout changes. See the roadmap for the connector.</div>'
      + '</div>';
    app.innerHTML = html;
  }

  window.WIZ = { open: render, data: { findings: FINDINGS, paths: PATHS, inventory: INVENTORY } };
})();
