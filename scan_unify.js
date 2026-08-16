/* Cross-vendor unifier. Normalizes findings from all five scanner sources
   (Tenable baseline via VMOPS + Wiz/Qualys/Rapid7/CrowdStrike modules) into one
   shape, and rolls them up by CVE so the Scanner Coverage view and the opt-in
   workbench loader can share one source of truth. Read-only; no network. */
(function () {
  var VENDORS = ['Tenable', 'Qualys', 'Rapid7', 'CrowdStrike', 'Wiz'];
  var SEV_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 };

  function titleSev(s) {
    s = String(s || '').toLowerCase();
    if (s.indexOf('crit') === 0) return 'Critical';
    if (s.indexOf('high') === 0 || s === 'severe') return 'High';
    if (s.indexOf('med') === 0 || s === 'moderate') return 'Medium';
    if (s.indexOf('low') === 0 || s.indexOf('info') === 0) return 'Low';
    return 'Low';
  }
  function qualysSev(n) { return n >= 5 ? 'Critical' : n === 4 ? 'High' : n === 3 ? 'Medium' : 'Low'; }
  function shortHost(h) { return String(h || '').trim().split('.')[0].toLowerCase(); }

  // Each vendor -> array of {cve, host, vendor, severity, cvss}
  function fromTenable() {
    var out = [];
    try {
      var fs = (window.VMOPS && window.VMOPS.getFindings) ? window.VMOPS.getFindings() : [];
      fs.forEach(function (f) {
        // Only rows whose source is the Tenable baseline (skip any scanner rows
        // already loaded into the store, so they are not double-counted here).
        var src = (f.source || 'Tenable');
        if (src !== 'Tenable') return;
        out.push({ cve: String(f.cve || '').toUpperCase(), host: f.host || '', vendor: 'Tenable', severity: titleSev(f.severity), cvss: f.cvss == null ? null : +f.cvss });
      });
    } catch (e) { }
    return out;
  }
  function fromWiz() {
    if (!window.WIZ) return [];
    return (window.WIZ.data.findings || []).map(function (f) {
      return { cve: String(f.name).toUpperCase(), host: f.vulnerableAsset.name, vendor: 'Wiz', severity: titleSev(f.CVSSSeverity), cvss: f.score };
    });
  }
  function fromQualys() {
    if (!window.QUALYS) return [];
    // Exclude remediated detections (Qualys marks them Fixed), mirroring the CrowdStrike 'closed' filter.
    return (window.QUALYS.data.detections || []).filter(function (d) { return d.status !== 'Fixed'; }).map(function (d) {
      return { cve: String(d.cve).toUpperCase(), host: d.host, vendor: 'Qualys', severity: qualysSev(d.sev), cvss: d.cvss };
    });
  }
  function fromRapid7() {
    if (!window.RAPID7) return [];
    return (window.RAPID7.data.vulns || []).map(function (v) {
      return { cve: String(v.cve).toUpperCase(), host: v.host, vendor: 'Rapid7', severity: titleSev(v.sev), cvss: v.cvss };
    });
  }
  function fromCrowdstrike() {
    if (!window.CROWDSTRIKE) return [];
    return (window.CROWDSTRIKE.data.vulns || []).filter(function (v) { return v.status !== 'closed'; }).map(function (v) {
      return { cve: String(v.cve).toUpperCase(), host: v.host, vendor: 'CrowdStrike', severity: titleSev(v.exprt), cvss: v.base };
    });
  }

  // All normalized rows across every available vendor.
  function rows() {
    return [].concat(fromTenable(), fromQualys(), fromRapid7(), fromCrowdstrike(), fromWiz());
  }

  // Which vendors actually have data loaded right now.
  function present() {
    var r = rows(), set = {};
    r.forEach(function (x) { set[x.vendor] = 1; });
    return VENDORS.filter(function (v) { return set[v]; });
  }

  // Roll up by CVE: which vendors flagged it, on which hosts, worst severity.
  function byCve() {
    var m = {};
    rows().forEach(function (x) {
      var k = x.cve;
      if (!m[k]) m[k] = { cve: k, vendors: {}, hosts: {}, severity: 'Low', cvss: null };
      m[k].vendors[x.vendor] = 1;
      if (x.host) m[k].hosts[shortHost(x.host)] = 1;
      if (SEV_RANK[x.severity] > SEV_RANK[m[k].severity]) m[k].severity = x.severity;
      if (x.cvss != null && (m[k].cvss == null || x.cvss > m[k].cvss)) m[k].cvss = x.cvss;
    });
    return Object.keys(m).map(function (k) {
      var e = m[k];
      return { cve: e.cve, vendors: Object.keys(e.vendors), hosts: Object.keys(e.hosts), severity: e.severity, cvss: e.cvss, count: Object.keys(e.vendors).length };
    });
  }

  // Normalized Finding rows for the OPT-IN workbench loader: the non-Tenable
  // vendors, shaped like the console's Finding model (so mergeFindings dedups by
  // cve+host and the workbench/Overview/Campaigns pick them up).
  function scannerFindings() {
    var today = new Date().toISOString().slice(0, 10);   // real date so SLA/age/risk compute correctly
    function toFinding(x) {
      return { cve: x.cve, host: x.host, severity: x.severity, cvss: x.cvss == null ? null : x.cvss, vpr: null,
        plugin: '', name: x.cve + ' (' + x.vendor + ')', desc: x.cve + ' detected by ' + x.vendor,
        repo: '', source: x.vendor, firstSeen: today, state: '' };
    }
    return [].concat(fromQualys(), fromRapid7(), fromCrowdstrike(), fromWiz()).map(toFinding);
  }

  window.VMSCAN = {
    VENDORS: VENDORS, SEV_RANK: SEV_RANK,
    rows: rows, present: present, byCve: byCve, scannerFindings: scannerFindings, titleSev: titleSev
  };
})();
