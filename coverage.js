/* Scanner Coverage — cross-vendor view, route #/coverage. Reads the unified
   VMSCAN rollup and shows, per CVE, which of the five tools detected it, where
   the overlap is, and where the blind spots are. Read-only; no network. */
(function () {
  var app = document.getElementById('app');
  var HOST_SCANNERS = ['Tenable', 'Qualys', 'Rapid7'];
  var SEV_VAR = { Critical: 'var(--crit)', High: 'var(--high)', Medium: 'var(--med)', Low: 'var(--low)' };
  var SEV_TONE = { Critical: 'crit', High: 'high', Medium: 'med', Low: 'low' };

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]; }); }
  function kpiCard(label, val, sub, tone) {
    return '<div class="sc-kpi' + (tone ? ' ' + tone : '') + '"><div class="sc-kpi-v">' + val + '</div><div class="sc-kpi-l">' + esc(label) + '</div>' + (sub ? '<div class="sc-kpi-s">' + esc(sub) + '</div>' : '') + '</div>';
  }
  function barRow(label, count, max, color) {
    var pct = max ? Math.round(count / max * 100) : 0;
    return '<div class="sc-bar"><span class="sc-bar-l">' + esc(label) + '</span>'
      + '<span class="sc-bar-track"><span class="sc-bar-fill" style="width:' + pct + '%;background:' + color + '"></span></span>'
      + '<span class="sc-bar-n">' + count + '</span></div>';
  }
  function card(title, body, note) {
    return '<section class="sc-card"><h3>' + esc(title) + '</h3>' + (note ? '<div class="sc-cardnote">' + note + '</div>' : '') + body + '</section>';
  }

  function render() {
    if (!app) return;
    app.className = '';
    if (!window.VMSCAN) { app.innerHTML = '<div class="scapp"><p class="lede">Coverage module unavailable.</p></div>'; return; }

    var present = VMSCAN.present();              // vendors with data loaded
    var rollup = VMSCAN.byCve().sort(function (a, b) {
      var s = (VMSCAN.SEV_RANK[b.severity] || 0) - (VMSCAN.SEV_RANK[a.severity] || 0);
      if (s !== 0) return s;
      return b.count - a.count;
    });
    var nV = present.length;

    if (!rollup.length) {
      app.innerHTML = '<div class="scapp"><div class="schead"><div class="overline">Coverage</div><h1>Scanner coverage</h1>'
        + '<p class="lede">No scanner data is loaded yet. Open the Tenable, Qualys, Rapid7, CrowdStrike, or Wiz dashboards, or load the sample findings, then return here.</p></div></div>';
      return;
    }

    // KPIs
    var uniqueCves = rollup.length;
    var full = rollup.filter(function (r) { return r.count === nV; }).length;
    var single = rollup.filter(function (r) { return r.count === 1; }).length;
    var avg = (rollup.reduce(function (a, r) { return a + r.count; }, 0) / uniqueCves).toFixed(1);
    // Host-scanner blind spots: CVEs no host scanner (Tenable/Qualys/Rapid7) caught,
    // but an agent/cloud tool (CrowdStrike/Wiz) did.
    var blind = rollup.filter(function (r) {
      var hasHost = r.vendors.some(function (v) { return HOST_SCANNERS.indexOf(v) > -1; });
      var hasOther = r.vendors.some(function (v) { return HOST_SCANNERS.indexOf(v) < 0; });
      return !hasHost && hasOther;
    });

    // Per-vendor totals
    var vTotals = {};
    present.forEach(function (v) { vTotals[v] = 0; });
    rollup.forEach(function (r) { r.vendors.forEach(function (v) { vTotals[v] = (vTotals[v] || 0) + 1; }); });
    var vMax = Math.max.apply(null, present.map(function (v) { return vTotals[v]; }));
    var vendorBars = present.map(function (v) { return barRow(v, vTotals[v], vMax, 'var(--accent)'); }).join('');

    // Overlap distribution: how many CVEs were seen by exactly k tools
    var dist = {};
    for (var i = 1; i <= nV; i++) dist[i] = 0;
    rollup.forEach(function (r) { dist[r.count] = (dist[r.count] || 0) + 1; });
    var dMax = Math.max.apply(null, Object.keys(dist).map(function (k) { return dist[k]; }));
    var distBars = [];
    for (var k = nV; k >= 1; k--) {
      var color = k === 1 ? 'var(--crit)' : k === nV ? 'var(--ok)' : 'var(--med)';
      distBars.push(barRow(k + ' tool' + (k > 1 ? 's' : '') + (k === 1 ? ' (blind-spot risk)' : k === nV ? ' (full overlap)' : ''), dist[k], dMax, color));
    }

    // Coverage matrix
    var head = '<tr><th>Sev</th><th>CVE</th>' + present.map(function (v) { return '<th class="cov-vh">' + esc(v) + '</th>'; }).join('') + '<th>Tools</th><th>Assets</th></tr>';
    var body = rollup.map(function (r) {
      var cells = present.map(function (v) {
        var yes = r.vendors.indexOf(v) > -1;
        return '<td class="cov-c">' + (yes ? '<span class="cov-yes" title="' + esc(v) + ' detected">●</span>' : '<span class="cov-no">·</span>') + '</td>';
      }).join('');
      var gap = !r.vendors.some(function (v) { return HOST_SCANNERS.indexOf(v) > -1; }) && r.vendors.some(function (v) { return HOST_SCANNERS.indexOf(v) < 0; });
      return '<tr' + (gap ? ' class="cov-gaprow"' : '') + '><td><span class="sc-sev ' + SEV_TONE[r.severity] + '">' + r.severity.charAt(0) + '</span></td>'
        + '<td class="mono">' + esc(r.cve) + (gap ? ' <span class="sc-tag exp" title="No host scanner detected this">host-scanner gap</span>' : '') + '</td>'
        + cells
        + '<td class="sc-risk" style="color:' + (r.count === 1 ? 'var(--crit)' : r.count === nV ? 'var(--ok)' : 'var(--soft)') + '">' + r.count + '/' + nV + '</td>'
        + '<td>' + r.hosts.length + '</td></tr>';
    }).join('');
    var matrix = '<div style="overflow-x:auto"><table class="sc-table cov-matrix"><thead>' + head + '</thead><tbody>' + body + '</tbody></table></div>';

    // Blind-spot detail
    var blindBody;
    if (blind.length) {
      blindBody = blind.map(function (r) {
        return '<div class="sc-rem"><div class="sc-rem-head"><span class="sc-sev ' + SEV_TONE[r.severity] + '">' + r.severity.charAt(0) + '</span>'
          + '<span class="sc-rem-title mono">' + esc(r.cve) + '</span>'
          + '<span class="sc-rem-metric">caught by ' + r.vendors.join(', ') + '</span></div>'
          + '<div class="sc-rem-sub">Missed by every host scanner (' + HOST_SCANNERS.join(' / ') + ') on ' + r.hosts.length + ' asset' + (r.hosts.length === 1 ? '' : 's') + '</div></div>';
      }).join('');
    } else {
      blindBody = '<div class="sc-note">No host-scanner blind spots in the current data: every CVE an agent or cloud tool found was also seen by at least one network scanner.</div>';
    }

    var missing = VMSCAN.VENDORS.filter(function (v) { return present.indexOf(v) < 0; });

    var html = '<div class="scapp">'
      + '<div class="schead"><div class="overline">Coverage</div>'
      + '<h1>Scanner coverage</h1>'
      + '<p class="lede">Every CVE across Tenable, Qualys, Rapid7, CrowdStrike, and Wiz, reconciled into one view: which tools agree, which CVEs only one tool caught, and where your network scanners have blind spots that only an agent or cloud tool covers.</p></div>'
      + '<div class="sctools"><span class="sc-sample">Reconciled from loaded scanner data</span>'
      + '<span class="priv">🔒 100% local — nothing leaves this browser</span></div>'
      + '<div class="sc-kpis">'
      + kpiCard('Unique CVEs', uniqueCves, 'across ' + nV + ' tool' + (nV > 1 ? 's' : ''), '')
      + kpiCard('Full overlap', full, 'seen by all ' + nV, '')
      + kpiCard('Single-tool', single, 'only one tool caught', 'crit')
      + kpiCard('Host-scanner gaps', blind.length, 'agent/cloud only', 'crit')
      + kpiCard('Avg tools / CVE', avg, 'detection agreement', 'high')
      + kpiCard('Tools reporting', nV, missing.length ? 'missing: ' + missing.join(', ') : 'all connected', '')
      + '</div>'
      + '<div class="sc-grid2">' + card('CVEs found per tool', vendorBars, 'How many distinct CVEs each tool reported. Gaps between tools are coverage differences, not noise.')
      + card('Detection overlap', distBars.join(''), 'How many tools independently flagged each CVE. Single-tool CVEs carry the most uncertainty; full-overlap CVEs are the most corroborated.') + '</div>'
      + card('Host-scanner blind spots', blindBody, 'CVEs that no network scanner (' + HOST_SCANNERS.join(' / ') + ') detected but an agent (CrowdStrike) or cloud (Wiz) tool did — the exposures a scan-only program would miss.')
      + card('Coverage matrix', matrix, 'One row per CVE; a dot means that tool detected it. Rows flagged “host-scanner gap” were caught only by an agent or cloud tool.')
      + '<div class="sc-foot">Reconciled live from whichever scanner dashboards have data loaded (all use sample data until a connector is added). Dedup is by CVE; the Assets column counts distinct hosts across tools. Load the multi-scanner sample on the Data Import page to also see these in the Findings workbench.</div>'
      + '</div>';
    app.innerHTML = html;
  }

  window.COVERAGE = { open: render };
})();
