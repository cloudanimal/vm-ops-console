> **Official documentation.** Maintained as features ship (definition of done). The at-a-glance HTML scorecard also lives in [feature-comparison.html](feature-comparison.html). Basis: DefectDojo OSS v3.2.201 live demo + PRO demo + current docs. Last updated 2026-08-19.

Here is the complete deliverable.

---

# DefectDojo feature-parity gap analysis — vm-ops-console

Scope: features, functionality, and settings only. DefectDojo visual design and UX styling are deliberately out of scope (we keep our own clean design). Every gap carries a short UX note describing how the capability should feel inside our own experience. Version basis: DefectDojo OSS v3.2.201 live demo plus docs corrections (parser count now "500+ docs / 330+ discrete tools"; Universal Parser and dedup-tuning are Pro; Pro entry ~$300/mo storage-tiered). vm-ops-console at app version 1.10.1.

Status legend: **Have** (shipped) · **Partial** (present but lighter) · **Browser-roadmap** (feasible fully client-side, not built) · **Needs-backend** (crosses a boundary B1–B6; one small opt-in local-first connector unlocks all six).

## PART 1 — GAP ANALYSIS

### Core object model

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Product / Asset as top object | OSS | Have | We key on Assets (hosts) not "Products"; keep our flatter host-first model, do not adopt the Product Type > Product > Engagement > Test > Finding nesting. Surface any grouping as saved views, not new object tiers. |
| Engagement (a testing effort grouping Tests, Interactive vs CI/CD, dates, lead) | OSS | Browser-roadmap | Do not clone Engagements as a hard object. If users want scan-batch grouping, express it as an import-session tag on findings, shown as a filter chip, not a modal-heavy wizard. |
| Test (a single scan run inside an engagement) | OSS | Partial | Our import already captures per-feed presence and rescan reconciliation; expose "scan runs" as a lightweight timeline on the Import view rather than a first-class navigable object. |
| Finding as core object with rich fields | OSS | Have | Our finding drawer already carries status/owner/notes/updates/risk; keep progressive disclosure so the drawer never becomes DefectDojo's wall of fields. |
| Finding Groups (group findings by component) | OSS | Partial | Our Remediations root-cause grouping already does the useful half. Add an optional "group by component/fix" toggle on the workbench header, not a separate object. |
| Finding Templates (apply saved finding text) | OSS | Browser-roadmap | Deliver as a small snippet library in Settings that the drawer can insert into notes/mitigation; keyboard-first insert, no template-management screen. |
| Transfer finding between assets | OSS | Browser-roadmap | Rare; make it a drawer action ("reassign host") with undo, not a dedicated flow. |

### Findings and triage

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Findings list with sort on every column | OSS | Have | Already have sortable/resizable grid with per-column hide and width persistence; keep it. |
| Large filter panel (severity, status, scanner, tags, CWE, date, EPSS, dup/FP/OOS/mitigated) | OSS | Have | Our facet set is broader (KEV/PoC, EPSS≥50, no-ticket, recurring, fresh, age). Keep filters inline in a collapsible rail, avoid DefectDojo's separate show-filters page reload. |
| Status model | OSS: Active, Verified, Duplicate, False Positive, Out of Scope, Risk Accepted, Mitigated, Inactive | Partial | We have 6 statuses (new, triaged, in_remediation, resolved, risk_accepted, false_positive). Missing: Verified, Out of Scope, Duplicate-as-status, Inactive. Add Verified and Out-of-Scope as optional flags in the drawer rather than new columns; keep the core lifecycle uncluttered. |
| "Verified" status + Enforce Verified (global/Jira/grading/metrics) | OSS | Browser-roadmap | Add a single "verified" boolean and one Settings toggle "require verified before counting in metrics"; do not replicate DefectDojo's four separate enforcement switches. |
| Risk acceptance as expiring object (reason, files, default days, expiry heads-up) | OSS | Partial | We store risk_accepted as an override, not deletion (good), but no expiry date or reason file. Add optional "accept until <date> + reason" in the drawer; surface expiring acceptances on the dashboard as a quiet nudge, not an alert storm. |
| False Positive history (+ retroactive auto-mark) | OSS | Browser-roadmap | Powerful and fully local: hash the FP signature, auto-suggest "matches a prior FP" as a dismissible drawer banner. Suggest, never auto-apply silently. |
| Bulk actions (edit, risk-accept, push Jira, tag, delete) | OSS | Have | Our bulk bar is richer (bulk status/owner/note/ticket/campaign/CSV, undo). Keep undo-first; never expose hard delete. |
| Per-finding notes public/private + note types | OSS | Partial | We have dated update log + notes. Add a public/private toggle and optional note-type tag; render inline in the drawer, no separate note-type admin screen (make types a free tag). |
| Similar Findings panel (near-dup surfacing) | OSS | Browser-roadmap | Show "N similar" as a drawer chip that expands inline; reuse our dedup key logic. Progressive disclosure, collapsed by default. |
| Tags everywhere | OSS | Partial | Assets have tags; extend a single tag model to findings and campaigns. One tag input component reused everywhere, keyboard-completing from existing tags. |
| Finding detail: SAST service/location/line/code snippet | OSS | Have | SARIF import already carries code-scanning context; render the snippet in the drawer with a monospace block, collapsed. |

### Import / parsers

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Parser breadth | OSS: 500+ reports / 330+ tools | Partial | We parse Tenable/Nessus CSV, SARIF 2.1.0, CycloneDX, plus AD/ME/.sc/.io/CS coverage feeds. Biggest single gap. Add SPDX and more native vendor CSV/JSON. Keep the drop-zone auto-detecting format so users never pick a parser from a 300-item dropdown. |
| API-import parsers (Blackduck/Bugcrowd/Cobalt/Edgescan/SonarQube/Vulners) | OSS (~6) | Needs-backend (B1) | Cross-origin token calls; unlocks with the connector. Until then, keep the file-import path first-class. |
| Universal Parser (no-code map arbitrary JSON/CSV/XML) | PRO | Browser-roadmap | A genuinely winnable in-browser feature: a column-mapping UI over any uploaded CSV/JSON, previewing rows live. This is a differentiator we can ship without a backend. Make it a guided 3-step inline panel, not a modal wizard. |
| Reimport / rescan reconciliation (dedup, close-old, reactivate) | OSS | Have | Our importScan/mergeFindings auto-resolves gone/Fixed, reopens re-detected with recurrence count, preserves status/owner/notes, flags new keys. Strong. |
| "Do not reactivate" control on reimport | OSS | Browser-roadmap | Reimport currently reopens re-detected findings unconditionally. Add a per-import "do not reactivate closed findings" checkbox so triage can stay source of truth. Present as one checkbox on the import confirm step. |
| close_old_findings as Mitigated (import scope only) | OSS | Partial | We auto-resolve absent findings; align terminology and make "close missing findings" an explicit opt-in toggle on import with a clear count preview before applying. |
| Sample / demo data | OSS (demo) | Have | Multi-scanner sample load already present; keep the one-click "load sample" prominent for first-run. |
| CSV / Excel / PDF / Print export toolbar (DataTables) on lists | OSS | Partial | We have 19-column CSV export (injection-guarded) plus per-panel image/clipboard. Add XLSX and print-friendly export on the workbench. Deliver as one export menu on the grid header; avoid DefectDojo's five separate toolbar buttons. |

### Dedup / reconcile

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Deduplication engine, algorithms (hash_code, unique_id_from_tool, unique_id_or_hash_code, legacy) | OSS (legacy OSS-only) | Partial | We dedup by a fixed identity key (cve|host, host normalized per source). Expose the algorithm choice conceptually as a Settings option "match on: CVE+host / tool unique id / either," defaulted, with a one-line plain-English explainer each. |
| Cross-tool dedup only via hash_code; HASH_CODE_FIELDS_ALWAYS=["service"] | OSS | Partial | Our Scanner Coverage already correlates cross-vendor by CVE+host. Document that cross-tool matching uses the CVE key, matching DefectDojo's hash_code-only cross-tool limit. |
| Deduplicate-findings scope setting (cross-engagement / cross-product) + per-parser algorithm map | OSS | Browser-roadmap | Add a Settings toggle for dedup scope with a short note; keep it one switch plus an advanced disclosure, not a per-parser table by default. |
| Dedup tuning UI (hashcode field inspection) | PRO | Browser-roadmap | We can win here client-side: a "why did these merge" inspector in the drawer showing the exact key fields. Inline, on demand, collapsed. |
| Deduplicate on import + delete duplicates + max duplicates | OSS | Have | Merge-on-import is built; keep it silent-with-undo rather than a blocking prompt. |

### Risk and prioritization

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| EPSS score + percentile columns | OSS | Have | Bundled local EPSS plus opt-in live EPSS. Keep the local-first default. |
| KEV / Known Exploited + Used in Ransomware + KEV date columns | OSS | Have | Have KEV, ransomware, PoC, LEV, EOL. Keep the exploited signals as compact badges, not extra columns by default. |
| CVSS3 / CVSS4 display toggles | OSS | Partial | We use CVSS/severity in the model. Add a Settings display toggle for CVSS3 vs CVSS4 vectors in the drawer. |
| Multi-signal composite score | OSS: EPSS+KEV feed but scoring is lighter | Have | Our CVSS+EPSS+KEV+LEV+SSVC+VPR+asset-criticality weighted model is a clear strength over OSS. Keep the transparent per-finding breakdown as the headline. |
| User-tunable weighting | PRO-ish (leaders sell it) | Have | Per-signal sliders in Settings already ship; keep the live "recompute preview" feel. |
| Reachability / exploit maturity context | PRO (My Work columns) | Browser-roadmap | Possible with imported topology/exploit-maturity fields; render as an optional context row in the drawer when data is present, hidden when absent. |
| Vulnerability Explorer — findings grouped by CVE (blast radius: assets/engagements impacted, first/last seen) | PRO | Partial | We have a CVE Explorer and Remediations grouping; add an explicit "by CVE" rollup showing assets impacted and total/active counts. Reuse the existing grid, one toggle "group by CVE." |

### Assets and grading

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Asset inventory | OSS | Have | Host register rolls up open count, max sev, summed risk, sources. Keep. |
| Business criticality on asset | OSS (A–F) / PRO (revenue, user records, internet-accessible, external audience) | Have (tiers) | We have Critical/High/Medium/Low tiers feeding risk. Add optional business-context fields (internet-facing, data-sensitivity) as they materially change risk; keep them optional inline fields, not a required form. |
| Product Grading A–F (thresholds, pass/fail) | OSS | Browser-roadmap | Fully local. Derive an A–F letter per asset from open-risk vs thresholds set in Settings. Show as a small letter badge on the asset row; make thresholds one compact settings block. |
| Asset Tag Inheritance | OSS | Browser-roadmap | Nice-to-have; if we add asset tags, let child hosts inherit a group tag. Keep invisible until tags exist. |
| Export toolbar on asset list | OSS | Partial | Same one-menu export as findings. |
| Contact roles (PM / Team Lead / Technical Contact) | OSS | Partial | We have single owner. Add optional named contact roles per asset; render as a small contacts strip in the asset drawer, not a permissions screen. |
| Metadata key/values on asset | OSS | Browser-roadmap | Offer a free key/value metadata block per asset; collapsed by default. |

### SLA

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Per-severity SLA windows | OSS | Have | Crit 7 / High 30 / Med 90 / Low 180, editable. Keep. |
| Multiple named SLA configs (per-asset selection) | OSS | Browser-roadmap | Add named SLA profiles and let an asset pick one. Deliver as a small profile picker on the asset; default profile applies unless overridden. |
| SLA breach badges + due dates | OSS | Have | dueDate/dueIn/slaState with ok/soon/overdue. Keep the badges compact. |
| SLA breach notify (active / active+verified / Jira-linked; exponential backoff) | OSS (notification routing) | Needs-backend (B6) | Sending is server-side. In-browser we already show breach state; the actual notify unlocks with the connector. |
| SLA compliance % metric | OSS | Have | In kpis(); keep on dashboard. |

### Remediation / campaigns

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Remediation grouping / campaigns | PRO/commercial norm | Have | Campaigns v1 (board/table/timeline/calendar/workload/dashboard) + v2 ClickUp-style workspace over real data. Strong; keep drag-drop plus keyboard card moves. |
| Root-cause / fix-first grouping | Rapid7/Dazz | Have | Remediations view: one fix clears N findings across M assets, ranked by risk removed. Keep as the "start here" for remediation. |
| Remediation guidance / scripts | Growing | Have | Shipped PowerShell playbooks + combined copy. Keep per-finding and combined copy one click apart. |
| Planned Remediation Date / Version, Effort, Mitigation Policy fields | PRO | Browser-roadmap | Add optional planned-fix date and effort estimate to the finding drawer; these feed campaign workload views. Keep them optional inline fields. |
| Auto-fix / AI opens fix PRs (Sensei) | PRO (locked) | Needs-backend (B1/B4) | Out of scope for local-first; note as a connector-tier possibility, not a near-term target. |

### SBOM / components

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Component inventory grouped by name + version | OSS | Have | SBOM view with components-by-license and vuln counts per component. Keep. |
| Components finding-linked (active/dup/total counts per component) | OSS | Partial | Add active/total finding counts per component and click-through to the filtered workbench. One click from component to its findings. |
| License risk classification | SecObserve/OSS | Have | permissive/copyleft/other/unknown classes. Keep as bars. |
| SPDX import (in addition to CycloneDX) | OSS parser | Browser-roadmap | Add SPDX to the import auto-detect. No new UI needed. |

### Endpoints

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Endpoint object (URL/host DAST targets), active/total products+findings, overall status | OSS | Partial | Our Assets are host-centric already; DefectDojo separates URL endpoints from products. Rather than a new object, add a URL/endpoint field on findings and let Assets show endpoint rows. Avoid a parallel Endpoints nav. |
| Endpoint metadata import | OSS | Browser-roadmap | Fold into asset metadata import; one importer, not two. |
| Endpoint status per finding (mitigated per endpoint) | OSS | Browser-roadmap | Represent as finding status scoped to host; we largely have this via keyOf(cve|host). |

### Reporting

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Dashboards + executive tiles | OSS | Have | Overview KPIs, workflow strip, top hosts, campaign roll-up, drilldowns. Keep. |
| Drag-and-drop Report Builder (cover, TOC, custom content, findings, endpoints, page break; HTML + async PDF) | OSS | Browser-roadmap | Winnable client-side: a section-picker that assembles a printable report from existing views, exported via the browser print/PDF path. Keep it a simple ordered checklist of sections, not a freeform canvas. |
| Saved / generated reports list | OSS | Browser-roadmap | Persist report configs in localStorage; list them on the report view. No server storage needed. |
| Per-product / per-engagement / per-finding-list report export | OSS | Partial | Any filtered workbench view should export to a report; wire the current filter set into the report builder. |
| Morning Report (fresh KEV/EPSS/exploit/Tenable briefing) | n/a (our differentiator) | Have | Unique to us; keep it the default landing-adjacent briefing. |
| Custom disclaimers on reports/notes/notifications (+ force on reports) | OSS | Browser-roadmap | Add a disclaimer text field in Settings appended to exported reports. One text area, one toggle. |

### Metrics / insights

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Open bug count by month/week by severity; closed/accepted in period | OSS | Partial | We have current-state KPIs and MTTR but limited historical trending. Add a local time-series by snapshotting counts on each import; render as a trend sparkline row. Trending is the acknowledged lighter area. |
| Posture trending over time | ASPM norm | Browser-roadmap | Same snapshot mechanism; store per-import roll-ups in IndexedDB and chart them. No backend needed if we snapshot on import. |
| Top products / engineer / reporter metrics | OSS | Partial | We have top-hosts and campaign roll-ups. Add top-owners and top-assets-by-risk; reuse existing bar drilldowns. |
| Simple metrics / product-type counts | OSS | Have | Covered by dashboard KPIs. |
| Insights analytics (Pro) | PRO | Browser-roadmap | Our on-device analytics can approximate; keep any AI narrative on-device (Ask AI), never a cloud call. |

### Compliance / regulations / benchmarks / questionnaires

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Regulations registry (GDPR/HIPAA/PCI/GLBA/SOX/PIPEDA etc.) attachable to assets | OSS | Browser-roadmap | Ship a bundled regulation library (static JSON, like KEV) that users attach to assets as compliance tags. This is entirely local. Present as a tag/selector on the asset, with a compliance filter on findings. |
| Compliance category mapping on findings (PCI DSS clause, OWASP Top 10) | OSS | Browser-roadmap | Map CWE/finding to framework references from a bundled crosswalk; show as a small "maps to" chip in the drawer. |
| Benchmarks (CIS / OWASP ASVS checklists + grading) | OSS | Browser-roadmap | A bundled checklist per asset with pass/fail and a rolled-up grade; deliver as a collapsible checklist tab on the asset, not a separate nav section. |
| Questionnaires (named, question counts, attach to engagements, anonymous responses, answered tracking) | OSS | Browser-roadmap | Lower priority for our audience. If built, keep it a simple local form-builder writing to localStorage; skip the anonymous-response and engagement-attach machinery. |
| Checklists | OSS | Browser-roadmap | Fold into the benchmarks checklist component; one checklist primitive reused. |

### Notifications

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| In-app alerts / notification bell | OSS | Partial | We have new-key flagging and Morning Report. Add a lightweight in-app "what changed since last visit" alerts tray (new findings, breaches, expiring acceptances) built entirely from local diff. Keep it a quiet badge, not a 21-count noise bell. |
| Per-event notification routing (product/engagement/test/scan added, SLA breach, risk-acceptance expiry, mention, review requested) | OSS | Needs-backend (B6) for send; Browser-roadmap for in-app | The in-app equivalents are local; email/Slack/Teams/webhook delivery is B6. Build the local event model now so the connector only adds the transport later. |
| Slack / Teams / email / outbound webhook channels | OSS | Needs-backend (B6) | Unlocks with the single connector. |
| Announcement banner + login banner | OSS | Browser-roadmap (announcement) / Needs-backend (login) | A local announcement banner (Settings text) is trivial and useful for team-shared builds; login banner presupposes auth (B3). |

### Integrations (Jira / connectors / webhooks)

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Deep-link to Jira / ServiceNow (pre-filled create) | common baseline | Have | Pre-filled Jira CreateIssueDetails and SNOW incident URLs with an in-app pre-edit modal and URL-length meter. Keep. |
| Link an existing ticket key to a finding | OSS-ish | Have | setTicket/ticketOf via overrides. Keep the inline "paste key" affordance. |
| Two-way Jira: create + webhook status sync + epic/labels + min-severity push | OSS | Needs-backend (B4) | Connector holds the token, writes back, reads status. Until then keep deep-link + manual key link. |
| Inbound Jira webhook (status sync only) | OSS | Needs-backend (B5) | Note the scope is Jira-only status sync; no general inbound webhook API in OSS. |
| GitHub issues integration | OSS | Needs-backend (B4) | Same connector tier. |
| Upstream connectors (134) — API pull from Tenable/Qualys/Rapid7/CrowdStrike/Wiz/ServiceNow/ManageEngine etc. | PRO | Needs-backend (B1/B2) | Our dashboards already return vendor-API-shaped data, so the connector swap is small. This is the headline backend value. |
| Downstream connectors (push to ticketing/SIEM) | PRO | Needs-backend (B4) | Same connector. |
| Universal Importer binary + DefectDojo-CLI (pipeline push) | PRO | Needs-backend (B5) | CI/CD push presupposes a listening endpoint. |
| Tool Configuration / Tool Type registry (stored tool connections) | OSS | Partial | We store Jira/SNOW/Tenable.io/ManageEngine config for deep-links/labels. Extend the same Settings block into a "connections" catalog the connector later activates; keep it one settings page. |
| CI/CD infrastructure object | OSS | Needs-backend (B5) | Pipeline-side; connector tier. |

### RBAC / SSO / multi-user

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| Multi-user with shared state | OSS | Needs-backend (B3) | Single-user local today. Connector adds shared DB + identity. Keep the app fully usable solo so the backend is opt-in. |
| Object roles Reader/Writer/Maintainer/Owner + Groups + global roles | OSS | Needs-backend (B3) | Design the permission model now (roles map to our existing actions) so it drops in cleanly. |
| Configuration Permissions (fine-grained per-feature grants) — third RBAC axis | OSS | Needs-backend (B3) | Note this as a distinct axis beyond object + global roles when we design RBAC; do not surface until multi-user exists. |
| SSO: SAML2 / OAuth2 (Google/Azure AD/Okta/GitLab/Keycloak/Auth0) / RemoteUser | OSS | Needs-backend (B3) | Entra SSO already noted as the intended path in the backend direction. |
| Superuser / staff / API tokens per user | OSS | Needs-backend (B3) | Token issuance is server-side. |
| Ownership assigned to groups (Pro) | PRO | Needs-backend (B3) | Our owner field is per-finding text today; group ownership needs identity. |

### API / MCP / AI

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| REST API v2 (full CRUD, OpenAPI/Swagger, tokens) | OSS | Needs-backend (B3) | Console consumes public CVE APIs, serves none. Served API is a backend feature. |
| MCP service exposing vuln data to LLMs | PRO | Needs-backend (B3) | Server-side MCP. Conceptually aligns with our on-device Ask AI; keep our AI on-device and note MCP as a connector-tier option. |
| On-device NL assistant | n/a | Have | Ask AI: 100% on-device embedding model maps NL to a whitelist-validated route grammar; never leaves the browser. A genuine differentiator over Pro's server MCP. Keep it the default landing. |
| AI auto-remediation / threat modeling from design | PRO (locked) | Needs-backend | Out of scope for local-first; note only. |
| Triage Engine (automated triage/auto-disposition rules) | PRO (beta) | Browser-roadmap | We can ship local rule-based auto-triage (e.g., auto-accept below threshold, auto-tag by pattern) entirely client-side. Deliver as a small rules list in Settings with a dry-run preview before enabling. |

### Settings / workflow

| Capability | DefectDojo (OSS/PRO) | vm-ops-console status | UX consideration (our design) |
|---|---|---|---|
| System settings surface (dedup, grading, benchmarks, SLA, disclaimers, display toggles) | OSS | Partial | We have branding, SLA, risk weights, ticketing config, nav-hide, home route, live-EPSS, recurrence, export/import. Add grading thresholds, dedup scope, verified enforcement, disclaimers as new Settings blocks. Keep Settings sectioned and searchable, avoid DefectDojo's single long toggle wall. |
| Finding Workflow (custom statuses + transitions) | PRO | Browser-roadmap | Let users rename/reorder our 6 statuses and define allowed transitions locally. Deliver as a visual mini state-machine in Settings; ship sensible defaults so most users never open it. |
| Feature flags | PRO | Browser-roadmap | A local flags panel for opt-in experiments; keep off by default, local-first. |
| Password policy / login banner / celery status | OSS | Needs-backend (B3) | All presuppose auth/server; connector tier. |
| Settings export / import | n/a | Have | We already export/import settings JSON; keep it as the portability story. |
| Calendar (engagement schedule) | OSS | Browser-roadmap | Campaigns already have calendar views; a lightweight due-date calendar can reuse them. No separate nav. |
| Custom branding (name/icon/color/favicon) | limited | Have | User-rebrandable already; a genuine plus. Keep. |

**Backend-boundary summary.** Every Needs-backend row above collapses to the same single opt-in, local-first connector (PocketBase-style, on your machine or network): **B1** live vendor API pulls (134-connector catalog, API-import parsers), **B2** scheduled/continuous ingestion, **B3** multi-user + RBAC + Configuration Permissions + SSO + served REST API + MCP + password policy + login banner, **B4** two-way Jira/GitHub/ServiceNow write-back + status sync, **B5** inbound webhooks + CI/CD gating + Universal Importer/CLI, **B6** email/Slack/Teams/webhook sends. One backend, added once, unlocks all six.

---

## PART 2 — HTML section (splice after "Where we can still win inside the browser")

_(The at-a-glance HTML scorecard is rendered in [feature-comparison.html](feature-comparison.html).)_

---

## TOP 10 highest-value gaps to close in-browser next

Ranked by value to Joe's positioning versus effort, all fully client-side (no backend):

1. **No-code Universal Parser (map any CSV/JSON/XML).** Directly attacks the single biggest gap (parser breadth) and one-ups a Pro-only DefectDojo feature. A column-mapping panel over any upload turns "unsupported format" into "map it once." Effort: medium-high.

2. **Broader native parsers: SPDX + more vendor CSV/JSON.** Cheapest way to shrink the 330-tool breadth gap; auto-detect means no new UI. Effort: medium (incremental per format).

3. **Asset grading A–F + benchmarks (CIS/OWASP ASVS) checklist.** A visible DefectDojo parity item, fully local from thresholds we already compute; adds an at-a-glance letter badge executives understand. Effort: low-medium.

4. **Regulations library + framework mapping (bundled JSON like KEV).** Closes the ASPM "compliance-framework mapping" area we ourselves flag as light; attach GDPR/PCI/HIPAA to assets and map CWE to framework refs. Effort: medium (data crosswalk is the work).

5. **Posture trending over time (snapshot counts on import).** Our other self-flagged weak area; snapshot roll-ups to IndexedDB on each import and chart them. High reporting value, no backend. Effort: low-medium.

6. **Client-side Report Builder (assemble + print/PDF).** Matches DefectDojo's report builder using existing views and the browser print path; saved configs in localStorage. Strong for the exec-deliverable story. Effort: medium.

7. **"Do not reactivate" reimport toggle + explicit close-missing control.** Small, high-trust correctness feature so triage stays source of truth on rescan; direct DefectDojo behavior parity. Effort: low.

8. **Local automated triage rules (auto-accept below threshold, auto-tag, FP-history match) with dry-run.** Approximates Pro's Triage Engine entirely on device; multiplies the value of the risk model. Effort: medium.

9. **In-app "what changed since last visit" alerts tray.** The local half of notifications (new findings, breaches, expiring acceptances) built from a local diff; sets up the event model the connector later routes to email/Slack. Effort: low-medium.

10. **Finding status enrichment: add Verified + Out-of-Scope flags and custom status/transition config.** Closes the status-model gap and adds Pro-style workflow customization locally; ship sensible defaults so most users never touch it. Effort: low-medium.