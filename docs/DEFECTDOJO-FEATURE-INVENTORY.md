> **Official documentation.** Raw feature/settings inventory captured by clicking through both live DefectDojo demos (OSS demo.defectdojo.org + PRO pro.demo.defectdojo.com). Source material for [DEFECTDOJO-PARITY.md](DEFECTDOJO-PARITY.md) and [feature-comparison.html](feature-comparison.html). Last updated 2026-08-19.

# DefectDojo feature inventory (from live demo.defectdojo.org, v3.2.201 open-source)

Captured by clicking through the live demo. Goal: full feature list to map against vm-ops-console (task #28).
PRO features captured separately from pro.demo.defectdojo.com.

## Top-level navigation (left sidebar)
Dashboard · Assets · Engagements · Findings · Components · Endpoints · Reports · Metrics · Users · Calendar · Questionnaires · Configuration · Upgrade
Top bar: global Search, Alerts/notifications bell (21), User menu.

## Dashboard (/dashboard)
- Tiles: Active Engagements count, findings "Last Seven Days" (new), "Closed in Last Seven Days", "Risk Accepted in Last Seven Days" — each links to filtered finding lists.
- Historical Finding Severity pie (critical/high/medium/low/info counts).
- Reported Finding Severity by Month trend chart + data table.
- Unassigned Answered Engagement Questionnaires panel.
- (Dashboard is configurable per-user in newer versions.)


## Configuration menu (Settings) — submenu items + URLs
- **System Settings** (/system_settings) — global toggles
- **SLA Configuration** (/sla_config) — per-severity SLA day windows (multiple named configs)
- **Notifications** (/notifications) — per-event notification routing
- **Tool Configuration** (/tool_config) — configured scanner/tool connections
- **Tool Type** (/tool_type) — scanner tool type registry
- **CI/CD Infrastructure** (/cicd_infrastructure)
- **Regulations** (/regulations) — compliance regulation registry (GDPR/HIPAA/etc.)
- **Note Types** (/note_type) — custom note categories
- **Announcement** (/configure_announcement) — site-wide banner message
- **Login Banner** (/configure_banner) — pre-login banner text
- **Celery Status** (/celery_status) — background task queue health (backend infra)

## Section URL map (top nav)
/asset · /engagement · /finding/open · /components · /endpoint · /reports/builder · /metrics?date=5&view=dashboard · /user · /calendar/engagements · /questionnaire · /support
Header: global Search, Alerts bell, User Menu (profile/config/logout). Two header "+" quick-add dropdowns.

## System Settings (/system_settings) — global toggles (the feature surface)
- **Deduplication**: deduplicate findings, delete duplicates, max duplicates.
- **JIRA**: enable integration, web hook + secret, min severity to push, labels, add vuln-id as label.
- **GitHub** integration.
- **Notification channels**: Slack, Microsoft Teams, mail, Webhook (each toggle).
- **Enforce Verified Status**: globally / Jira / Asset Grading / Metrics.
- **False positive history** (+ retroactive) — auto-mark FPs matching prior FPs.
- **Asset (Product) Grading**: enable, Grade A/B/C/D/F thresholds; Asset Tag Inheritance.
- **Benchmarks** (CIS/OWASP ASVS checklists).
- **Similar Findings** surfacing.
- **Engagement Auto-Close** (+ days).
- **Finding SLAs**: enable; notify SLA breach for active / active+verified / Jira-linked only; exponential backoff.
- **Risk acceptance**: default days, expiration heads-up days.
- **Questionnaires**, **Checklists**, **Endpoint Metadata Import**, **Tracked Asset Files**, **Finding Groups**.
- **UI table-based filtering/sorting**, **Calendar**, **CVSS3 display**, **CVSS4 display**.
- **Custom Disclaimers**: notifications / reports / notes (+ force disclaimer on reports).
- **Password policy**: min/max length, require digit/special/lower/upper, block common.
- **API**: expose error details. Filter string-matching optimization. Anonymous survey responses. Url prefix, Team name.

## SLA Configuration (/sla_config)
- Multiple **named SLA configs**; per-severity day windows (Default = Critical 7 / High 30 / Medium 90 / Low 120); products pick a config. (vm-ops-console has per-severity SLA but single global config.)

## Notifications (/notifications) — per-event routing
- Scope: Personal / System / (per-Product override). Channels: Slack/Teams/mail/webhook/in-app alerts.
- Events: product type added, product added, engagement added, test added, scan added, scan added (empty), JIRA problems, upcoming engagement, stale engagement, auto-close engagement, close engagement, user mentioned, code review, review requested, other, SLA breach, Risk Acceptance Expiration, SLA breach (combined).

## Findings (/finding/open, plus /finding/closed /accepted etc.)
- Columns: severity, title, CWE (links to mitre), **Vulnerability Id (CVE)**, **EPSS Score**, **EPSS Percentile**, **Known Exploited (KEV)**, **Used in Ransomware**, **Date Added to KEV**, date, **SLA age days**, Reporter, **Found By (scanner/test)**, Status. Sort on every column.
- **SLA overdue badges** per finding ("Overdue: Remediation for high findings in 30 days since <date>").
- **Bulk actions** (dropdown): select by severity / select-all; bulk edit, risk-accept, push to Jira, delete, tag, etc.
- **Filters** (show-filters): large filter panel (severity, status, scanner, product, tags, CWE, date, EPSS, active/verified/duplicate/false-positive/out-of-scope/mitigated, etc.).
- Per-finding "More options" menu. Pagination + page size + column search.
- Finding status tabs: Open / Verified / Closed / Accepted / False Positive / Out of Scope / Inactive / Risk-expired.

## Engagements (/engagement)
- Active/All engagements. Columns: name (+ type badge e.g. "pci"), Period, **Status** (Not Started/Blocked/In Progress/Completed/Cancelled), Asset (product), Organization (product type), **Lead**, **Tests** count.
- Engagement = a testing effort grouping Tests; types **Interactive** vs **CI/CD**; start/end dates + overdue; per-engagement risk acceptance, notes, files, questionnaires.

## Assets = Products (/asset)
- Columns: Asset, **Tags**, **Criticality (A–F grade)**, Metadata, Eng. count, **Active (Verified) Findings**, **Vulnerable Hosts/Locations**, **Contact roles** (Product Manager / Team Lead / Technical Contact), **Organization (Product Type)**.
- **Export toolbar**: Column visibility, Copy, Excel, CSV, PDF, Print, Search (this is a DataTables export the console lacks).
- Product **grading A–F**, business criticality, per-product user/role assignment, metadata key/values.

## Finding detail (/finding/<id>)
- Product sub-nav (per-product context): Overview, Components, Metrics, Engagements, Findings, Hosts/Endpoints, Benchmarks, Settings.
- Header: title, **Last Reviewed by/date**, Last Status Update, Created. Fields: ID, Severity, **SLA age (overdue days)**, **Status flags** (Active, Verified — also Duplicate/False Positive/Out of Scope/Risk Accepted/Mitigated/Inactive), Type, Date discovered, **Age**, Reporter, **CWE**, **Vulnerability Id (CVE)**, **Found by (scanner)**.
- **SAST detail**: Service, Location, Line Number, code snippets (line/column/source-object), Finding Link back to scanner.
- **Compliance category mapping** on description (e.g. "PCI DSS v3.1 6.5.7 XSS", "OWASP Top 10 2013 A3").
- **Similar Findings (N)** panel (dedup/near-dup detection).
- Sections: Description, Mitigation, Impact, Steps To Reproduce, Severity Justification, **References**, **Notes (private/public)**, files/images.
- Workflow verbs (keyboard + buttons): edit, verify, close, prev/next, request review, risk accept, push to Jira, tag, add note, clone, delete.

## Endpoints (/endpoint)
- All Endpoints (DAST/host targets). Columns: Endpoint (url/host), Active (Total) Products, Active (Total) Findings, Overall Status (Active/Mitigated). Endpoint-status per finding; endpoint metadata; endpoint metadata import.

## Components (/components)
- SBOM/SCA component inventory grouped by **Name + Version**: Active, Duplicate, Total finding counts. Export toolbar (Copy/Excel/CSV/PDF/Print). (vm-ops-console has an SBOM/Licenses view; DefectDojo's is finding-linked.)

## Metrics (/metrics — multiple views)
- Charts: Open Bug Count by Month/Week (by severity), Risk Accepted by Month/Week, Top Products by Bug Severity, Total Findings in Period by Severity (pie), Risk Accepted in Period, Closed in Period. Date-range filtered.
- Other metric views: Simple Metrics, Product Type counts, per-Product metrics, Engineer/reporter metrics, homepage dashboard tiles.

## Reports (/reports/builder)
- **Drag-and-drop Report Builder**: widgets = Cover Page, Table of Contents, Custom Content, Findings, Vulnerable Endpoints, Page Break. Options: report name, include finding notes, finding images, report type (HTML; also async PDF). Saved/generated reports list. Also per-product / per-engagement / per-finding-list report exports.

## Users & RBAC (/user, /group)
- Users: name/username/email/title/phone, Active, **Superuser**, **Staff**, date joined, last login, **API token** (last reset), password last reset.
- **RBAC**: per-object roles **Reader / Writer / Maintainer / Owner** on Product Types + Products; **Groups** with roles; global roles; contact roles (PM/Team Lead/Technical).
- **SSO / auth**: SAML2, OAuth2 (Google/Azure AD/OKTA/GitLab/KeyCloak/Auth0), RemoteUser; configurable login. API v2 tokens per user.
- (All of RBAC/SSO/multi-user = crosses vm-ops-console's backend boundary B3.)

## Questionnaires (/questionnaire)
- Named questionnaires (Access Control, Information Flow/Dependency Modeling, Information Management, Infrastructure, Inventory, Testing Preparation) with question counts + Active flag; General Questionnaires; Create Questionnaire; filters. Attach to engagements; anonymous responses option; answered-questionnaire tracking on the dashboard.

## Tool Config / Tool Type (/tool_config, /tool_type)
- Tool Types: SAST / DAST / IAST / Build Server / Source Code (deprecated, removed v3.5.0). Tool Configuration = stored connections (URL + auth) to external tools for API import.

## Regulations (/regulations) — built-in compliance registry
- Ships a big regulation library: OPPA, CA SB-1386, COPPA, DPA 1998, EU Directive 95/46/EC & 2002/58/EC, FERPA, **GDPR**, **GLBA**, **HIPAA**, **PCI DSS**, **PIPEDA**, **SOX**. Jurisdiction + category (privacy/finance/medical/education) + reference. Attach to products for compliance context.

## Other confirmed features (demo + known)
- **Import / Reimport scan** (core): per-engagement/product; a scanner-type dropdown with **180+ parsers**; reimport reconciles against prior test (dedup, close-old, reactivate); options: active/verified defaults, min severity, tags, close old findings, push to jira, apply tags, service, group_by, api-scan-config.
- **Deduplication engine**: algorithms (hash_code, unique_id_from_tool, legacy, unique_id_or_hash_code); cross-engagement/product dedup; dedup on import.
- **Finding Groups** (group findings by component/etc.), **Finding Templates** (apply saved finding text), **Bulk edit**.
- **Risk Acceptance** objects (expiring, reasons, files), **False Positive history**, **Mitigated** lifecycle, **Out of Scope**, **Transfer finding**.
- **JIRA** two-way (create issue, webhook status sync, epic/labels), **GitHub** issues.
- **Benchmarks** (CIS/OWASP ASVS product checklists + grading), **Product grading A–F**.
- **Endpoint metadata import**, **Tracked files**, **Notes (public/private) + note types**, **Tags** everywhere.
- **Calendar** (engagement schedule), **Announcements + login banner**, **Custom disclaimers**.
- **REST API v2** (full CRUD, tokens, OpenAPI/Swagger), **webhooks (outbound)**, **Slack/Teams/email/webhook notifications**.
- **RBAC** (Reader/Writer/Maintainer/Owner) + **groups** + **SSO** (SAML/OAuth) + superuser/staff.
- **SLA** per-severity + named configs + breach notifications; **EPSS + KEV + Ransomware** columns on findings.

## Boundary note vs vm-ops-console (browser-only)
- HARD backend (B3/B4/B2/B5/B6): multi-user + RBAC + SSO; JIRA/GitHub 2-way write-back + webhook status sync; scheduled/CI import + auto-close; inbound webhooks; email/Slack/Teams sending; API-based tool pull; Celery async.
- ALREADY-HAVE or IN-BROWSER-FEASIBLE: findings workbench + filters/bulk, per-severity SLA, EPSS/KEV/LEV/SSVC, asset inventory + criticality, remediations/root-cause, SBOM/components, campaigns (v1+v2), CSV/SARIF/CycloneDX import, dedup-by-key, risk-acceptance-as-override, reports (client-side), metrics/dashboards, tags, notes. GAPS feasible in-browser: product grading A–F, named SLA configs, compliance/regulation mapping, questionnaires/checklists, finding templates, more parsers, DataTables-style CSV/Excel/PDF export, endpoint model, benchmarks.

# ============ DefectDojo PRO (pro.demo.defectdojo.com, v3.2.200-Pro, "PRO UI" React app) ============
Completely different modern React UI. PRO-only nav sections:
- **OVERVIEW**: Home, **Insights**, **My Work** (NEW), **Reporting** (BETA), Calendar
- **SENSEI + AI**: **Sensei** (AI auto-fix, LOCKED), **Threat Modeling** (LOCKED), **MCP** (Model Context Protocol service), **AI Model Settings** (LOCKED)
- **CONNECT**: **Upstream** (scanner connectors / universal importer), **Downstream** (ticketing push), **Authorization**, **Diagnostics**, **Import**
- **ACT**: **Triage Engine** (BETA — automated triage rules), **Vulnerability Explorer** (BETA), **Risk Acceptances**, **PSIRT 1.0** (LOCKED), **Explore**
- **SETTINGS**: All Settings (NEW), **Feature Flags** (NEW), System, UI Defaults, **Users & Permissions**, **Finding Workflow**, Configuration, Notifications, Operations, License & Support

## PRO Dashboard
- Tiles: Passing/Failing Products (grading), Active Engagements, Findings Last-7-days/Closed/Accepted, **Approaching SLA Violation**, Active Critical/High/Medium/Low, **Not Scanned in 3 Months**. Historical + Reported severity charts. **Top/Bottom Graded Assets**, Open Surveys. Customizable tiles (+ / gear).

## PRO My Work (/ui/my-work)
- Views: My Team's Queue, **Assigned to Me**, **Awaiting My Review**, Reviews I Requested, My Risk Acceptances. **Ownership assigned to GROUPS** (not individuals).
- MASSIVE finding column model (their data richness): Priority, **Reachability**, **Sensei**, **Exploit Maturity**, CVSSv3, **CVSSv4**, EPSS score/percentile, KEV, Ransomware, KEV Date, Age, **SLA Expiration Date**, **Mitigated Within SLA**, **Planned Remediation Date/Version**, **Effort For Fixing**, **Mitigation Policy**, Review Claimant, Assignees, Reviewers, plus asset business-context: **Asset Revenue, Asset User Records, Asset Business Criticality, Asset Internet Accessible, Asset External Audience**, Component name/version, File Path, Unique/Vuln ID From Tool, Locations.

## PRO Sensei (/ui/ai/sensei) — AI auto-remediation (LOCKED here, preview)
- Onboard **repositories + cloud accounts**; **auto-fix candidates**, **/fix command**, **staged auto-fixes**, fix quota, remediations, scan activity, Fix Impact/Targets. (AI that opens fix PRs.)

## PRO Threat Modeling (/ui/threat-modeling) — powered by Sensei/AI
- Generate a **threat model + attack paths + security requirements from a feature DESIGN before code exists** (from a design doc or pasted description). Outputs: Threats, Requirements, Findings, versioned per asset.

## PRO MCP Service (/ui/ai/mcp-service) — AI assistant integration
- Exposes a **DefectDojo MCP server** (Streamable HTTP over HTTPS, per-user REST API token auth) so Claude/OpenAI/Gemini can query your vuln data. Example prompts: quarterly board security report, SAST tool false-positive/MTTR/cost analysis. (Server-side MCP = backend; but conceptually aligns with vm-ops-console's on-device Ask AI + the free-AI-ideas list.)

## PRO Vulnerability Explorer (/ui/vulnerability-explorer) — CVE-centric rollup
- Groups findings **by CVE** (not by finding): Vulnerability ID, Type, Severity, EPSS Score/Percentile, KEV, Ransomware, KEV Date, **Total Findings**, **Active Findings**, **Assets Impacted**, **Engagements Impacted**, First/Last Seen. "Sync KEV/EPSS data" action. 1706 CVEs. (Blast-radius-per-CVE view; vm-ops-console has CVE-centric CVE Explorer + KEV/EPSS already.)

## PRO other (nav-confirmed, detail pending)
- **Insights** (analytics), **Reporting** BETA (richer than OSS builder), **Triage Engine** BETA (automated triage rules / auto-disposition), **Upstream** (scanner connectors / universal importer — API pull), **Downstream** (ticketing push), **Authorization**, **Diagnostics**, **PSIRT 1.0** (product security incident response, LOCKED), **Explore**.
- **SETTINGS**: All Settings, **Feature Flags**, System, UI Defaults, **Users & Permissions** (RBAC), **Finding Workflow** (custom statuses/transitions), Configuration, Notifications, Operations, License & Support.

## PRO Upstream Connectors (/ui/connections/upstream) — API-pull, NOT file import
- **134 available connectors** for pulling findings directly from tools via their APIs (vs OSS file-upload import). Overlapping Joe's env: **Tenable Vulnerability Management**, Tenable Web App Scanning, **Qualys**, **Rapid7 InsightVM**, Rapid7 InsightAppSec, **CrowdStrike Falcon**, **Wiz**, **ServiceNow CMDB**, **Vulnerability Manager Plus (ManageEngine)**, **Azure DevOps**, GitHub, GitHub Advanced Security, GitLab, Bitbucket, Snyk, Semgrep, SonarQube, Checkmarx One, Veracode, Fortify, Coverity, Black Duck, Mend, JFrog XRay, Dependency-Track, Trivy, Anchore, Aqua, Sysdig, Orca, Microsoft Defender (+for Cloud), Prowler, runZero, Shodan, Censys, HackerOne, Bugcrowd, etc. (full 134 captured in demo).
- Connector config = stored creds + scheduled pull + map to product/engagement. **All backend (B1/B2).**
- **Downstream connectors** = push to ticketing/SIEM. **Triage Engine** (BETA, route not /triage-engine) = automated triage/auto-disposition rules. **Insights** = analytics dashboards. (Both behind different SPA routes; confirmed in nav.)

## PRO Settings menu
All Settings, **Feature Flags**, System, UI Defaults, **Users & Permissions** (RBAC/groups/SSO), **Finding Workflow** (custom finding statuses + transitions), Configuration, Notifications, Operations, License & Support.
