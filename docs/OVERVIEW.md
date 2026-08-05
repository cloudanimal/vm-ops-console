# Overview

## What it is

A browser-local **vulnerability-management operations console**. One nav, one theme, and one natural-language
"Ask AI" box tie together two halves:

1. **CVE intelligence front end** — search and browse the public CVE corpus, see exploitation signals
   (CISA KEV, EPSS, public PoCs), statistics, software end-of-life, and a daily "what's newly exploitable"
   Morning Report. All from public data, fetched live or shipped as pre-built static datasets.
2. **Operational tooling over the user's own data** (all client-side):
   - **Findings workbench** — import scanner findings (Tenable today), triage by status/owner/SLA, keep
     per-finding notes + a dated status-update log, open Jira/ServiceNow tickets, export CSV. Re-imports
     reconcile by presence and, when the export carries a Tenable "State" column, by state (Fixed rows
     resolve; a resolved finding that reappears active reopens), and each reopen is counted so **recurring /
     flapping** findings surface via a chip, a Recurring filter, and a dashboard KPI.
   - **Tenable VM dashboard** — upload Tenable SC cumulative + mitigated exports for KPIs, severity/SLA
     breakdowns, top findings, one-click report export.
   - **Agent Coverage dashboard** — reconcile Active Directory (the denominator) against ManageEngine,
     Tenable, and CrowdStrike agents to surface coverage gaps and orphaned hosts.
   - **AI Prompt Scanner** — scan agent instructions / MCP configs for prompt-injection & malicious content.

## Who it's for

A solo operator or the smallest of teams who has to track and manage *every* vulnerability flowing from
Tenable + Wiz (and endpoint tools) at scale, without a budget for a heavyweight platform. The north star:
one place, from raw scan export → triaged, owned, ticketed, resolved.

## Product principles

- **Backend-free by default.** It must run as a static site with zero server. The user's data lives in
  their browser. (An *optional* connector for live enterprise data is a separate, additive path — see
  [BACKEND-CONNECTOR.md](BACKEND-CONNECTOR.md).)
- **Never invent data.** Ask AI classifies intent and opens *real* views over *real* data; it does not
  generate CVE facts. Prioritization models are shown side-by-side precisely because they disagree.
- **Public data is public; private data is private.** CVE lookups go to public APIs / shipped datasets.
  Imported findings, scan exports, notes, and API keys never leave the browser.
- **Transparent math.** Coverage %, KPIs, SLA windows, and risk scores are all derived from visible inputs;
  where a number could be misread, the UI shows what it was computed from.

## The five prioritization models (why they coexist)

Every CVE is shown through five lenses because no single one is sufficient and they routinely disagree:

- **CVSS** — impact severity (NVD).
- **EPSS** — FIRST's probability of exploitation in the next 30 days.
- **CISA KEV** — confirmed exploited in the wild (ground truth).
- **NIST LEV** — lower-bound probability it has *already* been exploited (CSWP 41, from EPSS history).
- **SSVC** — a simplified Act/Attend/Track decision tree (CISA's authoritative decision points shown on
  the CVE detail page where published).

A composite verdict (Patch now / this cycle / standard cadence → P1/P2/P3) folds confirmed exploitation +
likelihood + severity together.
