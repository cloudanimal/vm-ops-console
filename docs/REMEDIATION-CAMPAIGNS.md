# Remediation Campaigns — Design Brief

Design notes for a planned **Remediation Campaigns** feature in the VM Ops Console: the org-level
orchestration layer *above* per-finding triage. Group findings into a campaign with an owner, a due
date/SLA, and a target, then track the group to closure and report on it.

Status: **design only — not built.** Researched 2026-07-08 from vendor docs + NIST/CISA guidance.

---

## 1. Concept

A campaign shifts the unit of progress from *"is this finding fixed?"* to *"is this body of work on
track?"* Every mature platform converges on the same shape under different names — Vulcan "Campaigns,"
Rapid7 "Remediation Projects," ServiceNow "Vulnerability Groups / remediation tasks":

> **group findings → assign an owner → set a due date/SLA → open ticket(s) → track % to closure → report.**

**Scope has two modes** (both worth supporting):

| Mode | Behaviour | Use case |
|---|---|---|
| **Static** | Fixed set of findings; **auto-completes at 100%**; does *not* absorb new discoveries | One-time push (e.g. "clear this quarter's criticals") |
| **Dynamic** | A saved query; progress rises as things close and *falls* as new matches appear; "rarely reaches 100% (and shouldn't)" | Standing program (e.g. "all KEV on internet-facing assets") |

## 2. Guidance to anchor SLAs / priority on

- **NIST SP 800-40r4** (enterprise patch management): asset/maintenance groups, risk-response scenarios,
  a deploy → verify loop — effectively the campaign lifecycle.
- **NIST 800-53 RA-5** (scan + remediate) and **SI-2** (flaw remediation within *org-defined timeframes*)
  are the control basis for SLAs; **CSF 2.0** maps to ID.RA / PR.PS.
- **CISA KEV + BOD 22-01**: remediate KEV CVEs by a fixed due date.
- **⭐ CISA BOD 26-04 (2026), "Prioritizing Security Updates Based on Risk"** — the modern model to mirror.
  Replaces flat CVSS SLAs with **SSVC-style dynamic timelines** from four factors: **Asset Exposure, KEV
  status, Exploit Automation, Post-Exploitation Technical Impact.** Timelines **shift as facts change**
  (take an asset off the internet → the window lengthens). The console already ingests most of these
  inputs (KEV, exploitation intel, VPR, exposure), so campaign SLAs can be **risk-tiered and dynamic**
  rather than fixed days — a genuine differentiator.

## 3. Vendor patterns

| Platform | Name | Scope | SLA / Goal model | Ticketing | Progress metric |
|---|---|---|---|---|---|
| Vulcan Cyber | Campaigns | Static (manual) / Dynamic (playbook) | Due date **defaults to SLA-config date**; "SLA Status" = assets over SLA | Jira, SNOW, Email, Slack | **resolved instances ÷ total** (fixed/archived/ignored) |
| Rapid7 InsightVM | Remediation Projects | Query Builder (dynamic) or static | **Goals + SLAs** first-class ("Goals define the standard; projects get you there") | Jira, SNOW (manual + auto) | Projects tab + remediator dashboards |
| ServiceNow VR | Vulnerability Groups | Grouping / remediation-task rules | Assignment rules + SLAs | Native | Remediation task state |
| Tenable / Qualys VMDR | remediation views / rules | Filter/tag-based | Risk-based (VPR / TruRisk) | Jira / SNOW connectors | Dashboards |

## 4. Proposed data model

Fits the existing app primitives (`STATE.findings`, `keyOf`, overrides, `slaState`/`dueDate`, saved Views,
Jira/SNOW deep-links). New `localStorage` key `vmops-campaigns`, new route `#/campaigns`.

```js
{
  id,
  name,
  scope: { dynamic: bool, query: <findings filter>, staticKeys: [keyOf, ...] },
  owner,
  team,
  priority,
  dueDate,        // default from SLA config; optionally risk-tiered per BOD 26-04
  status,         // planning | active | paused | completed | cancelled
  created,
  notes,
  ticketRef
}
```

- **Scope = a saved Findings filter** — reuse the `#/findings` query/Views engine. Dynamic campaigns
  re-evaluate against `STATE.findings` on each render; static campaigns snapshot `keyOf[]`.
- **Progress = resolved ÷ total instances** (reuse `isOpen` / `statusOf`). **Auto-complete static
  campaigns at 100%.**
- **KPIs**: open vs remediated, % complete, **overdue-vs-SLA** (reuse `slaState` / `dueDate`), MTTR.
- **SLA**: default the due date from SLA config; offer **risk-tiered / dynamic** windows à la BOD 26-04.
- **Ticketing**: reuse the existing Jira / ServiceNow deep-link buttons at the campaign level.
- **Lifecycle**: planning → active → (paused) → completed / cancelled. Cancelling stops managing
  tickets (matches Vulcan's behaviour).

## 5. UI sketch

- **`#/campaigns`** — list/table: Name, Scope, Owner, Priority, Progress bar, SLA status, Due, Status.
- **Campaign detail** — the scoped findings grid (reuse the Findings table) + progress KPIs + notes +
  ticket actions + edit.
- **"New campaign"** — start from a filtered Findings view ("Take Action"-style), or from the campaigns
  page with a filter builder. Choose static vs dynamic scope.

## 6. Sources

- Vulcan Cyber — [Campaigns: Create, Track and Manage Remediation Campaigns](https://help.vulcancyber.com/en/articles/5352974-campaigns-create-track-and-manage-remediation-campaigns)
- Rapid7 InsightVM — [Create and Assign Remediation Projects](https://docs.rapid7.com/insightvm/objective-4-create-and-assign-remediation-projects/)
- ServiceNow — [Vulnerability Groups](https://www.servicenow.com/docs/bundle/yokohama-security-management/page/product/vulnerability-response/concept/vulnerability-groups.html)
- CISA — [BOD 26-04: Prioritizing Security Updates Based on Risk](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk)
- NIST — [SP 800-40r4, Guide to Enterprise Patch Management Planning](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-40r4.pdf)

*Caveat: one researched claim was refuted — Vulcan does **not** auto-compute a due date and push it to
ticketing for SLA compliance; the due date simply **defaults** to the SLA-configured date and is
manually overridable.*
