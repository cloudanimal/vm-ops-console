# Optional backend connector (design — not yet built)

The app is backend-free by default. For a team running it at scale, an **optional connector** adds live
enterprise data and two-way ticketing **without turning the app into a server it has to host**. The browser
stays a static client; the "backend" is the user's own infrastructure.

## The setup this targets

An on-prem server that already has the **Power BI on-premises data gateway** installed and can run
**PowerShell or Python**, with network reach to:
- **ManageEngine Endpoint Central** (patch/agent inventory)
- **Tenable** (vulnerabilities / agents)
- **Active Directory on-prem** (asset source of truth)

…plus, eventually, API access to **ServiceNow** and **Jira**.

## Two planes

### Read / data plane
```
sources (ME, Tenable, AD) ──pull (PS/Python, scheduled)──▶ connector ──dataflows──▶ Power BI (semantic model)
                                                                                         │
                                                        browser ◀── Entra PKCE + executeQueries (DAX) ──┘
```
- The connector pulls the sources on a schedule, normalizes, and lands the data where **Power BI dataflows**
  pick it up → a semantic model.
- The **browser reads Power BI directly** via Entra sign-in (public-client PKCE) and the Power BI REST
  `executeQueries` DAX endpoint. This is **CORS-allowed** (verified) — so the console gets live, at-scale
  data with no server of its own to host for reads.

### Write / action plane (ServiceNow / Jira)
Two distinct patterns — keep them separate:
- **Status (read):** don't call ServiceNow/Jira from the browser. The **connector polls** them and writes
  ticket status into the same Power BI model; the console shows live status through the read plane. No CORS,
  no secrets in the browser.
- **Create (write):** creating tickets / change requests needs secret auth, so it can't come from the
  browser. It goes **browser → a thin HTTPS endpoint on the connector → ServiceNow/Jira**. The connector
  holds the credentials; the browser just POSTs a payload.

Credentials always live on the connector, never in the browser.

## Suggested phasing

1. **Now** — connector → Power BI; console reads it live. Ticketing stays the current deep-link (open a
   pre-filled Jira/ServiceNow ticket URL). Zero new infra beyond the connector job.
2. **Next** — connector polls ServiceNow/Jira status → Power BI; console shows live ticket status
   (read-only, high value, still no browser secrets).
3. **Later** — connector exposes a thin write endpoint; the console calls it to open tickets and change
   requests, and to query beyond status.

## How this changes the app's story

"Backend-free" becomes **"runs fully standalone (import CSVs, deep-link tickets), or connects to your
Power BI + connector for live at-scale data and two-way ticketing."** The About page's Architecture +
"Standalone, or connected" sections describe both paths.

## Starting point in this repo

A working Python **Endpoint Central** client already exists (built earlier, outside the web app —
`ec_client.py`: Zoho OAuth self-client / server / device flows, Reports Sync API + `/dcapi`). The first
build step is to extend that to Tenable + AD and add the Power BI dataflow/push landing (Phase 1). The
browser side already has the empirically-verified CORS/auth facts: Power BI + MS Graph are browser-direct
(Entra PKCE + CORS); Tenable.io / ManageEngine EC / Wiz are connector-only (no ACAO + confidential auth).
