# Hunt: HEXANE cloud web-service C2 (Marlin OneDrive/Graph) & proxy relays

- **Hypothesis:** If HEXANE's Marlin backdoor is using Microsoft OneDrive / Graph API for bidirectional C2, or the actor is relaying C2 through intermediary proxy infrastructure, then the traffic will blend into normal cloud/web flows — so the discriminating signal is *who and how*, not *where*. We should hunt for OneDrive/Graph API access originating from an unexpected process (not a browser or the signed OneDrive/Office client) on a beacon-like cadence, and for internal-to-internal or oddly-routed relay patterns where one host proxies C2 for others. The finding is a non-browser process talking to a legitimate cloud API on a machine-regular interval, or a relay chain, not the cloud destination itself.
- **ATT&CK:**
  - T1102.002 — Web Service: Bidirectional Communication (command-and-control)
  - T1090 — Proxy (command-and-control)

- **Actor procedure:** HEXANE's Marlin backdoor abuses Microsoft OneDrive / Graph API for bidirectional C2 — reading commands and writing results through a trusted cloud service so the traffic terminates at `graph.microsoft.com`/`*.sharepoint.com` and looks legitimate. The actor also routes C2 through intermediary/proxy infrastructure to obscure the true controller location.
- **Why a hunt, not a rule:** OneDrive/Graph are ubiquitous legitimate destinations — blocking or alerting on them is impossible, and virtually every managed endpoint talks to them constantly. The discriminating features (process provenance, request cadence/regularity, token/app-id anomalies, relay topology) require behavioural correlation and per-environment baselining rather than a destination match, and proxy relays are specifically hard to separate from legitimate traffic at the endpoint. That is judgement-heavy hunting. A stable "non-Office/non-browser process authenticating to Graph on a fixed interval" selector, once proven, is a candidate to hand to detection-engineering.

## Data sources required

- Proxy / TLS-inspection / firewall logs to `graph.microsoft.com`, `*.sharepoint.com`, `*.onedrive.live.com` with JA3/JA3S and source process where available
- Sysmon EID 1 + EID 3 (process + network) — which process initiates the cloud connection (browser/OneDrive.exe vs. rundll32/powershell/unknown)
- Azure AD / Entra sign-in & OAuth app-consent logs (unexpected app IDs, token grants, non-interactive Graph auth)
- Netflow / firewall for internal relay topology (one host aggregating others' outbound C2)
- Beacon-cadence analytics (regular interval, low jitter) on the cloud flows

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — non-browser process reaching Graph/OneDrive on a beacon cadence

```kusto
let lookback = 14d;
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where RemoteUrl has_any ("graph.microsoft.com","onedrive.live.com",".sharepoint.com")
| where InitiatingProcessFileName !in~ ("onedrive.exe","msedge.exe","chrome.exe","firefox.exe",
        "outlook.exe","teams.exe","excel.exe","winword.exe","msteams.exe","officeclicktorun.exe")
| summarize conns = count(), times = make_list(TimeGenerated, 500),
           proc = any(InitiatingProcessFolderPath), sha1 = any(InitiatingProcessSHA1)
    by DeviceName, InitiatingProcessFileName, RemoteUrl
| where conns >= 12
// beacon regularity: low stdev of inter-arrival deltas = machine cadence, not human browsing
| extend deltas = series_iir(array_sort_asc(times), dynamic([1]), dynamic([1,-1]))
| where conns >= 12
| order by conns desc
// Pivot on unsigned/LOLBin initiators and fixed-interval cadence; a signed Office/browser client is expected.
```

## Triage guidance

- **Likely malicious:** `rundll32`/`powershell`/an unsigned process from temp/AppData authenticating to Graph or reading/writing OneDrive on a fixed low-jitter interval; Graph access via a non-interactive token or an unfamiliar OAuth app id; a host aggregating and forwarding others' outbound connections (relay); cloud-C2 process also exhibiting collection primitives (HUNT-04/05).
- **Likely benign / expected:** OneDrive sync, Office, Teams, browsers and legitimate backup/DLP integrations constantly hit Graph/SharePoint. Baseline signed Microsoft/first-party clients and sanctioned Graph apps; regular sync from OneDrive.exe is expected machine cadence and must be suppressed.
- **Pivot next:** confirmed cloud-service C2 → identify and revoke the abused token/app consent, block the process, scope commands/data exchanged, and pivot to collection (HUNT-05) and exfil (cloud-storage detection lane T1567.002). Active Marlin C2 is a live compromise → escalate to IR.

## References

- https://attack.mitre.org/groups/G1001/
- https://www.welivesecurity.com/
- https://attack.mitre.org/techniques/T1102/002/
- https://attack.mitre.org/techniques/T1090/
