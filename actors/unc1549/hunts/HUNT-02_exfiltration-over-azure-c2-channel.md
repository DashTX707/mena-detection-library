# Hunt: UNC1549 (TA455) — exfiltration hiding in the same encrypted Azure channel as the beacon

- **Hypothesis:** If UNC1549 is collecting from us (SIGHTGRAB screenshots, CRASHPAD browser creds, SharePoint/Teams pulls, staged documents), then the data leaves over the *same* Azure-hosted C2 the implant already beacons on — so there is no separate exfil destination to blocklist. The observable is a **directional volume asymmetry**: a host that normally receives more than it sends suddenly *uploads* a burst of bytes (screenshots, archives, credential output) to an Azure `*.azurewebsites.net`/`*.cloudapp.azure.com` host that is otherwise a low-chatter beacon. The finding is upload-volume outlier + beacon-host reuse + a preceding collection artefact on the same host — not raw egress volume, which Azure makes meaningless on its own.
- **ATT&CK:**
  - T1041 — Exfiltration Over C2 Channel (exfiltration) — MINIBIKE/TWOSTROKE/DEEPROOT implement file-upload-to-C2; exfil rides the beacon channel and blends with normal cloud egress, so it is hunted volumetrically against the actor domains.
  - T1573 — Encrypted Channel (command-and-control) — the exfil is TLS/443 (TWOSTROKE SSL-TCP, LIGHTRAIL WebSocket), opaque to inspection; we hunt the byte-direction metadata and beacon-host reuse, not the payload.
- **Actor procedure:** UNC1549 collects broadly — SIGHTGRAB periodically writes XOR(0x41) `.jpg` screenshots under `C:\Users\Public\Videos|Music\`, CRASHPAD dumps browser creds to `crash.log` in the VMware VGAuth dir, DEEPROOT hex-encodes `-===-`-delimited payloads, and operators browse Teams/SharePoint for files. All of it is uploaded through the backdoor's file-upload command over the Azure C2. Because it reuses the beacon channel, there is no new IP/domain to catch — the shape of the traffic (a normally-quiet beacon host suddenly sending MBs) is the only network tell.
- **Why a hunt, not a rule:** A byte-count threshold on Azure egress would fire on every OneDrive sync, Teams upload and browser update in the estate. The malicious signal is contextual: the *same* host+destination that shows beacon behaviour also shows an out-of-character upload burst, and a collection artefact exists on disk in the same window. Correlating network direction, beacon-host identity and endpoint collection evidence — and judging "out of character" against that host's own baseline — is analyst work, not a static rule. If a robust pairing emerges (a specific beacon FQDN that also carries upload bursts from a side-loaded process), route it to detection-engineering.

## Data sources required

- Zeek `conn.log` / proxy logs: `orig_bytes` vs `resp_bytes` (send/receive direction) per destination FQDN, per host, over time — to compute per-host upload baselines.
- Passive DNS + the actor-Azure FQDN watchlist (shared with HUNT-01) to scope destinations.
- EDR file-creation telemetry (DeviceFileEvents): SIGHTGRAB `.jpg` under `Users\Public\Videos|Music`, CRASHPAD `crash.log`/`config.txt`, archive staging — the on-disk collection corroborator.
- M365 unified audit log: bulk SharePoint/Teams `FileDownloaded` by unusual principals (collection source that precedes exfil).

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — find upload-direction outliers to beacon hosts, corroborated by a same-host collection artefact

```kusto
let lookback = 14d;
// per-host, per-Azure-destination outbound byte baseline
let egress = DeviceNetworkEvents
    | where TimeGenerated > ago(lookback)
    | where RemoteUrl has_any ("azurewebsites.net","cloudapp.azure.com")
    | extend host = tostring(split(RemoteUrl,"/")[0])
    | summarize sentBytes = sum(tolong(coalesce(column_ifexists("SentBytes","0"),"0"))),
                conns = count() by DeviceName, host, bin(TimeGenerated, 1h);
let stats = egress | summarize mean=avg(sentBytes), sd=stdev(sentBytes) by DeviceName, host;
let bursts = egress
    | join kind=inner stats on DeviceName, host
    | extend z = (sentBytes - mean) / (sd + 1)
    | where z > 3 and sentBytes > 5000000          // >3 sigma over this host's own baseline AND material size
    | project DeviceName, host, burstTime=TimeGenerated, sentBytes, z;
// corroborate: a collection artefact written on the same host within +/- 6h of the burst
let collect = DeviceFileEvents
    | where TimeGenerated > ago(lookback)
    | where (FolderPath has @"\Users\Public\Videos" or FolderPath has @"\Users\Public\Music" and FileName endswith ".jpg")
         or FileName in~ ("crash.log","config.txt","LOG.txt")
    | project DeviceName, artefactTime=TimeGenerated, FileName, FolderPath;
bursts
| join kind=inner collect on DeviceName
| where abs(datetime_diff('hour', burstTime, artefactTime)) <= 6
| order by z desc
```

## Triage guidance

- **Likely malicious:** an upload burst >3σ over a host's own baseline to an Azure host that is otherwise a low-volume beacon (HUNT-01), time-correlated with SIGHTGRAB `.jpg`/CRASHPAD `crash.log` creation or a bulk M365 download by that user; upload destination on the actor-Azure IOC list.
- **Likely benign / expected:** OneDrive/SharePoint sync, Teams file shares, cloud backup, CI/CD artefact pushes and video-conferencing all produce legitimate large Azure uploads — baseline sanctioned sync clients per host; a developer pushing to Azure DevOps is expected. The `crash.log`/`config.txt` filenames are generic — confirm content/path is the VMware VGAuth dir, not a real crash dump.
- **Pivot next:** on a confirmed pairing, hash-and-carve the staged file if still on disk, decrypt SIGHTGRAB with single-byte XOR 0x41 to confirm screenshot content, and pull the uploading process lineage. Reuse of a HUNT-01 beacon FQDN as the exfil sink upgrades both hunts to a confirmed implant — escalate to incident-response-coordinator, preserve the C2 FQDN/JA3 and staged files, and scope all hosts talking to that FQDN.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/analysis-of-unc1549-ttps-targeting-aerospace-defense
- https://attack.mitre.org/techniques/T1041/
- https://attack.mitre.org/techniques/T1573/
