# Hunt: POLONIUM — cloud-service C2 via rogue OAuth apps & AES-encrypted tasking files

- **Hypothesis:** POLONIUM hides C2 inside legitimate cloud services, so the wire looks like normal OneDrive/Dropbox/Mega traffic and, for MegaCreep, the payload is AES-opaque. If the group is here, the tell is a *relationship mismatch*: a non-browser, non-sync process (PowerShell, an unsigned .NET binary, InstallUtil-spawned) reading and writing small tasking files (`data.txt`, `cd.txt`, `response.json`) in a cloud store, authenticating to a **rogue OAuth application** that was consented in our tenant with an embedded refresh token, and beaconing on a fixed cadence. Content is encrypted and useless — the finding is the *process-to-cloud-app-to-tasking-file* correlation, not the bytes.
- **ATT&CK:**
  - T1583.006 — Acquire Infrastructure: Web Services (resource-development) — 20+ malicious OneDrive OAuth apps and abused Dropbox/Mega accounts; hunt anomalous tenant OAuth-app consents and their token use.
  - T1573.001 — Encrypted Channel: Symmetric Cryptography (command-and-control) — MegaCreep AES-encrypts commands stored in Mega; hunt the host process + Mega destination since content is opaque.

- **Actor procedure:** POLONIUM stood up **20+ malicious OneDrive applications**, embedding **OAuth refresh tokens** directly in CreepyDrive/CreepyBox/DeepCreep so C2 flows only to legitimate `graph.microsoft.com` / Dropbox / Mega endpoints. Tasking is a **file drop**: commands land in `data.txt`/`cd.txt` in the cloud directory and results are written to `response.json`. **MegaCreep** additionally **AES-encrypts** its command/response channel stored in Mega, so payload inspection yields nothing. Because the implant carries its own token, there is no interactive OAuth consent at run time — the consent happened earlier and is the durable tenant-side artifact.
- **Why a hunt, not a rule:** Cloud sync clients read and write these services all day, and encrypted blobs are normal — an alert on "process talks to graph.microsoft.com" or "AES traffic to Mega" is unmanageable. The signal only exists when you correlate three weak facts on one host: a *non-sync* process making cloud-API calls, a *rogue/over-permissioned OAuth app* in the tenant audit, and *tasking-file* naming/access patterns — plus a beacon cadence. That multi-source fusion is hunt work. A durable piece — a specific rogue app's client ID or a PowerShell-to-Graph relationship (Level-3/4 relational observable) — can be handed to detection-engineering once confirmed.

## Data sources required

- Entra ID / Azure AD audit: OAuth application consents, service-principal creation, refresh-token grants; app publisher/verified-publisher status and requested scopes
- EDR process + network telemetry: which process image initiated the connection to graph.microsoft.com / dropbox / mega (browser & sync-client vs PowerShell / unsigned .NET / InstallUtil)
- Cloud/CASB audit of file operations on tasking-file names (`data.txt`, `cd.txt`, `response.json`) and small periodic read/write pairs
- Proxy/NetFlow for beacon-cadence analysis (regular-interval small transfers to cloud endpoints)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR + Entra audit)`

```kusto
// (a) rogue / anomalous OAuth app consents — recent, over-permissioned, unverified publisher
let suspectApps = AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName in ("Consent to application","Add OAuth2PermissionGrant","Add service principal")
| mv-expand td = TargetResources
| extend appName = tostring(td.displayName)
| where AdditionalDetails !has "verified"          // no verified publisher
| project consentTime = TimeGenerated, appName, InitiatedBy;
// (b) non-sync process making cloud-API calls (the on-host half)
let cloudProc = DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| where RemoteUrl has_any ("graph.microsoft.com","content.dropboxapi.com","api.mega.co.nz","g.api.mega.co.nz")
| where InitiatingProcessFileName has_any ("powershell.exe","InstallUtil.exe")
     or (InitiatingProcessFileName endswith ".exe"
         and InitiatingProcessFileName !in ("OneDrive.exe","Dropbox.exe","msedge.exe","chrome.exe","firefox.exe"))
| summarize hits=count(), urls=make_set(RemoteUrl,10),
            first=min(TimeGenerated), last=max(TimeGenerated)
         by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName;
cloudProc
| extend beaconing = (last - first) > 1h and hits > 20   // sustained periodic contact
| join kind=leftouter (suspectApps) on $left.DeviceName == $right.appName
| order by hits desc
```

## Triage guidance

- **Likely malicious:** PowerShell or an unsigned/masqueraded .NET binary (Mega.exe, DropBox.exe, OnDrive.exe) making Graph/Dropbox/Mega API calls on a fixed cadence, reading `data.txt`/`cd.txt` and writing `response.json`; a rogue OneDrive OAuth app consented by a non-admin user with mail/files scopes and no verified publisher, whose refresh token is used from an endpoint rather than a browser; AES/opaque traffic to Mega from a process that is not the Mega desktop client.
- **Likely benign / expected:** the genuine OneDrive/Dropbox/Mega sync clients and browsers (exclude by signed image + path); IT-approved cloud-backup or DLP tooling using Graph with a verified publisher and documented scopes; developers scripting Graph with a registered internal app. A cloud-API call alone is thin — the non-sync process AND rogue-app AND tasking-file naming stacked together is the finding.
- **Pivot next:** on a stack, dump the process tree (was it InstallUtil-launched DeepCreep? — detection pack T1218.004), pull the tasking-file contents from cloud audit, revoke the rogue app's consent and refresh tokens, and hunt the same host for staging/exfil (HUNT-06) and discovery bursts (HUNT-05). A confirmed rogue app + on-host token use is a live compromise — escalate to incident-response-coordinator.

## References

- https://www.microsoft.com/en-us/security/blog/2022/06/02/exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/
- https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/
- https://attack.mitre.org/techniques/T1583/006/
- https://attack.mitre.org/techniques/T1573/001/
