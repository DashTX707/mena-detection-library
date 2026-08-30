# Hunt: Cavern Manticore — tooling acquisition & payload staging (FRP / GitHub dead-drop)

- **Hypothesis:** If Cavern Manticore is operating in our environment, then their reliance on *publicly-obtained tooling staged on off-victim dead-drops* will show up on-host as **PowerShell download cradles reaching out to their staging infrastructure — a GitHub account (`protections20`) and payload-hosting domains (`service-management.tk`) — pulling named archives** (`pxy.zip`, `pxy.rar`, `23.zip`, `netscan_portable_v621.zip`, `rsf.exe`) that unpack into their toolset: FRPC (masqueraded as `audio.exe`), Plink, Ngrok, Procdump, SoftPerfect netscan, and Impacket. The tool *acquisition* and *upload/staging* are off-victim, but the *retrieval* is on-victim and correlatable: a web/exploit process → PowerShell `WebClient.DownloadFile` → archive write → extraction → masquerade-named binary execution with tunneling behavior. The finding is that chain, not any single download.
- **ATT&CK:**
  - T1588.002 — Obtain Capabilities: Tool (resource-development) — the actor acquires FRPC/Plink/Ngrok/Procdump/Impacket/DiskCryptor/netscan; the hunt catches the downstream retrieval+execution of exactly this named toolset.
  - T1608.001 — Stage Capabilities: Upload Malware (resource-development) — payloads staged on GitHub `protections20` and `service-management.tk`; the hunt catches pulls from those dead-drops onto our hosts.
  - T1105 — Ingress Tool Transfer (command-and-control) — cross-referenced: the on-victim retrieval mechanism (PowerShell WebClient cradle writing the staged archives) is where the off-victim staging becomes visible.
  - T1036.005 — Masquerading: Match Legitimate Resource Name or Location (defense-evasion) — cross-referenced: FRPC as `audio.exe`, payloads as `dllhost.exe`/`task_update.exe`/`user.exe`/`CacheTask` — name/path mismatch is a corroborating tell.

- **Actor procedure:** Cavern Manticore operationalizes off-the-shelf tools rather than bespoke malware. They stage these on a GitHub account (`protections20`) and on actor domains (`service-management.tk`), then pull them onto victims via PowerShell `System.Net.WebClient` cradles. Observed staged artifacts: `pxy.zip`, `pxy.rar`, `23.zip`, `rsf.exe`, `netscan_portable_v621.zip`. The unpacked toolset: **FRPC** for reverse-proxy tunneling (dropped as `audio.exe`, config file alongside), **Plink** and **Ngrok** for RDP tunneling, **Procdump** and **comsvcs.dll MiniDump** for LSASS, **SoftPerfect Network Scanner** (`netscan`/`netscanold.exe`) for internal recon, and **Impacket wmiexec** for remote execution. Payloads masquerade as `dllhost.exe`, `task_update.exe`, `user.exe`, `CacheTask`.
- **Why a hunt, not a rule:** Tool acquisition (T1588.002) and dead-drop upload (T1608.001) both happen entirely off-victim — on the actor's laptop and on GitHub/their domains — so there is literally nothing on our telemetry to alert on for those two techniques directly. Their *only* on-victim shadow is the retrieval-and-run chain, and each link is individually noisy: PowerShell reaches the internet constantly, GitHub is a legitimate developer destination, and `audio.exe` is usually benign. The finding is the *stacked correlation* — a server-context or exploit-spawned PowerShell pulling a named archive from a dead-drop that extracts to a masquerade-named tunneling binary — which requires joining process lineage + download source + file write + name/path mismatch. That fusion is hunt work. Where a link is precise enough (FRPC config-file write, `comsvcs.dll,MiniDump` command line, `\\127.0.0.1\ADMIN$\<epoch>` wmiexec artifact), a scoped analytic already lives in the detection pack (T1572/T1218.011/T1047) — hand any new durable one there.

## Data sources required

- PowerShell script-block & module logging (EID 4104) — `System.Net.WebClient`, `DownloadFile`/`DownloadString`, encoded cradles; and the parent process (Tomcat/Exchange/web)
- Process-creation telemetry (Sysmon EID 1 / `DeviceProcessEvents`) with full command line + parent lineage + image hash/signature
- File-write telemetry (`DeviceFileEvents`) for the named archives and for FRPC config files; archive-extraction events
- Proxy/DNS logs for GitHub (`raw.githubusercontent.com/*protections20*`) and `service-management.tk` retrievals
- Binary metadata for masquerade detection: signer vs. filename vs. path (e.g. `audio.exe` that is actually FRPC; `dllhost.exe` outside `System32`)

## Query starting point

Platform: `Microsoft Defender for Endpoint (KQL advanced hunting)` — the download-cradle → staged-archive → masquerade-binary chain

```kusto
let deadDrops = dynamic(["protections20","service-management.tk","raw.githubusercontent.com"]);
let stagedArtifacts = dynamic(["pxy.zip","pxy.rar","23.zip","rsf.exe",
    "netscan_portable_v621.zip","netscanold.exe"]);
let masqueradeNames = dynamic(["audio.exe","task_update.exe","user.exe","CacheTask.exe","dllhost.exe"]);
// (a) PowerShell / process pulling from a dead-drop
let cradle = DeviceProcessEvents
    | where TimeGenerated > ago(30d)
    | where ProcessCommandLine has_any ("WebClient","DownloadFile","DownloadString","Invoke-WebRequest","curl","certutil")
         and ProcessCommandLine has_any (deadDrops)
    | project cradleTime = TimeGenerated, DeviceName, ProcessCommandLine,
              parent = InitiatingProcessFileName, InitiatingProcessAccountName;
// (b) staged archive written, or masquerade-named tunneling binary executed
let dropped = union
    (DeviceFileEvents | where FileName has_any (stagedArtifacts)
        | project dropTime = TimeGenerated, DeviceName, evidence = strcat("file:",FileName), FolderPath),
    (DeviceProcessEvents | where FileName in (masqueradeNames)
        // masquerade: FRPC-as-audio.exe / dllhost.exe outside System32 / config file alongside
        and (FolderPath !has @"\Windows\System32" and FolderPath !has @"\Windows\SysWOW64")
        | project dropTime = TimeGenerated, DeviceName, evidence = strcat("proc:",FileName,"|",ProcessCommandLine), FolderPath);
cradle
| join kind=inner (dropped) on DeviceName
| where abs(datetime_diff('minute', dropTime, cradleTime)) <= 120   // retrieval and drop time-clustered
| project DeviceName, cradleTime, parent, InitiatingProcessAccountName, ProcessCommandLine, dropTime, evidence, FolderPath
| order by cradleTime asc
```

## Triage guidance

- **Likely malicious:** a PowerShell cradle whose *parent* is `ws_TomcatService.exe`/`w3wp.exe`/an exploit process pulling `pxy.zip`/`netscan_portable_v621.zip` from `protections20` or `service-management.tk`, followed by an `audio.exe` (FRPC) or `dllhost.exe` executing *outside* System32 with an FRPC config file alongside and an outbound tunnel; SoftPerfect netscan run on a server; the `\\127.0.0.1\ADMIN$\<epoch>` wmiexec artifact appearing near the drop.
- **Likely benign / expected:** developers and CI agents legitimately pull from `raw.githubusercontent.com` — scope GitHub hits to the `protections20` account and to non-developer hosts (a domain controller or Exchange server pulling from GitHub is not normal); a genuine, System32-resident, Microsoft-signed `audio.exe`/`dllhost.exe` is fine — the mismatch (wrong path, wrong signer, FRPC behavior) is the tell; admins do run Plink/PsExec-family tools, so pair with parent lineage and staging source before calling it.
- **Pivot next:** if the chain confirms, pivot to the tunneling hunt and network telemetry — FRPC/Plink/Ngrok outbound to actor IPs (detection pack T1572/T1090), the config file's server address (a *new* actor IP to add to HUNT-03's watchlist), and the internal RDP subnet sweep (T1046) that netscan feeds. Confirmed tooling retrieval on a server is an active intrusion — escalate to incident-response-coordinator and back-hunt the foothold (T1190/T1505.003) and credential access (T1003.001). Feed the dead-drop URL and any new staged-archive hash to detection-engineering/TI.

## References

- https://www.sentinelone.com/labs/log4j2-in-the-wild-iranian-aligned-threat-actor-tunnelvision-actively-exploiting-vmware-horizon/
- https://www.secureworks.com/blog/cobalt-mirage-conducts-ransomware-operations-in-us
- https://www.microsoft.com/en-us/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
- https://attack.mitre.org/techniques/T1588/002/
- https://attack.mitre.org/techniques/T1608/001/
- https://attack.mitre.org/techniques/T1105/
- https://attack.mitre.org/techniques/T1036/005/
