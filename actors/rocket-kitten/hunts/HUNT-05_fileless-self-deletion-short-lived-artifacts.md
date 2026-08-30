# Hunt: Rocket Kitten — in-memory payloads and self-deleting on-host artifacts

- **Hypothesis:** If Rocket Kitten malware ran on one of our hosts but wiped itself, then the durable tell is not the payload file (it's gone) but the *scar tissue* of a short-lived executable: a file created in `%TEMP%`/Downloads and deleted minutes later, whose brief lifetime overlaps a process-execution and/or an outbound C2/FTP connection, leaving execution evidence (Prefetch, Amcache, SRUM, EDR process events, image-load) that outlives the file itself. A lone create-then-delete is normal churn; the finding is a self-deleting binary that *executed and communicated* before removal, on a targeted user's host.
- **ATT&CK:**
  - T1070.004 — Indicator Removal: File Deletion (defense-impairment) — some Rocket Kitten payloads load in memory and erase themselves from disk after execution to defeat forensic recovery.

- **Actor procedure:** Per Trend Micro's *Spy Kittens Are Back*, some Rocket Kitten malware places its payload in memory and then erases the on-disk traces after execution to hinder forensic recovery. This sits atop their broader %TEMP%-centric tradecraft (droppers, keylogger, `wsc.vbs`, `NTSuser.exe`), so a self-deleting binary here typically bracketed a real infection chain — a dropper that removed itself after loading the GHOLE/CWoolger stage, or a stage that ran in memory and cleaned up. Because the group otherwise leaves distinctive persistence and keylog artifacts, the deletion is a *gap* to reconstruct around, not a dead end.

- **Why a hunt, not a rule:** Files are created and deleted in `%TEMP%` constantly — installers, updaters, browsers and Office all self-clean, so "a file was deleted" is one of the noisiest possible signals and unfit for a standalone alert. The finding only emerges by *reconstructing the missing artifact* from surviving execution evidence: correlating the short lifetime against process creation, image loads, Prefetch/Amcache execution records, and any concurrent network egress — a multi-source forensic join with heavy benign-churn suppression that is inherently analyst work. If a precise, low-FP relationship surfaces (e.g. an unsigned `%TEMP%` PE that executed, opened a socket, then self-deleted within N minutes with no installer parentage), that scoped correlation can be handed to detection-engineering; the raw deletion cannot.

## Data sources required

- EDR file events with create *and* delete (`DeviceFileEvents` FileCreated/FileDeleted) plus process-creation and image-load telemetry (`DeviceProcessEvents`, `DeviceImageLoadEvents`).
- Windows execution-evidence artifacts that survive file deletion — Prefetch, Amcache, SRUM, ShimCache, `4688` process-creation with command line.
- Network connection telemetry (`DeviceNetworkEvents`) to correlate a short-lived binary with outbound C2/FTP (cross-ref detection-lane GHOLE beacon / FTP exfil IOCs).
- Host-integrity / AMSI / script-block logs for in-memory (fileless) loads that leave no PE on disk at all.

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — find executables that were created, ran, communicated, then self-deleted within a short window.

```kusto
let lifespanMinutes = 30;
let created =
    DeviceFileEvents
    | where TimeGenerated > ago(21d)
    | where ActionType == "FileCreated"
    | where FolderPath has_any ("\\Temp\\","\\Downloads\\","\\AppData\\Local\\Temp\\")
    | where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".scr"
    | project DeviceName, FileName, FolderPath, SHA1, createTime = TimeGenerated,
              creator = InitiatingProcessFileName;
let deleted =
    DeviceFileEvents
    | where TimeGenerated > ago(21d)
    | where ActionType == "FileDeleted"
    | project DeviceName, FileName, FolderPath, deleteTime = TimeGenerated,
              deleter = InitiatingProcessFileName;
created
| join kind=inner deleted on DeviceName, FileName, FolderPath
| where deleteTime between (createTime .. createTime + lifespanMinutes*1m)
// require evidence it actually RAN and/or talked out before vanishing
| join kind=leftouter (
    DeviceProcessEvents | project DeviceName, ranImage = FileName, procTime = TimeGenerated, InitiatingProcessFileName )
    on DeviceName
| where procTime between (createTime .. deleteTime) and ranImage =~ FileName
| join kind=leftouter (
    DeviceNetworkEvents | where RemoteIPType == "Public"
    | project DeviceName, RemoteIP, RemoteUrl, netTime = TimeGenerated )
    on DeviceName
| where isnotempty(RemoteIP) and netTime between (createTime .. deleteTime + 5m)
| project DeviceName, FileName, FolderPath, SHA1, creator, createTime, deleteTime, RemoteIP, RemoteUrl
| order by createTime asc
// suppress: creator/deleter in known installers/updaters (msiexec, setup, *_updater, onedrive)
```

## Triage guidance

- **Likely malicious:** an unsigned executable dropped in `%TEMP%` by Office/script/browser, which executed and opened an outbound connection (bonus: to a GHOLE/FTP C2 range from the detection pack) and then self-deleted within minutes with no installer parentage; a fileless in-memory load (AMSI/script-block evidence) with Prefetch/Amcache execution records but no surviving PE; deletion clustered with other Rocket Kitten artifacts on the same host (`wsc.vbs`, `NTSuser.exe`, `WinDefender` startup .lnk).
- **Likely benign / expected:** software installers, auto-updaters, browsers and Office routinely create and delete `%TEMP%` binaries — suppress by trusted creator/deleter process, valid code signature and known update infrastructure; CI/build agents and packagers generate high create/delete churn; a create-then-delete with *no* execution and *no* egress is churn, not a finding.
- **Pivot next:** reconstruct the deleted file from Amcache/Prefetch/SRUM and, if recoverable, hash it against the detection-lane sample set (GHOLE/CWoolger); sweep the host for the actor's persistence and keylog artifacts even though the dropper is gone; if execution + egress is confirmed, treat as a live compromise with anti-forensics → escalate to incident-response-coordinator and preserve volatile memory before reimaging.

## References

- https://documents.trendmicro.com/assets/wp/wp-the-spy-kittens-are-back.pdf
- https://attack.mitre.org/techniques/T1070/004/
