# Hunt: POLONIUM — local collection, clipboard capture & in-process archiving before cloud exfil

- **Hypothesis:** POLONIUM is espionage-focused — it collects documents, keystrokes, screenshots and clipboard contents, then **archives them in-process (library ZIP, no external archiver)** and ships them to cloud storage. If the group is here, the tell is a *stage-then-egress sequence on one host*: bursty local-file reads across document shares and a clipboard capture, followed by creation of an archive file by the *same* process, immediately preceding an upload to OneDrive/Dropbox/Mega. Because the ZIP is built via a code library there is no `7z.exe`/`rar.exe` to catch — the finding is the file-write of an archive by a non-archiver process, time-adjacent to collection and cloud egress.
- **ATT&CK:**
  - T1115 — Clipboard Data (collection) — clipboard contents captured from compromised hosts; hunt clipboard-API use by non-interactive/unsigned processes correlated with staging.
  - T1005 — Data from Local System (collection) — bulk collection of confidential documents; hunt fan-out reads across document paths by one process.
  - T1560.002 — Archive Collected Data: Archive via Library (collection) — in-process ZIP creation (no external archiver); hunt archive-file writes by a non-archiver process before egress.

- **Actor procedure:** POLONIUM's modular tooling **collects files of interest from the local system**, captures **clipboard contents**, keystrokes, screenshots and webcam, and **compresses collected data into ZIP archives via a code library inside the .NET modules** (so no standalone archiver process spawns). The staged archive is then exfiltrated to attacker-controlled **OneDrive/Dropbox/Mega**. The chain is tight: collect → archive-in-process → upload, often from a masqueraded binary (Rehost.exe for exfil, WinSc.exe screenshots, Device.exe webcam).
- **Why a hunt, not a rule:** Users create ZIPs, copy to clipboard and read documents constantly, and in-process archiving produces no archiver process to key on — a rule on "a ZIP was written" or "clipboard was read" is unusable. The finding is the *sequence and lineage*: one process reads many documents, writes an archive, and uploads to cloud within a short window. Reconstructing that chain across file, clipboard and network telemetry is correlation work. If a durable link emerges — e.g., a non-sync process that both writes an archive and uploads it to Graph/Dropbox in one lineage (a Level-3/4 relational observable) — hand it to detection-engineering.

## Data sources required

- EDR / Sysmon file-create + file-access (EID 11 / 4663) for document reads and archive-file writes, with initiating process
- EDR behavioral / API telemetry for clipboard access (OpenClipboard/GetClipboardData) attributed to a process
- Network/cloud upload telemetry (join to HUNT-03: non-sync process uploading to OneDrive/Dropbox/Mega)
- Process lineage to tie collection, archive write and upload to a single parent

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)`

```kusto
// (a) one process reads many documents in a short window (bulk local collection)
let collectors = DeviceFileEvents
| where TimeGenerated > ago(14d)
| where ActionType == "FileAccessed"
| where FileName has_any (".docx",".xlsx",".pdf",".pptx",".txt",".msg",".pst",".dwg")
| summarize docReads = dcount(FolderPath), docs = make_set(FileName, 20),
            tstart = min(TimeGenerated), tend = max(TimeGenerated)
         by DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessAccountName
| where docReads >= 15 and (tend - tstart) < 30m;         // fan-out burst, not routine open
// (b) SAME process writes an archive (in-process ZIP), and it isn't a known archiver
let archives = DeviceFileEvents
| where TimeGenerated > ago(14d)
| where ActionType == "FileCreated"
| where FileName endswith ".zip" or FileName endswith ".dat" or FileName has "archive"
| where InitiatingProcessFileName !in ("7z.exe","7zg.exe","WinRAR.exe","Explorer.EXE","Compress-Archive")
| project DeviceName, InitiatingProcessId, archiveName = FileName,
          archiveFolder = FolderPath, archiveTime = TimeGenerated, InitiatingProcessFileName;
collectors
| join kind=inner (archives) on DeviceName, InitiatingProcessId
// (c) elevate if the same host then uploads to cloud storage (see HUNT-03)
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemoteUrl has_any ("graph.microsoft.com","dropboxapi","mega")
    | where InitiatingProcessFileName !in ("OneDrive.exe","Dropbox.exe","msedge.exe","chrome.exe")
    | distinct DeviceName, uploader = InitiatingProcessFileName
  ) on DeviceName
| order by docReads desc
```

## Triage guidance

- **Likely malicious:** one unsigned/masqueraded process (Rehost.exe, an unknown .NET binary) reading 15+ documents across shares in minutes, writing a ZIP/`.dat`, and the same host uploading to OneDrive/Dropbox/Mega via a non-sync process; clipboard capture plus screenshot/webcam file writes (WinSc.exe/Device.exe) on the same host; an archive written to a user-writable staging path immediately before cloud egress.
- **Likely benign / expected:** backup agents and DLP tools that legitimately read documents in bulk (baseline by signed publisher/role); users zipping a project folder via Explorer/7-Zip and syncing via the real OneDrive/Dropbox client; developers archiving build artifacts. Bulk reads by a *known archiver or backup agent* are expected — by an *unknown, non-archiver* process that then uploads to cloud, they are not.
- **Pivot next:** identify and hash the collecting process; confirm whether the upload is attacker cloud-C2 (HUNT-03) and whether it was InstallUtil-launched (detection pack T1218.004); recover the staged archive to scope stolen data; hunt the same lineage for the encoded beacon (HUNT-05) and persistence. A confirmed collect→archive→cloud-upload chain is active exfiltration — escalate to incident-response-coordinator and preserve the archive for scoping.

## References

- https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/
- https://www.microsoft.com/en-us/security/blog/2022/06/02/exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/
- https://attack.mitre.org/techniques/T1115/
- https://attack.mitre.org/techniques/T1005/
- https://attack.mitre.org/techniques/T1560/002/
