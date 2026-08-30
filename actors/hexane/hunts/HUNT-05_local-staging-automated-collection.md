# Hunt: HEXANE local data staging & automated collection (pre-exfil bulk file activity)

- **Hypothesis:** If a HEXANE implant (DanBot / Milan) is automatically harvesting files on one of our hosts ahead of exfiltration, then before the data leaves we should see the staging footprint — a single non-interactive process performing a bulk, breadth-first read sweep across user document/share paths in a short window, then concentrating the output into a staging directory (temp/AppData/ProgramData or a hidden folder), disproportionate to any human workflow. The finding is the *automation shape* — read fan-out + write concentration by one process — not the mere presence of files in temp.
- **ATT&CK:**
  - T1119 — Automated Collection (collection)
  - T1074.001 — Data Staged: Local Data Staging (collection)

- **Actor procedure:** HEXANE's implants automatically collect files and system data of interest from compromised hosts and stage the collected data locally prior to exfiltration over the DNS/HTTP C2 channel. Automated collection lets a single implant sweep many documents without operator interaction; local staging consolidates them for chunked exfil.
- **Why a hunt, not a rule:** Files land in temp/AppData constantly (installers, browsers, Office autosave, sync clients) and bulk reads happen legitimately (backup agents, indexers, AV scans, search). A rule on "process touched many files" or "file written to temp" is pure noise. The discriminating signal is relational and statistical — one process reading *far* more distinct files across user-data paths than its own/peer baseline, then writing a concentrated staging set — which needs per-process baselining and analyst judgement, not a static threshold. If a specific implant staging path/shape proves stable, hand that selector to detection-engineering.

## Data sources required

- EDR/Sysmon EID 11 (file create) + file-read/open telemetry with initiating process
- Sysmon EID 1 process lineage + signature (is the collector unsigned / oddly parented?)
- Baseline of normal per-process file-access breadth (backup/indexer/AV allowlist)
- Staging-directory candidates — temp, AppData, ProgramData, hidden/recently-created folders
- Correlation to outbound C2 (files staged then a beacon/upload — HUNT-07/HUNT-08)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — bulk read fan-out + write concentration by one process

```kusto
let lookback = 14d;
let userdata = dynamic([@"\documents\", @"\desktop\", @"\downloads\", "\\\\", @"\share"]);
DeviceFileEvents
| where TimeGenerated > ago(lookback)
| where ActionType in ("FileCreated","FileModified")
| where tolower(FolderPath) has_any (userdata)
| summarize distinctReads = dcount(FileName), paths = dcount(FolderPath),
           span = datetime_diff("minute", max(TimeGenerated), min(TimeGenerated)),
           stageDir = make_set(iff(FolderPath has_any (@"\temp\",@"\appdata\",@"\programdata\"), FolderPath, ""), 10)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA1, InitiatingProcessFolderPath
| where distinctReads >= 200 and span <= 60           // ~200+ files in <1h = automation, not a human
| where InitiatingProcessFolderPath has_any (@"\temp\", @"\appdata\", @"\programdata\")
       or InitiatingProcessFileName in~ ("powershell.exe","wscript.exe","cscript.exe","rundll32.exe")
| order by distinctReads desc
```

## Triage guidance

- **Likely malicious:** an unsigned or LOLBin process (powershell/wscript/rundll32) reading hundreds of documents across user/share paths in minutes and depositing a concentrated set into a hidden/temp staging folder; staging immediately followed by an outbound beacon or archive; collection breadth wildly exceeding that user's normal activity.
- **Likely benign / expected:** backup agents, desktop search/indexers, AV/EDR scans, cloud-sync clients (OneDrive/Dropbox) and migration tools legitimately read many files fast. Baseline and allowlist these by signed publisher and known path; a human editing a handful of files is normal.
- **Pivot next:** confirmed automated staging → identify and preserve the staging set, trace the exfil path (HUNT-07 cloud web-service / HUNT-08 encrypted C2), scope which data was collected, and escalate to IR — active collection staging means exfil is imminent or underway.

## References

- https://www.secureworks.com/research/lyceum-takes-center-stage-in-middle-east-campaign
- https://attack.mitre.org/techniques/T1119/
- https://attack.mitre.org/techniques/T1074/001/
