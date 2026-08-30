# Hunt: Infy (Prince of Persia) — peripheral & clipboard collection correlated with keylog/staging

- **Hypothesis:** Infy/Tonnerre are surveillance implants that harvest *everything the target touches* — including the clipboard (Foudre captures it on a ~10-second cycle alongside keylogging) and files from **external/removable devices** (Tonnerre steals from attached drives; Infy enumerates drives during recon). Clipboard reads and removable-media enumeration are individually invisible API noise, so the hunt keys on the *collection stack*: a single non-media process that (a) reacts to removable-volume arrival by enumerating and reading files from the new drive, and/or (b) reads the clipboard on a fixed short cycle, *and* is the same process writing a keystroke-log artifact and staging collected data into a password-protected archive. The falsifiable pattern is a removable-volume insert (or a periodic clipboard-read cadence) tied to the *same* process lineage that produces keylog/staging artifacts — not one drive read in isolation.
- **ATT&CK:**
  - T1120 — Peripheral Device Discovery (discovery) — Tonnerre enumerates attached/removable devices to locate and steal files from them; Infy enumerates drives during recon; hunt via removable-volume-arrival correlated with same-process file reads from the new volume.
  - T1115 — Clipboard Data (collection) — Foudre captures the clipboard on a ~10-second cycle alongside keylogging; Infy harvests clipboard contents; hunt via fixed-cadence clipboard reads correlated with keylog artifacts.
  - T1056.001 — Keylogging (collection) — *context/corroborator*: the keystroke-log artifact (Infy window `TRON2VDLLB`) written by the same process anchors the clipboard/peripheral reads as collection, not benign use. (Detection-lane technique; cited as the correlating artifact.)
  - T1074.001 — Local Data Staging (collection) — *context*: collected clipboard/keylog/removable-media data is compressed into a password-protected archive (`Z8(2000_2001uI)`) before egress. (Detection-lane technique; cited as the staging tell that closes the loop.)

- **Actor procedure:** Infy harvests clipboard contents and keystrokes (keylogger under window `TRON2VDLLB`, with language identification); Foudre keylogs on a cycle with **periodic clipboard capture (~10 s)**; Tonnerre keylogs on machines of interest, records audio, captures the screen, and **steals files from predefined folders and from external/removable devices**, enumerating attached peripherals to find data of interest. Collected data is compressed locally into password-protected archives (Infy document-capture password `Z8(2000_2001uI)`; SFX/decode key `1qaz2wsx3edc`) prior to exfiltration over HTTP POST or command-directed FTP. The collection is automated and continuous — the same implant process quietly reads the clipboard, watches for removable media, logs keystrokes and rolls the results into an archive.
- **Why a hunt, not a rule:** Clipboard access (`GetClipboardData`) and drive/volume enumeration (`GetLogicalDrives`, `WM_DEVICECHANGE`) are extremely common benign operations — clipboard managers, sync clients, backup and DLP agents all do them constantly, so a standalone alert is pure noise and there is little discrete log footprint (why this is a hunt lane). The signal only appears when these reads are *correlated by shared process lineage* with a keystroke-log write and a staging archive — the collection loop — which is baselining and correlation work, not a single alertable event. If the loop (removable-read or fixed-cadence clipboard-read → keylog write → password-archive by one process) proves cleanly separable from benign tooling, hand that lineage correlation to detection-engineering; the clipboard/drive API on its own is not alertable.

## Data sources required

- EDR / Sysmon: process-lineage (EID 1) + file-write telemetry (Sysmon EID 11) to catch keystroke-log artifacts and password-protected staging archives written by a non-media process.
- Removable-media / device telemetry: Windows-Partition/Ntfs or `Microsoft-Windows-DriverFrameworks-UserMode` events, EDR device-mount events, or Sysmon file events on newly-mounted volume roots (`D:\`, `E:\`…) for volume-arrival + same-process reads.
- EDR API telemetry for clipboard reads / periodic `GetClipboardData` cadence (where instrumented); archive-utility process telemetry (7z/zip/rar command lines with password flags) for the staging corroborator.

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — tie a removable-volume read (or clipboard-cadence process) to the same process's keylog/staging writes.

```kusto
// Processes reading files off a freshly-mounted removable volume...
let periphReads = DeviceFileEvents
    | where Timestamp > ago(21d)
    | where ActionType == "FileAccessed"
    | where FolderPath matches regex @"^[D-Z]:\\" and FolderPath !startswith @"C:\"     // non-system volume roots
    | summarize reads=count(), volset=make_set(FolderPath,10), first=min(Timestamp), last=max(Timestamp)
             by DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessAccountName
    | where reads >= 10;                          // bulk pull off removable media, not a single open
// ...that are the SAME process writing keylog/staging artifacts
let collectStage = DeviceFileEvents
    | where Timestamp > ago(21d)
    | where ActionType in ("FileCreated","FileModified")
    | where FileName matches regex @"(?i)(klog|keylog|\.dat$|\.tmp$|clip)"             // keystroke/clip artifact
          or (FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z")
    | project stageTime=Timestamp, DeviceName, InitiatingProcessId, StagedFile=FileName, StagePath=FolderPath;
periphReads
| join kind=inner (collectStage) on DeviceName, InitiatingProcessId
| where InitiatingProcessFileName !in~ ("explorer.exe","backup.exe","onedrive.exe","dropbox.exe","robocopy.exe")  // baseline
| project first, last, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, reads, volset, StagedFile, StagePath
| order by first desc
```

## Triage guidance

- **Likely malicious:** a single non-media, non-backup process bulk-reads files off a newly-mounted removable/external volume (or reads the clipboard on a tight fixed cadence) and is *the same process* writing a keystroke-log file and rolling data into a password-protected archive — the Infy/Tonnerre collection loop; extra weight if the archive uses the actor password `Z8(2000_2001uI)` (T1560.001/T1074.001), if the lineage traces to a HUNT-03 loader, or if screenshot/audio artifacts (detection-lane T1113/T1123) appear from the same process.
- **Likely benign / expected:** backup/sync/DLP agents, clipboard managers, and media apps legitimately read removable volumes and the clipboard constantly — baseline and exclude those process identities; a user copying files off a USB drive via `explorer.exe`, or a password manager touching the clipboard, is expected. The discriminators are the shared-lineage stack (peripheral/clipboard read *and* keylog write *and* staging archive by one process) and an unknown/unsigned initiating binary.
- **Pivot next:** on a match, capture the staging archive and keylog artifact, trace the initiating process into HUNT-03 (loader/decode) and HUNT-04 (profiling), and follow the staging into egress — HTTP POST to C2 or command-directed FTP to the actor's FTP IPs (detection-lane T1041/T1048.003). A confirmed on-host collection loop targeting a dissident/diplomatic user is active surveillance — escalate to incident-response-coordinator and preserve artifacts for scope/timeline.

## References

- https://unit42.paloaltonetworks.com/prince-of-persia-infy-malware-active-in-decade-of-targeted-attacks/
- https://unit42.paloaltonetworks.com/unit42-prince-persia-ride-lightning-infy-returns-foudre/
- https://research.checkpoint.com/2021/after-lightning-comes-thunder/
- https://attack.mitre.org/techniques/T1120/
- https://attack.mitre.org/techniques/T1115/
- https://attack.mitre.org/techniques/T1056/001/
- https://attack.mitre.org/techniques/T1074/001/
