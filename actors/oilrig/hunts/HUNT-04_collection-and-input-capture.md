# Hunt: OilRig collection & input capture (automated collection, clipboard, screenshots, keylogging, local files)

- **Hypothesis:** If OilRig has established an interactive foothold, then a single host will show a *cluster* of collection behaviors — an infostealer/backdoor process that reads many user documents in a short window (automated collection), captures the clipboard, grabs screenshots, hooks keystrokes, and uploads files via PowerShell — that a normal user process would not exhibit together.
- **ATT&CK:**
  - T1119 — Automated Collection (collection)
  - T1115 — Clipboard Data (collection)
  - T1113 — Screen Capture (collection)
  - T1056.001 — Input Capture: Keylogging (credential-access)
  - T1005 — Data from Local System (collection)
- **Actor procedure:** OilRig uses **automated collection**, **infostealer tools to copy clipboard data**, the **CANDYKING** tool to screenshot the desktop, the **KEYPUNCH** and **LONGWATCH** keyloggers, and **PowerShell to upload files** collected from compromised systems.
- **Why a hunt, not a rule:** clipboard, screen-capture and keystroke-hook APIs leave little discrete log signal and automated collection blends with normal document use; there is no reliable single event. The hunt keys on the *co-occurrence* of collection behaviors on one host plus anomalous process-lineage (a non-Office/non-browser process touching Documents, Desktop and browser profiles), which needs EDR behavioral telemetry and baselining — not a fixed alert.

## Data sources required

- EDR behavioral telemetry (clipboard/GetAsyncKeyState/SetWindowsHookEx, BitBlt/GDI screen-capture, bulk file-read events)
- Sysmon EID 11 (file create/write) + EID 1 (process create) for stager/uploader processes
- PowerShell 4104 script-block logging (`Get-Content`, `Invoke-WebRequest`/`Invoke-RestMethod` upload patterns)

## Query starting point

Platform: `KQL/Sentinel`

```
let window = 30m;
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType in ("ClipboardData","ScreenshotTaken","KeyloggingDetected","GetAsyncKeyState")
   or (ActionType == "FileAccessed" and FolderPath has_any (@"\Documents", @"\Desktop", @"\Downloads"))
| summarize behaviors=make_set(ActionType), file_reads=countif(ActionType=="FileAccessed"),
          distinct_behaviors=dcount(ActionType)
  by DeviceId, InitiatingProcessFileName, bin(Timestamp, window)
| where distinct_behaviors >= 2 or file_reads > 100
| where InitiatingProcessFileName !in~ ("winword.exe","excel.exe","chrome.exe","msedge.exe","explorer.exe","onedrive.exe")
| order by distinct_behaviors desc, file_reads desc
```

## Triage guidance

- **Likely malicious:** an unsigned or oddly-pathed process (e.g. from `\ProgramData` or `%TEMP%`) that both screenshots and hooks keystrokes; bulk reads of Documents/Desktop by a non-Office process followed by a PowerShell upload; clipboard reads by a background process with no UI.
- **Likely benign / expected:** RMM/support tools, screen-recording/DLP agents, password managers and clipboard managers, backup agents doing bulk reads. Enumerate and allowlist by signed publisher + process.
- **Pivot next:** identify the collecting process → tie to macro/CHM lineage (HUNT-09) and staging (HUNT-05); check for outbound upload/C2 (HUNT-01); if exfil confirmed, escalate to IR.

## References

- https://attack.mitre.org/groups/G0049/
