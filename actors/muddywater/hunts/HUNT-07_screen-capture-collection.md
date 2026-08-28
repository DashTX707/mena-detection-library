# Hunt: Screen capture / collection by POWERSTATS

- **Hypothesis:** If MuddyWater is running hands-on collection on a host, then POWERSTATS-style screen capture will leave indirect traces — periodic small image files written to temp/appdata, PowerShell using screen-capture APIs, or an unusual process with sustained GDI/`CopyFromScreen` activity — rather than any single high-fidelity log event.
- **ATT&CK:**
  - T1113 — Screen Capture (collection)
- **Actor procedure:** MuddyWater has used malware (POWERSTATS) that can **capture screenshots** of the victim's machine.
- **Why a hunt, not a rule:** Screen-capture APIs (`System.Drawing`, `CopyFromScreen`, GDI `BitBlt`) are used by countless legitimate tools (screenshot utilities, RMM, conferencing, screen recorders) and leave almost no discrete log event. There is no reliable single-event signature — detection requires behavioral EDR correlation and per-host baselining of who legitimately captures the screen, i.e. a hunt.

## Data sources required

- PowerShell 4104 script-block logging (`.CopyFromScreen`, `System.Drawing`, `[System.Windows.Forms.Screen]`, `Bitmap`)
- Sysmon EID 11 (periodic small `.png`/`.jpg`/`.bmp` writes to `%temp%`/`%appdata%`)
- EDR API-telemetry (GDI screen-capture calls by unexpected processes)

## Query starting point

Platform: `KQL/Sentinel`

```kql
// A. PowerShell screen-capture API usage
let apihits = union isfuzzy=true
  (DeviceEvents
    | where ActionType == "PowerShellCommand" or InitiatingProcessCommandLine has "CopyFromScreen"
    | where InitiatingProcessCommandLine has_any ("CopyFromScreen","System.Drawing","Screen]::","Bitmap","BitBlt")
    | project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine);
apihits
| union (
  // B. cadence of small image writes to user-writable paths (capture loop)
  DeviceFileEvents
  | where FolderPath has_any (@"\Temp\",@"\AppData\")
  | where FileName endswith ".png" or FileName endswith ".jpg" or FileName endswith ".bmp"
  | summarize shots=count(), by DeviceName, InitiatingProcessFileName, bin(TimeGenerated,10m)
  | where shots >= 3
)
```

## Triage guidance

- **Likely malicious:** PowerShell invoking `CopyFromScreen`/`BitBlt`; a regular cadence of small image files written by a script interpreter or unknown binary; screen-capture activity on a server or headless host; capture correlated with active C2/collection on the same host.
- **Likely benign / expected:** Snipping Tool, ShareX/Greenshot, Teams/Zoom screen share, RMM screen-view sessions, screen recorders. Enumerate and allowlist sanctioned capture tools per host role.
- **Pivot next:** Where do the captured images go (→ HUNT-06 exfil, HUNT-05 C2)? What is the capturing process's lineage (→ HUNT-01)? If tied to active C2, escalate to IR.

## References

- https://attack.mitre.org/groups/G0069/
