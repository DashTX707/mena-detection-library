# Hunt: Obfuscated payload staging in images/temp and in-memory decode

- **Hypothesis:** If MuddyWater staged a payload on this host, then we should find script/executable content hidden inside a non-script container (e.g. an image such as `temp.jpg`) or dropped as a decoy/staging file in `%temp%`, followed shortly by a decode routine (Base64/`certutil -decode`/`FromBase64String`) executed by a script interpreter that reads that file.
- **ATT&CK:**
  - T1027.003 — Obfuscated Files or Information: Steganography (defense-evasion)
  - T1074.001 — Data Staged: Local Data Staging (collection)
  - T1140 — Deobfuscate/Decode Files or Information (defense-evasion)
- **Actor procedure:** MuddyWater has stored obfuscated JavaScript inside an image file named **`temp.jpg`**, stored a **decoy PDF within the victim's `%temp%` folder**, and decoded Base64-encoded PowerShell, JavaScript and VBScript at runtime.
- **Why a hunt, not a rule:** `%temp%` file writes and Base64 decoding are extremely common (installers, browsers, legitimate scripts all decode data). A payload hidden in a `.jpg` produces almost no discrete log signal on its own — the anomaly only emerges when you correlate *a script interpreter reading an image/temp file and then decoding it*, which needs file-read + script-block context stitched together and per-host baselining of normal temp activity.

## Data sources required

- Sysmon EID 11 (file create) and EID 1 (process create) with command line
- PowerShell 4104 script-block logging (decode routines, `Get-Content` on image paths)
- EDR file-read / file-access telemetry (script interpreter reading `.jpg`/`.png`/PDF in temp)

## Query starting point

Platform: `KQL/Sentinel`

```kql
// A. script interpreter touching an image/temp file, then a decode routine
let interp = dynamic(["powershell.exe","wscript.exe","cscript.exe","mshta.exe","cmd.exe"]);
DeviceProcessEvents
| where FileName in~ (interp)
| where ProcessCommandLine has_any ("frombase64string","-decode","::frombase64","[convert]",
        "gc ",".jpg",".png",".jpeg","temp.jpg")
| where ProcessCommandLine has_any (@"\temp\",@"\appdata\local\temp",".jpg",".png",".jpeg")
| project TimeGenerated, DeviceName, AccountName, FileName, InitiatingProcessFileName, ProcessCommandLine
// B. corroborate with an image/PDF file written to temp shortly before
| join kind=leftouter (
    DeviceFileEvents
    | where FolderPath has @"\Temp\"
    | where FileName endswith ".jpg" or FileName endswith ".png" or FileName endswith ".pdf"
    | project DeviceName, StagedFile=FileName, StageTime=TimeGenerated
) on DeviceName
| where isempty(StageTime) or StageTime between (TimeGenerated-30m .. TimeGenerated)
```

## Triage guidance

- **Likely malicious:** A `.jpg`/`.png` being read by `powershell.exe`/`wscript.exe` and passed through a Base64/decode routine; `temp.jpg` filename specifically; decode chain whose output is then executed (IEX / `Invoke-Expression`); decoy PDF opened while a script runs in parallel.
- **Likely benign / expected:** Image-processing apps, browsers and Office reading images; software updaters decoding Base64 config; developers using `certutil` legitimately. Baseline decode routines per host.
- **Pivot next:** Decoded content → C2 network activity (→ HUNT-05); the writing process → initial access (Office/mshta); persistence created around the same time (Run keys, scheduled tasks — detection lane).

## References

- https://attack.mitre.org/groups/G0069/
