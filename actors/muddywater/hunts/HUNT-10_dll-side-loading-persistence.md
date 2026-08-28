# Hunt: DLL side-loading persistence

- **Hypothesis:** If MuddyWater maintains persistence via DLL side-loading, then we should find a legitimate, signed executable loading an *unsigned or anomalously-located* DLL — a module whose name matches a real dependency but which sits in a user-writable/non-standard path, a path/property mismatch and masquerading anomaly on the same load.
- **ATT&CK:**
  - T1574.001 — Hijack Execution Flow: DLL (persistence)
- **Actor procedure:** MuddyWater **maintains persistence by side-loading DLLs to trick legitimate programs into running malware** — a signed host binary is dropped alongside a malicious DLL that it loads from its own directory.
- **Why a hunt, not a rule:** Legitimate software loads thousands of DLLs, and many apps legitimately ship in user-space (per-user installs, portable apps). The malicious pattern — a trusted EXE loading a same-named DLL from an unexpected, writable location, often unsigned — requires image-load telemetry plus baselining of each binary's normal module set and load paths. A blanket "unsigned DLL load" rule is far too noisy, so this is a hunt.

## Data sources required

- Sysmon EID 7 (image load, with signature status and signed/unsigned + hash)
- Sysmon EID 1 (the host process and its image path)
- Sysmon EID 11 (a DLL written next to a signed EXE in a user-writable path)

## Query starting point

Platform: `KQL/Sentinel`

```kql
DeviceImageLoadEvents
| where FileName endswith ".dll"
| where FolderPath has_any (@"\AppData\", @"\Temp\", @"\Users\Public\", @"\ProgramData\", @"\Downloads\")
| where InitiatingProcessFolderPath !startswith @"C:\Windows"
      and InitiatingProcessFolderPath !startswith @"C:\Program Files"
// signed host binary loading a module from a writable path = classic side-load setup
| where InitiatingProcessFileName endswith ".exe"
| extend loadDir = tostring(parse_path(FolderPath).DirectoryPath),
         procDir = tostring(parse_path(InitiatingProcessFolderPath).DirectoryPath)
| where loadDir =~ procDir                         // DLL sits next to the EXE
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".dll"
    | project DeviceName, FileName, dllWritten=TimeGenerated, WroteBy=InitiatingProcessFileName
  ) on DeviceName, FileName
| project TimeGenerated, DeviceName, InitiatingProcessFileName, procDir, FileName, FolderPath, WroteBy, dllWritten
| order by TimeGenerated desc
```

## Triage guidance

- **Likely malicious:** A signed/trusted EXE loading a DLL from `%appdata%`/`%temp%`/`%programdata%` where the same DLL name normally lives under `System32`/`Program Files`; the DLL is unsigned or signed by an unexpected authority; the DLL was written recently by a script interpreter or downloader; the pairing appears on only one/few hosts.
- **Likely benign / expected:** Legitimate portable apps and per-user installs (Teams, some updaters) that load their own DLLs from appdata; developer build outputs. Baseline each EXE→DLL pairing and its normal path.
- **Pivot next:** Hash/reputation the DLL; determine autostart hooking the host EXE (Run keys/scheduled task — detection lane); look for the same DLL name across other hosts (campaign spread); confirmed side-load → escalate to IR.

## References

- https://attack.mitre.org/groups/G0069/
