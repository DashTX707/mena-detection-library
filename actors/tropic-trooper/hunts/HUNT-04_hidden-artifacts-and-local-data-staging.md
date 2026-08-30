# Hunt: Tropic Trooper — payloads hidden in non-standard data folders & local data staging

- **Hypothesis:** If Tropic Trooper has staged an implant or collection on a host, then the file-system tell is *path anomaly plus company-you-keep*: implant components and recon/collection output written into obscure "data" subdirectories that almost never see file creation — `c:\Windows\branding\data`, `c:\Users\Public\Music\data`, and sibling `...\data` folders — where a DLL (`VERSION.dll`/`datast.dll`/`datastate.dll`) sits next to a side-load host binary, or ping-sweep `.txt` output and to-be-exfiltrated archives accumulate. No single file in `Public\Music` is alarming, but a *never-before-written directory suddenly holding an unsigned DLL, a signed EXE and text output, created by `w3wp.exe` or a side-load host process*, is the finding. This hunt keys on the unexpected creator-plus-location relationship, not the file name.
- **ATT&CK:**
  - T1564.001 — Hide Artifacts: Hidden Files and Directories (stealth) — actor tucks implant DLLs into uncommon data subfolders (`c:\Windows\branding\data`, `c:\Users\Public\Music\data`) to keep components out of common inspection paths; hunted via file-create telemetry on rarely-written directories.
  - T1074.001 — Data Staged: Local Data Staging (collection) — actor stages recon output (i.bat ping-sweep `.txt`) and tooling/collected data in dedicated data directories before use/exfil; hunted via clustering of staged files by an implant-related creator process.

- **Actor procedure:** Per Kaspersky, the loader components are dropped into `c:\Windows\branding\data` and `c:\Users\Public\Music\data` — legitimate-sounding but rarely-used data folders — so the malicious `VERSION.dll`/`datast.dll`/`datastate.dll` sit alongside the signed side-load hosts (`inst.exe`, `WinStore.exe`) out of normal review paths. Separately, the actor stages locally: the `i.bat` ICMP ping-sweep script writes reachable-host results to text files for targeting, and (consistent with Earth Centaur collection tradecraft) collected internal documents are gathered and archived locally before exfiltration over the Crowdoor HTTPS C2. Both behaviors converge on the same file-system pattern: a small number of related files appearing in an unusual directory, written by a web-shell or implant process rather than a user.
- **Why a hunt, not a rule:** File creation in `C:\Users\Public` or under `C:\Windows` happens legitimately all the time (installers, updaters, printer/color profiles, media apps), and a text file or a DLL in a data folder is individually meaningless — an alert on "file written to Public\Music" would be intolerable noise. The signal is emergent: a directory that is *new or historically write-quiet* suddenly receiving a cluster of files (unsigned DLL + signed EXE + `.txt`/archive) from an *implant-associated creator* (`w3wp.exe`, `inst.exe`, injected `colorcpl.exe`). Establishing the per-directory baseline and judging the creator/company-you-keep is hunt work over aggregated file telemetry. If a specific never-legitimately-written path proves stable (e.g., `\branding\data` never sees writes in your estate), hand detection-engineering a scoped file-create analytic for that exact path.

## Data sources required

- EDR / Sysmon file-create (EID 11) with creating-process and signer across endpoints and the web/IIS servers — the core telemetry
- Windows Security 4663 (object access / file audit) on the specific directories if SACLs are configured, for creation + subsequent read
- Historical file-create baseline per directory (to compute "rarely/never written" and "first-seen" for a path)
- File-signature / hash context to flag unsigned DLLs among signed host binaries in the same folder

## Query starting point

Platform: `Microsoft Defender XDR (KQL)` — surface implant-associated processes writing clusters of files into rarely-used data directories

```kusto
let lookback = 30d;
// directories that are historically write-quiet across the fleet (baseline over 90d)
let baseline = DeviceFileEvents
    | where TimeGenerated between (ago(120d) .. ago(30d))
    | where ActionType == "FileCreated"
    | summarize histWrites = count() by FolderPath;
DeviceFileEvents
| where TimeGenerated > ago(lookback)
| where ActionType == "FileCreated"
| where FolderPath has @"\branding\data" or FolderPath has @"\public\music\data"
     or FolderPath matches regex @"(?i)\\(public|programdata|windows)\\[^\\]+\\data($|\\)"
| where InitiatingProcessFileName in~ ("w3wp.exe","inst.exe","winstore.exe","colorcpl.exe","cmd.exe","powershell.exe")
| join kind=leftouter (baseline) on FolderPath
| extend rareDir = iif(isnull(histWrites) or histWrites < 5, true, false)
| summarize files = make_set(FileName, 25), fileCount = dcount(FileName),
            creators = make_set(InitiatingProcessFileName, 5),
            hasUnsignedDll = countif(FileName endswith ".dll"),
            hasText = countif(FileName endswith ".txt"),
            hasArchive = countif(FileName has_any (".zip",".rar",".7z",".cab",".dat")),
            first = min(TimeGenerated), last = max(TimeGenerated)
        by DeviceName, FolderPath, rareDir
| where rareDir and fileCount >= 2                 // cluster in a quiet dir = stage/hide
| sort by hasUnsignedDll desc, fileCount desc
// Directories with an unsigned DLL + a signed host EXE, or DLL + recon .txt/archive, written by w3wp/inst/colorcpl = investigate
```

## Triage guidance

- **Likely malicious:** a write-quiet `...\data` directory (esp. `\branding\data`, `\Public\Music\data`) that suddenly holds an unsigned `VERSION.dll`/`datast.dll` next to a signed `inst.exe`/`WinStore.exe`; ping-sweep `.txt` output or a fresh `.rar`/`.zip` created by `w3wp.exe`, `cmd.exe` off the web-shell, or injected `colorcpl.exe`; a first-seen path receiving a multi-file cluster within minutes.
- **Likely benign / expected:** software installers/updaters and OS servicing writing to `ProgramData\<vendor>\data`; media apps populating `Public\Music`; color/printer profiles under `\branding`; a single benign file from a signed, expected process. High write volume from a *known* installer is normal; a small cluster from a web-shell/implant process in a historically-empty directory is not — the creator identity and the directory's baseline are the discriminators.
- **Pivot next:** if the cluster includes a side-load DLL, jump to HUNT-03 (in-memory loader chain) and detection pack T1574.001; if it's recon `.txt`, jump to HUNT-05 (recon burst); if it's an archive, treat as collection staging and pivot to exfil (detection pack T1560/T1041 over `blog.techmersion[.]com`) — a staged archive on a server that also beacons the C2 is an active exfil-prep, escalate to incident-response-coordinator. Note the confirmed never-legitimately-written path for detection-engineering.

## References

- https://securelist.com/new-tropic-trooper-web-shell-infection/113737/
- https://www.trendmicro.com/en_us/research/21/l/collecting-in-the-dark-tropic-trooper-targets-transportation-and-government-organizations.html
- https://attack.mitre.org/groups/G0081/
- https://attack.mitre.org/techniques/T1564/001/
- https://attack.mitre.org/techniques/T1074/001/
