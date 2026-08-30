# Hunt: Tortoiseshell credential-file harvesting, directory enumeration & local staging in %Windir%\temp

- **Hypothesis:** If a Tortoiseshell operator or infostealer is collecting from a host, then a single process will, in a tight window, enumerate directories looking for credential-bearing files, read those files, and drop the harvested output plus tooling into a local staging directory (the actor's observed `%Windir%\temp`) ahead of exfiltration — a burst of file-access breadth followed by concentrated writes to one temp path. The evidence stacks an improper-frequency anomaly (one process touching an unusually broad set of directories/files fast) with an unexpected-relationship anomaly (a non-backup/non-indexer process reading `*.config`/`*.xml`/`*password*`/browser-login stores) and a path anomaly (collected output concentrated in `\Windows\Temp`, e.g. `rconfig.xml`, `bak.exe`).
- **ATT&CK:**
  - T1552.001 — Unsecured Credentials: Credentials In Files (credential-access)
  - T1083 — File and Directory Discovery (discovery)
  - T1074.001 — Data Staged: Local Data Staging (collection)

- **Actor procedure:** Tortoiseshell's info-gathering tools enumerate files and directories to locate credentials and data of interest, read credential-bearing files, and stage the collected data and tooling in temporary directories such as `%Windir%\temp` (Symantec observed artifacts including `rconfig.xml` and `bak.exe` there) before archiving and exfiltrating. Each individual file read or temp write is common and low-signal; the tradecraft only stands out as a *burst-then-concentrate* pattern driven by one process.
- **Why a hunt, not a rule:** File and directory enumeration and writes to `\Windows\Temp` are enormously high-volume, benign background activity (installers, indexers, AV, updaters, backup) — a rule on either fires constantly and gets tuned to death. The discriminating signal is behavioral and correlated: one non-backup process reading credential-shaped files across many directories in a short window and concentrating the output into a single temp staging path, ideally preceding an archive/exfil step. That correlation and baselining is judgement-heavy → hunt. A tighter derivative (a specific non-allowlisted process reading browser-login/DPAPI stores then writing an archive to temp — Summiting Level 3–4) can be handed to detection-engineering.

## Data sources required

- EDR/Sysmon EID 11 (file create) + file-read/open telemetry — per-process breadth of directories/files touched, and writes into `\Windows\Temp` / user temp
- Sysmon EID 1 (process create) — the collecting process's Image, ParentImage, signing, command line
- File-access telemetry on credential-bearing targets — `*.config`, `*.xml`, `*.kdbx`, `unattend.xml`, browser `Login Data`, `*password*`, `*.ppk`/`id_rsa`
- Correlation to archive-utility execution (rar/7z/zip — detection pack T1560.001) and outbound exfil (HUNT-01/02)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — one process: broad credential-file reads + concentrated temp staging

```kusto
let credLike = dynamic(["password","credential","login data","unattend","\\.config",
    "\\.kdbx","id_rsa","\\.ppk","web.config",".xml"]);
let staging = DeviceFileEvents
    | where TimeGenerated > ago(14d)
    | where FolderPath has_any (@"\Windows\Temp", @"\AppData\Local\Temp")
    | summarize stagedFiles = dcount(FileName), stagedWrites = count(),
                stagedList = make_set(FileName, 15), stageStart = min(TimeGenerated)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath;
let harvest = DeviceFileEvents
    | where TimeGenerated > ago(14d)
    | where ActionType in ("FileCreated","FileModified","FileAccessed")
    | where tolower(FileName) has_any (credLike) or tolower(FolderPath) has_any (credLike)
    | summarize credDirs = dcount(FolderPath), credReads = count(), harvestStart = min(TimeGenerated)
            by DeviceName, InitiatingProcessFileName;
staging
| join kind=inner harvest on DeviceName, InitiatingProcessFileName
| where credDirs >= 8                                        // broad enumeration by one process
| where abs(datetime_diff('minute', stageStart, harvestStart)) <= 120   // harvest→stage in one window
| project DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          credDirs, credReads, stagedFiles, stagedList
| order by credReads desc
// Pivot: is InitiatingProcessFileName unsigned / running from temp? Did an archiver then read the staging dir?
```

Platform: `SPL / Splunk` — credential-file breadth then temp concentration by the same process

```spl
index=edr sourcetype=sysmon EventCode=11
| eval f=lower(file_name), p=lower(file_path)
| eval credhit=if(match(f,"password|credential|login data|unattend|\.kdbx|id_rsa|\.ppk|web\.config") OR match(p,"password|credential"),1,0)
| eval staged=if(match(p,"\\\\windows\\\\temp|\\\\appdata\\\\local\\\\temp"),1,0)
| stats sum(credhit) as cred_reads dc(file_path) as dirs_touched sum(staged) as staged_writes
        values(eval(if(staged=1,file_name,null()))) as staged_files by host,process_name,process_path
| where cred_reads>=5 AND staged_writes>=5 AND dirs_touched>=8
| sort - cred_reads
```

## Triage guidance

- **Likely malicious:** one unsigned or temp-resident process reading credential-shaped files across many directories in a short burst and concentrating the output into `\Windows\Temp` (bonus: filenames like `rconfig.xml`, `bak.exe`); the staging directory then read by an archiver (rar/7z) or by the IMAP/web exfil process (HUNT-01/02); the process parented by `mshta`, a side-load host, or a script interpreter.
- **Likely benign / expected:** backup/sync agents, search indexers (Windows Search), AV/EDR scans, and installers legitimately touch broad file sets and write to temp — allowlist their signed binaries and known paths; a config-management tool reading `web.config` in its own scope is expected. Broad file access by a signed enterprise agent is noise; the same by a temp-resident unknown is not.
- **Pivot next:** capture the staging directory contents and the collecting binary before it self-deletes (actor deletes tooling post-use — detection pack T1070.004); trace the process lineage back to initial access (HUNT-02/04) and forward to archive + exfil (detection pack T1560.001, HUNT-01/02); scope the binary hash fleet-wide. Active credential harvesting with staging is pre-exfil collection in a live intrusion → escalate to IR.

## References

- https://www.security.com/threat-intelligence/tortoiseshell-apt-supply-chain
- https://www.crowdstrike.com/en-us/adversaries/imperial-kitten/
- https://attack.mitre.org/techniques/T1552/001/
- https://attack.mitre.org/techniques/T1083/
- https://attack.mitre.org/techniques/T1074/001/
