# Hunt: APT39 file & directory discovery recon-burst (collection-targeting enumeration)

- **Hypothesis:** If APT39 is locating data of interest to collect (PII, travel/movement records, documents), then — because enumeration precedes staging in the actor's collection workflow — we should see a *burst* of file/directory discovery (`dir /s`, `tree`, recursive listing, script-driven directory walks) issued in a *tight window* from a *suspicious parent* (script host, web shell `w3wp.exe`, an unusual interpreter, or a non-interactive session), traversing document/share/user-profile paths, and immediately followed by access to or archiving of the identified files. The signal is the *lineage + burst + target-path* combination, not the individual `dir` command, which is ubiquitous.
- **ATT&CK:**
  - T1083 — File and Directory Discovery (discovery)

- **Actor procedure:** APT39 enumerates files and directories (via `dir`, `cmd.exe`, and scripted walks) to find where valuable data lives before collecting it, often driving the enumeration from a web shell dropped after SQLi or from a script host on a compromised endpoint. The output guides which documents, mailboxes, and shares get staged with WinRAR and pulled out over C2 — the recon step that turns generic access into targeted surveillance collection.
- **Why a hunt, not a rule:** `dir`/directory enumeration is one of the most common commands on any Windows host — admins, scripts, installers, and users generate it constantly, so a rule on the command itself is pure noise. The hunt signal is *relational and temporal*: many enumeration commands in a short burst, spawned by an anomalous parent (`w3wp.exe`, `wscript`, `powershell`, an unsigned binary) rather than an interactive admin shell, walking sensitive/document/share paths, and paired with subsequent file access or archiving. Reconstructing that lineage-and-burst context is judgement-heavy → hunt. A tightly-scoped residual — web shell or non-interactive script host issuing recursive enumeration of document shares — can be handed to detection-engineering.

## Data sources required

- Sysmon EID 1 (process create) + full command line + parent lineage (`dir`, `tree`, `cmd /c dir /s`, `Get-ChildItem -Recurse`)
- PowerShell script-block logging (EID 4104) for scripted directory walks
- Web-server process telemetry (`w3wp.exe`/`php-cgi` spawning `cmd`/enumeration) — web-shell-driven recon
- Sysmon EID 11 / file-access audit (4663) on document shares & user-profile paths — the follow-on access

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — enumeration burst from a suspicious parent over sensitive paths

```kusto
DeviceProcessEvents
| where TimeGenerated > ago(14d)
| where (FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","cscript.exe","wscript.exe"))
| where ProcessCommandLine has_any ("dir /s","dir /b","tree ","Get-ChildItem -Recurse","gci -r","forfiles")
      or ProcessCommandLine matches regex @"(?i)dir\s+.*\\(Users|Shares|Documents|Desktop|Finance|HR|Travel)"
| extend suspParent = InitiatingProcessFileName in~ ("w3wp.exe","php-cgi.exe","wscript.exe","cscript.exe")
      or InitiatingProcessFileName endswith ".tmp"
      or InitiatingProcessFolderPath has_any (@"\Temp\", @"\AppData\")
| summarize enumCmds = count(),
            cmds = make_set(ProcessCommandLine, 25),
            first = min(TimeGenerated), last = max(TimeGenerated),
            anySusp = max(suspParent)
        by DeviceName, InitiatingProcessFileName, AccountName
| extend burstMins = datetime_diff("minute", last, first)
| where enumCmds >= 5 and burstMins <= 20           // burst, not steady-state admin use
| where anySusp == true                             // spawned by web shell / script host / temp binary
| order by enumCmds desc
// Exclude backup/indexing/AV agents and known admin scripts by parent+account (wiki baseline)
```

## Triage guidance

- **Likely malicious:** a rapid burst of recursive enumeration (`dir /s`, `Get-ChildItem -Recurse`, `tree`) spawned by `w3wp.exe`/a script host/a temp-path binary rather than an interactive admin, traversing user-profile, document, HR/finance/travel, or file-share paths, and followed within minutes by file access or WinRAR archiving of the discovered files — this is APT39 mapping data ahead of collection. Higher concern under a non-interactive/service logon or right after a web-shell hit.
- **Likely benign / expected:** backup/indexing agents, AV/EDR scans, software installers, DLP crawlers, migration/inventory scripts, and admins/users browsing shares legitimately enumerate directories — allowlist by parent process, service account, and known scheduled jobs. Steady, low-rate `dir` from an interactive admin shell is expected; a 30-command recursive burst from `w3wp.exe` is not.
- **Pivot next:** correlate with a preceding web-shell/SQLi hit (T1505.003/T1190 detection pack) or collection tooling (HUNT-01); check whether the enumerated files were then accessed, archived (T1560.001), staged (T1074.001), and exfiltrated (HUNT-04); identify whose data was targeted. A web-shell-driven recon burst over sensitive shares indicates hands-on-keyboard activity → escalate to IR.

## References

- https://attack.mitre.org/groups/G0087/
- https://attack.mitre.org/techniques/T1083/
- https://www.cisa.gov/news-events/analysis-reports/ar20-259a
