# Hunt: MuddyWater discovery burst (host / user / network / software enumeration)

- **Hypothesis:** If MuddyWater has landed on a host, then within minutes of the first foothold we should observe a *tight temporal cluster* of built-in discovery commands (system, user, network, process, software enumeration) issued from a single suspicious parent (PowerShell/mshta/wscript/Office lineage) on one host — a burst that stands out against the slow drip of legitimate admin recon.
- **ATT&CK:**
  - T1016 — System Network Configuration Discovery (discovery)
  - T1033 — System Owner/User Discovery (discovery)
  - T1049 — System Network Connections Discovery (discovery)
  - T1057 — Process Discovery (discovery)
  - T1082 — System Information Discovery (discovery)
  - T1083 — File and Directory Discovery (discovery)
  - T1518 — Software Discovery (discovery)
  - T1518.001 — Software Discovery: Security Software Discovery (discovery)
  - *Context/pivot (detection-lane):* T1087.002 — Account Discovery: Domain Account (`net user /domain`)
- **Actor procedure:** POWERSTATS/SHARPSTATS collect IP + domain name, username, OS version and machine name, and a running-process list. A PowerShell backdoor checks for **Skype connectivity** (software + network-connection check). Malware enumerates `ProgramData` for folders/files containing the keywords **`Kasper`, `Panda`, or `ESET`** and checks running processes against a hard-coded list of researcher/AV security tools.
- **Why a hunt, not a rule:** Each individual command (`ipconfig`, `whoami`, `tasklist`, `systeminfo`, `Get-Process`) has an enormous benign base rate — admins, logon scripts, inventory agents and helpdesk tooling run them constantly. The signal is not any single command but the **burst** (many distinct discovery verbs, same host, same parent, short window) plus the distinctive AV-keyword / Skype-connectivity checks. That requires per-environment baselining of normal recon volume — unsuitable for a fixed-threshold alert.

## Data sources required

- Sysmon EID 1 / Windows Security 4688 (process creation with command line)
- PowerShell 4104 script-block logging (for `Get-Process`, `Test-NetConnection`, `Get-CimInstance`, `Resolve-DnsName`, ProgramData enumeration)
- EDR process-lineage telemetry

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (source=WinEventLog:Security EventCode=4688) OR (source=*Sysmon* EventCode=1)
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line))
| eval disc=case(
    like(cmd,"%ipconfig%") OR like(cmd,"%net config%"),"net_config",
    like(cmd,"%whoami%") OR like(cmd,"%$env:username%"),"user",
    like(cmd,"%netstat%") OR like(cmd,"%test-netconnection%") OR like(cmd,"%skype%"),"net_conn",
    like(cmd,"%tasklist%") OR like(cmd,"%get-process%"),"process",
    like(cmd,"%systeminfo%") OR like(cmd,"%get-ciminstance%") OR like(cmd,"%get-wmiobject win32_operatingsystem%"),"sysinfo",
    like(cmd,"%programdata%") OR like(cmd,"%kasper%") OR like(cmd,"%panda%") OR like(cmd,"%eset%"),"file_av",
    1=1,null())
| where isnotnull(disc)
| bin _time span=10m
| stats dc(disc) as distinct_categories values(disc) as categories values(cmd) as cmds
        values(ParentImage) as parents by _time, host, user
| where distinct_categories >= 4
| sort - distinct_categories
```

## Triage guidance

- **Likely malicious:** 4+ distinct discovery categories in a 10-minute window under a single non-admin parent such as `mshta.exe`, `wscript.exe`, `powershell.exe -enc`, or `winword.exe` lineage; any hit containing `Kasper`/`Panda`/`ESET` ProgramData enumeration or a Skype-connectivity probe; discovery on a workstation with no matching helpdesk/inventory ticket.
- **Likely benign / expected:** Logon-script or GPO-driven recon at boot; asset-inventory agents (SCCM, Lansweeper, Tanium) that legitimately run broad enumeration on a schedule; IT staff troubleshooting. Baseline and suppress these parents.
- **Pivot next:** Parent process tree back to initial access (Office macro, mshta, scheduled task); outbound connections from the same host in the following hour (→ HUNT-05); any credential-tooling execution (→ HUNT-08).

## References

- https://attack.mitre.org/groups/G0069/
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a
