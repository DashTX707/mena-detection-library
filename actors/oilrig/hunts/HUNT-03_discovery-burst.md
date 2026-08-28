# Hunt: OilRig discovery burst (host / user / network / process / registry / software enumeration)

- **Hypothesis:** If OilRig has landed on a host, then within a short window we should observe a *tight temporal cluster* of built-in discovery commands (system info, network config/connections, user, service, process, RDP-history registry query, software inventory) issued from a single suspicious parent (Office/script-host/PowerShell lineage) on one host — a burst that stands out against the slow drip of legitimate admin recon.
- **ATT&CK:**
  - T1082 — System Information Discovery (`systeminfo`, `hostname`)
  - T1016 — System Network Configuration Discovery (`ipconfig /all`)
  - T1049 — System Network Connections Discovery (`netstat -an`)
  - T1033 — System Owner/User Discovery (`whoami`)
  - T1007 — System Service Discovery (`sc query`)
  - T1057 — Process Discovery (`tasklist`)
  - T1012 — Query Registry (`reg query "HKCU\Software\Microsoft\Terminal Server Client"`)
  - T1518 — Software Discovery (installed-software / browser-user enumeration)
- **Actor procedure:** OilRig runs `hostname`, `systeminfo`, `ipconfig /all`, `netstat -an`, `whoami`, `sc query`, `tasklist`, and `reg query "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client"` to enumerate the host and prior RDP targets, and uses browser-data dumper tooling (MKG) to build a list of Chrome users — often clustered immediately after macro-driven initial access.
- **Why a hunt, not a rule:** each command has an enormous benign base rate — admins, logon scripts, inventory agents (SCCM/Tanium/Lansweeper) and helpdesk run them constantly. The signal is the **burst** (many distinct discovery verbs, same host, same parent, short window) plus the distinctive Terminal-Server-Client registry query, which requires per-environment baselining of normal recon volume — unsuitable for a fixed threshold.

## Data sources required

- Sysmon EID 1 / Windows Security 4688 (process creation with command line)
- PowerShell 4104 script-block logging (`Get-Process`, `Get-CimInstance`, `Resolve-DnsName`)
- Sysmon EID 12/13 or 4688 for `reg query` of Terminal Server Client
- EDR process-lineage telemetry

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (source=WinEventLog:Security EventCode=4688) OR (source=*Sysmon* EventCode=1)
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line))
| eval disc=case(
    like(cmd,"%systeminfo%") OR like(cmd,"%hostname%"),"sysinfo",
    like(cmd,"%ipconfig%"),"net_config",
    like(cmd,"%netstat%"),"net_conn",
    like(cmd,"%whoami%"),"user",
    like(cmd,"%sc query%") OR like(cmd,"%sc.exe query%"),"service",
    like(cmd,"%tasklist%") OR like(cmd,"%get-process%"),"process",
    like(cmd,"%terminal server client%"),"rdp_hist",
    like(cmd,"%wmic product%") OR like(cmd,"%get-itemproperty%uninstall%"),"software",
    1=1,null())
| where isnotnull(disc)
| bin _time span=10m
| stats dc(disc) as cats values(disc) as categories values(cmd) as cmds values(ParentImage) as parents by _time, host, user
| where cats >= 4
| sort - cats
```

## Triage guidance

- **Likely malicious:** 4+ distinct discovery categories in a 10-minute window under a non-admin parent (`winword.exe`, `excel.exe`, `wscript.exe`, `powershell.exe -enc`, `hh.exe`); any `reg query` of `Terminal Server Client` (rare outside recon); discovery on a workstation with no matching helpdesk/inventory ticket.
- **Likely benign / expected:** GPO/logon-script recon at boot; asset-inventory agents on a schedule; IT troubleshooting. Baseline and suppress these parents.
- **Pivot next:** parent tree back to initial access (Office macro / CHM / scheduled task); outbound C2 from the same host in the following hour (→ HUNT-01); credential tooling (detection lane) or collection (→ HUNT-04).

## References

- https://attack.mitre.org/groups/G0049/
