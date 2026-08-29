# Hunt: Gaza Cybergang post-landing discovery burst (host / user / process / file / security-software enumeration)

- **Hypothesis:** If a Gaza Cybergang backdoor (Spark, DropBook, SharpStage, MoleNet) has landed on a host, then within a short window we should observe a *tight temporal cluster* of built-in profiling activity — system-information collection, username/owner lookup, running-process enumeration, file/directory browsing, and installed security-software enumeration — issued from a single suspicious parent (Office/script-host lineage, a `%AppData%` binary, or a PyInstaller-bundled process) on one host, standing out against the slow drip of legitimate admin recon.
- **ATT&CK:**
  - T1082 — System Information Discovery (OS/hostname/hardware collected by Spark/DropBook/SharpStage/MoleNet)
  - T1033 — System Owner/User Discovery (Spark gathers username/owner)
  - T1057 — Process Discovery (implant lists active processes and reports to C2)
  - T1083 — File and Directory Discovery (DropBook enumerates files/dirs to select data of interest)
  - T1518.001 — Software Discovery: Security Software Discovery (MoleNet enumerates installed AV/security products)
- **Actor procedure:** After execution these implants profile the host and report back to the cloud C2: Spark/DropBook/SharpStage/MoleNet collect OS, hostname and hardware; Spark grabs the username; the backdoors enumerate running processes and send the list to C2; DropBook walks the filesystem to pick collection targets; MoleNet queries installed security/AV software to inform follow-on tooling. These fire close together, immediately after macro/XLL/link-driven initial access.
- **Why a hunt, not a rule:** each primitive has an enormous benign base rate — admins, logon scripts, inventory agents (SCCM/Tanium/Lansweeper) and helpdesk run them constantly, and much of it is done via API (WMI/registry reads) that never touches a command line. The signal is the **burst** (several distinct discovery categories, same host, same suspicious parent, short window) plus the security-software enumeration, which needs per-environment baselining of normal recon volume — unsuitable for a fixed threshold.

## Data sources required

- Sysmon EID 1 / Windows Security 4688 (process creation with command line and parent)
- Sysmon EID 12/13 registry reads of `SecurityCenter`/AV uninstall keys; WMI-Activity operational log (`AntiVirusProduct` queries)
- PowerShell 4104 script-block logging (`Get-CimInstance`, `Get-Process`, `Get-ChildItem`)
- EDR process-lineage telemetry

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (source=WinEventLog:Security EventCode=4688) OR (source=*Sysmon* EventCode=1)
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line)), parent=lower(ParentImage)
| eval disc=case(
    like(cmd,"%systeminfo%") OR like(cmd,"%hostname%") OR like(cmd,"%get-computerinfo%"),"sysinfo",
    like(cmd,"%whoami%") OR like(cmd,"%query user%"),"user",
    like(cmd,"%tasklist%") OR like(cmd,"%get-process%"),"process",
    like(cmd,"%dir /s%") OR like(cmd,"%get-childitem%") OR like(cmd,"%where /r%"),"file_dir",
    like(cmd,"%securitycenter%") OR like(cmd,"%antivirusproduct%") OR like(cmd,"%get-mpcomputerstatus%")
      OR like(cmd,"%wmic%product%") OR like(cmd,"%sc query%windefend%"),"sec_sw",
    1=1,null())
| where isnotnull(disc)
| bin _time span=10m
| stats dc(disc) as cats values(disc) as categories values(cmd) as cmds values(parent) as parents by _time, host, User
| where cats >= 3
| sort - cats
```

## Triage guidance

- **Likely malicious:** 3+ distinct discovery categories in a 10-minute window under a non-admin parent (`winword.exe`, `excel.exe`, `msaccess.exe`, `wscript.exe`, a `%AppData%`/`_MEI` binary); any programmatic security-software enumeration (WMI `AntiVirusProduct` / `SecurityCenter2` read) tied to a freshly-spawned process; discovery on a workstation with no matching helpdesk/inventory ticket.
- **Likely benign / expected:** GPO/logon-script recon at boot; asset-inventory and EDR agents on a schedule; IT troubleshooting; developer file searches. Baseline and suppress these parents/agents.
- **Pivot next:** walk the parent tree back to initial access (Office macro / XLL / .accdb / link-click, HUNT-07); check the same host for outbound cloud-service C2 in the following minutes (HUNT-01); check for screen capture (HUNT-05) and persistence (scheduled task / Run key, detection lane). The reported-to-C2 profiling confirms a live backdoor — escalate if corroborated.

## References

- https://attack.mitre.org/groups/G0021/
- https://attack.mitre.org/software/S0553/
- https://www.cybereason.com/blog/new-malware-arsenal-abusing-cloud-services-in-middle-east-espionage-campaign
