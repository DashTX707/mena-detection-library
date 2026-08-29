# Hunt: WIRTE LitePower/IronWind discovery burst — scripted host, user-privilege and Domain-Admins recon in one short window

- **Hypothesis:** If a WIRTE stager (LitePower PowerShell / IronWind) is active, then we should see a tight scripted-reconnaissance burst on one host in a short window rather than isolated queries: WMI/PowerShell enumeration of host inventory (OS caption/architecture, computer name, disk volume serial, installed programs), a `WindowsPrincipal`/`IsInRole` Administrator check plus username report, and a domain-membership + `Domain Admins` group check — all issued by a single script-host process, and (for IronWind) an early outbound HTTP POST of that inventory to an unfamiliar domain like `requestinspector.com`.
- **ATT&CK:**
  - T1082 — System Information Discovery (discovery) — IronWind profiles Office/OS version, hostname, installed programs; LitePower queries OS caption/arch + disk volume serial via WMI
  - T1033 — System Owner/User Discovery (discovery) — LitePower `WindowsPrincipal IsInRole(Administrator)` + username report; IronWind includes username in profiling beacon
  - T1069.002 — Permission Groups Discovery: Domain Groups (discovery) — LitePower `Get-ServiceStatus` checks domain membership + `Domain Admins` membership
- **Actor procedure:** IronWind profiles the victim on first contact — Office version, OS version, computer name, username, installed-program list — and POSTs it to `requestinspector.com`. LitePower separately queries OS caption/architecture and the local disk volume serial via WMI, checks whether the current user is a local Administrator (`WindowsPrincipal.IsInRole`), and its `Get-ServiceStatus` function checks whether the host is domain-joined and whether the user is in `Domain Admins` — feeding lateral-movement and escalation decisions before follow-on activity. (The related `SELECT * FROM AntiVirusProduct` / `root\SecurityCenter2` AV check, T1518.001, is routed to the detection lane; surface it here as a corroborating pivot.)
- **Why a hunt, not a rule:** each query is individually routine — inventory scripts, admin-rights checks and group lookups are exactly what legitimate management tooling, logon scripts and IT audits do all day, so any one alert is noise. The durable find (Summiting behavioral, Level 3) is the *burst and co-location*: system-info **and** user-privilege **and** Domain-Admins checks fired by one script-host process within a few minutes, especially bracketed by an outbound inventory POST to an unfamiliar domain or the AV-discovery query. Distinguishing that compressed recon sequence from spread-out legitimate admin activity requires baselining who runs recon and when — analyst correlation, not a threshold.

## Data sources required

- PowerShell script-block logging (EID 4104) and module logging (4103) — `Get-WmiObject`/`Get-CimInstance`, `WindowsPrincipal`/`IsInRole`, `Domain Admins`/`System.DirectoryServices` calls
- Sysmon EID 1 / 4688 — `powershell.exe`/`wscript` process lineage and command line
- WMI-Activity operational log — `Win32_OperatingSystem`, `Win32_LogicalDisk`, `root\SecurityCenter2` queries
- Proxy / EDR network — early outbound POST to `requestinspector.com` / unfamiliar domain

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (source="*PowerShell/Operational" EventCode=4104) OR (source=*Sysmon* EventCode=1 Image="*powershell.exe")
| eval sb=lower(coalesce(ScriptBlockText, CommandLine))
| eval q_sysinfo=if(match(sb,"win32_operatingsystem|win32_logicaldisk|caption|osarchitecture|volumeserialnumber|installedprograms|win32_product"),1,0)
| eval q_user   =if(match(sb,"windowsprincipal|isinrole|administrator|\[security\.principal|whoami"),1,0)
| eval q_domain =if(match(sb,"domain admins|get-servicestatus|domainrole|system\.directoryservices|partofdomain"),1,0)
| bin _time span=10m
| stats sum(q_sysinfo) as sysinfo sum(q_user) as user sum(q_domain) as domain
        values(host) as host by _time, ProcessGuid
| eval categories=(sysinfo>0)+(user>0)+(domain>0)
| where categories>=2
| sort - categories
```

Pivot bursts (categories>=2 from one `ProcessGuid`) to an outbound POST to `requestinspector.com`/unfamiliar domain in the same window, and to the AV-discovery query (`root\SecurityCenter2`, detection lane) on the same host.

## Triage guidance

- **Likely malicious:** system-info + admin-check + Domain-Admins enumeration from one PowerShell process within minutes, especially with no corresponding change/ticket, and paired with an inventory POST to an unfamiliar domain or a preceding sideload/COM-hijack; a `Get-ServiceStatus`-style function name; volume-serial + AV-product queries in the same burst.
- **Likely benign / expected:** SCCM/Intune/monitoring agents inventorying hosts on schedule; logon scripts checking group membership; IT running audit scripts. Baseline your management-tooling service accounts, their hosts and their cadence and suppress; the discriminator is an *ad-hoc, compressed* burst from an unexpected parent.
- **Pivot next:** trace the script-host process back to its parent (sideload host / COM-hijack VBS — HUNT-03/04) and forward to the C2 beacon (HUNT-08) and collection (HUNT-09). Confirmed scripted Domain-Admins reconnaissance following a foothold is an active intrusion — escalate to incident-response-coordinator. A well-baselined "sysinfo+user+domain burst from one process" analytic is durable enough to hand to detection-engineering.

## References

- https://securelist.com/wirtes-campaign-in-the-middle-east-living-off-the-land-since-at-least-2019/105044/
- https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/
- https://attack.mitre.org/groups/G0090/
