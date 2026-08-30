# Hunt: Moses Staff / discovery burst preceding mass remote execution (PyDCrypt + StrifeWater recon)

- **Hypothesis:** If PyDCrypt is preparing to spread DCSrv or StrifeWater is profiling a freshly compromised host, then we should observe a compressed burst of host-profiling and network-enumeration activity — system-information queries, domain host enumeration, and file/directory listing — emanating from a single process or host, *immediately preceding* lateral movement or bulk collection. Any one of these is ubiquitous benign activity; the hunt keys on the *improper timing/frequency* of the three stacked together on one origin and directly abutting the spread/collection tail (unexpected relationship to what follows).
- **ATT&CK:**
  - T1082 — System Information Discovery (discovery) — host profiling (machine/user/OS/timezone/privilege)
  - T1018 — Remote System Discovery (discovery) — domain machine-name enumeration for targeting
  - T1083 — File and Directory Discovery (discovery) — RAT file/directory enumeration

- **Actor procedure:** Per Check Point, before spreading PyDCrypt collects the domain name and machine names to identify lateral targets; per Cybereason, StrifeWater profiles each host it lands on (machine name, username, OS version, timezone, privilege level) and enumerates files and directories as part of its reconnaissance. The recon is the hinge between access and either mass deployment (PyDCrypt → DCSrv) or collection (StrifeWater), so a discovery burst that immediately precedes those actions is the actor-rational tell.
- **Why a hunt, not a rule:** Discovery commands (`net view`, `nltest`, `systeminfo`, WMI host queries, directory listing) are among the most common benign administrative and software actions in any environment — alerting on them individually is pure noise. The huntable pattern is *sequence and concentration*: three discovery categories from one origin in a tight window, followed within minutes by remote execution or bulk file staging. That temporal-correlation judgement is analyst work, not a static rule; if a specific origin class (e.g. a web server that should never enumerate the domain) shows this pattern, the scoped correlation can be handed to detection-engineering.

## Data sources required

- Sysmon EID 1 / Security 4688 (process create, with full command line) — `net`, `nltest`, `systeminfo`, `whoami`, `wmic`, `arp`
- WMI-Activity operational log — remote host/system-info queries
- Sysmon EID 10 / EDR — process performing rapid directory enumeration (many `FindFirstFile`/`FindNextFile` or file-open events)
- DC authentication / DNS logs — bursts of host-name resolution consistent with domain enumeration
- Downstream lateral-movement (7045 / remote process-create) and staging telemetry to anchor the "precedes" clause

## Query starting point

Platform: `KQL / Microsoft Defender XDR` — three discovery categories from one host in a burst, abutting spread/collection

```kusto
let win = 14d;
let disco = DeviceProcessEvents
    | where TimeGenerated > ago(win)
    | extend cat = case(
        FileName in~ ("systeminfo.exe","whoami.exe") or ProcessCommandLine has_any ("computersystem","os get","timezone"), "T1082_sysinfo",
        FileName in~ ("nltest.exe","net.exe","net1.exe") and ProcessCommandLine has_any ("view","group \"domain","dclist","/domain"), "T1018_remotesys",
        ProcessCommandLine has_any (@"dir /s", "Get-ChildItem", "findstr /s") , "T1083_filedisco",
        "")
    | where cat != ""
    | project TimeGenerated, DeviceName, InitiatingProcessId, cat, ProcessCommandLine;
disco
| summarize cats = make_set(cat), catcount = dcount(cat), cmds = make_set(ProcessCommandLine, 20),
            firstSeen = min(TimeGenerated), lastSeen = max(TimeGenerated)
          by DeviceName, InitiatingProcessId, bin(TimeGenerated, 30m)
| where catcount >= 2                                    // >=2 of the 3 discovery categories in 30 min
// anchor the "precedes" clause: same host has a service install or bulk staging within the next hour
| join kind=inner (
    DeviceEvents | where TimeGenerated > ago(win)
    | where ActionType in ("ServiceInstalled","ProcessCreatedUsingWmiCommandLineEvent")
    | project NextTime = TimeGenerated, DeviceName
  ) on DeviceName
| where NextTime between (lastSeen .. (lastSeen + 1h))
| order by catcount desc
```

## Triage guidance

- **Likely malicious:** a web server or ordinary workstation (not a jump box) emitting system-info + domain-enumeration + directory-listing within a tight window, immediately followed by service creation, WMIC/PsExec remote execution, or bulk file staging; discovery originating from a masquerading `calc.exe` (→ HUNT-03); the enumerating account being one flagged in the valid-account fan-out (→ HUNT-02).
- **Likely benign / expected:** IT inventory/asset tools (SCCM, Lansweeper), login scripts, and admins troubleshooting legitimately run `systeminfo`, `net view` and directory listings — baseline the hosts/accounts/tools that do this routinely and allowlist them. A monitoring account profiling hosts on a stable cadence is expected; a burst from an origin that has no business enumerating the domain, abutting remote execution, is not.
- **Pivot next:** identify the parent process and account driving the burst; if it is a RAT (→ HUNT-03/HUNT-06) or precedes mass deployment, pivot forward to the lateral spread (→ HUNT-02) and destructive precursors (→ HUNT-01). A recon burst tightly coupled to mass remote execution indicates an active operator on-keyboard → escalate to incident-response-coordinator.

## References

- https://research.checkpoint.com/2021/mosesstaff-targeting-israeli-companies/
- https://www.cybereason.com/blog/research/strifewater-rat-iranian-apt-moses-staff-adds-new-trojan-to-ransomware-operations
- https://attack.mitre.org/techniques/T1082/
- https://attack.mitre.org/techniques/T1018/
- https://attack.mitre.org/techniques/T1083/
