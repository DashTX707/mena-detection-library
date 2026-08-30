# Hunt: StrongPity — low-signal host/environment recon in a tight post-execution window

- **Hypothesis:** If a StrongPity dropper has just run on a host, then in the *minutes after* the trojanized installer executes, its components perform a compact burst of environment reconnaissance — enumerating running processes (to check for security tools and target apps), enumerating local/removable storage volumes (to locate documents), and querying system network configuration — before collection begins. Each of these is individually ubiquitous and near-worthless as a standalone signal; the hypothesis keys on the **improper-timing / unexpected-relationship** stacking: process + storage + network-config discovery clustered within a short window, emitted by a *single non-administrative, non-management process* whose parent is a freshly-written installer/`%temp%` binary rather than an interactive shell or a known IT tool. One recon call is noise; the tight co-occurring cluster under a suspicious lineage is the finding.
- **ATT&CK:**
  - T1057 — Process Discovery (discovery) — enumerating running processes for security-product and target-app checks; hunt only inside a tight process-lineage window.
  - T1680 — Local Storage Discovery (discovery) — enumerating local/removable volumes to locate documents for collection.
  - T1016 — System Network Configuration Discovery (discovery) — querying host network configuration as part of environment checks.

- **Actor procedure:** Per S0491/Bitdefender, StrongPity runs environment checks as it lands: it enumerates running processes (feeding its ESET/Bitdefender security-software check and its search for target tools like `putty.exe`/`filezilla.exe`/`winscp.exe`/`mstsc.exe`/`mRemoteNG.exe`), enumerates local and removable storage volumes to locate collectible documents, and gathers system network-configuration information. These run automatically from the dropped components (not from an interactive operator), so the discriminating context is the *actor* (a `%temp%`/dropped binary or a masqueraded component such as `nvvscv.exe`/`procexp.exe`/`wmpsvn32.exe`) and the *tight clustering* right after user execution — not any single API/command.
- **Why a hunt, not a rule:** Process, storage, and network-configuration enumeration are among the noisiest events in any environment — installers, inventory agents, EDR itself, backup software and login scripts all do them constantly. Any standalone alert would be unusable. The signal exists only in *correlation*: several distinct discovery classes co-occurring in a short window under an anomalous parent lineage. That windowing-and-lineage judgement is hunt work. This hunt is deliberately scoped to run *pivoting off* a HUNT-01/HUNT-02/HUNT-05 lead (a suspicious installer/drop already in view) — used cold across the fleet it is a baseline-hygiene sweep, not a precise detection.

## Data sources required

- Process-creation telemetry with full command line and parent lineage (Sysmon Event ID 1 / EDR `DeviceProcessEvents`) — to attribute discovery to a dropped/`%temp%` parent
- Command-line / API telemetry for discovery utilities (`tasklist`, `wmic process`, `net config`, `ipconfig /all`, `wmic logicaldisk`, `fsutil fsinfo drives`, `Get-PSDrive`, `GetLogicalDrives`)
- EDR file-write telemetry to identify freshly-dropped binaries in `%temp%`/AppData as candidate parents (join key)

## Query starting point

Platform: `EDR (Microsoft Defender Advanced Hunting / KQL)` — cluster multiple discovery classes under one suspicious parent within a short window

```kusto
let lookback = 21d;
let discovery = DeviceProcessEvents
    | where TimeGenerated > ago(lookback)
    | extend cls = case(
        FileName in~ ("tasklist.exe") or ProcessCommandLine has_any ("process list","wmic process","Get-Process"), "process",
        ProcessCommandLine has_any ("logicaldisk","fsutil fsinfo drives","Get-PSDrive","GetLogicalDrives","wmic volume"), "storage",
        FileName in~ ("ipconfig.exe","netsh.exe") or ProcessCommandLine has_any ("net config","ipconfig /all","getmac","route print"), "netconfig",
        "other")
    | where cls != "other"
    | project TimeGenerated, DeviceName, cls, InitiatingProcessFileName, InitiatingProcessFolderPath,
              InitiatingProcessAccountName, InitiatingProcessParentFileName, ProcessCommandLine;
discovery
// Suspicious parent lineage: launched from %temp%/AppData or a masqueraded component, not a known admin/IT tool
| where InitiatingProcessFolderPath has_any ("\\Temp\\","\\AppData\\","lang_")
    or InitiatingProcessFileName in~ ("nvvscv.exe","procexp.exe","wmpsvn32.exe","wndplyr.exe")
| summarize classes = make_set(cls), classcount = dcount(cls), cmds = make_set(ProcessCommandLine, 12),
            firsttime = min(TimeGenerated), lasttime = max(TimeGenerated)
        by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, bin(TimeGenerated, 10m)
| where classcount >= 2      // >=2 distinct discovery classes co-occurring in the same 10-min window under one parent
| order by classcount desc, lasttime desc
```

## Triage guidance

- **Likely malicious:** two or more distinct discovery classes (process + storage + net-config) fired within minutes by a single `%temp%`/`lang_*`/masqueraded-name process that has no interactive session and was not launched by an inventory/EDR agent — especially if that same parent then reads documents in bulk or writes hidden `.sft` files (cross to detection-pack T1083/T1119/T1074.001). Discovery specifically probing for `putty/filezilla/winscp/mstsc/mRemoteNG` presence is a strong StrongPity-specific tell.
- **Likely benign / expected:** software installers, asset-inventory agents (SCCM/Intune/Lansweeper), EDR/AV, backup jobs, and admin login scripts legitimately run exactly this recon at scale — baseline and exclude those parent processes/accounts. A single discovery command in isolation, or discovery from a signed IT tool under an admin session, is expected and not a finding.
- **Pivot next:** confirm the parent binary's provenance (was it dropped by a trojanized installer? — pivot to HUNT-01/HUNT-02) and its signature/Defender-tamper behavior (HUNT-03, detection-pack T1685). If the recon burst is followed by document collection/staging, treat as an active StrongPity host compromise and escalate onto the collection/exfil kill chain (detection-pack T1119/T1074.001/T1560.003/T1041), and to incident-response-coordinator.

## References

- https://www.bitdefender.com/files/News/CaseStudies/study/353/Bitdefender-Whitepaper-StrongPity-APT.pdf
- https://attack.mitre.org/software/S0491/
- https://attack.mitre.org/techniques/T1057/
- https://attack.mitre.org/techniques/T1680/
- https://attack.mitre.org/techniques/T1016/
