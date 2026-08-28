# Hunt: UAC bypass privilege escalation

- **Hypothesis:** If MuddyWater elevated on this host, then we should observe a known UAC-bypass primitive — an auto-elevating Windows binary (`fodhelper.exe`, `eventvwr.exe`, `sdclt.exe`, `computerdefaults.exe`, `cmstp.exe`) spawning a script/attacker child, preceded by hijack-registry writes (e.g. `...\shell\open\command`, `mscfile`, `ms-settings`) — a path/property mismatch where an integrity boundary is crossed without a UAC prompt.
- **ATT&CK:**
  - T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control (privilege-escalation)
- **Actor procedure:** MuddyWater **uses various techniques to bypass UAC** to run payloads with elevated integrity.
- **Why a hunt, not a rule:** The individual auto-elevating binaries also run legitimately, and specific bypass variants come and go, so a static rule chasing one filename ages out. The durable hunt is the *behavioral shape* — an auto-elevator spawning an unexpected child at higher integrity, optionally with the tell-tale registry hijack write — which needs baselining of normal fodhelper/eventvwr usage per environment.

## Data sources required

- Sysmon EID 1 / Security 4688 (process create with parent + integrity level)
- Sysmon EID 13 (registry writes to known UAC-bypass hijack keys)
- PowerShell 4104 (elevated script blocks)

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (EventCode=1 OR EventCode=4688)
| eval parent=lower(coalesce(ParentImage,Parent_Process_Name))
| eval child=lower(coalesce(Image,New_Process_Name))
| eval integ=lower(coalesce(IntegrityLevel,Token_Elevation_Type))
| where match(parent,"(fodhelper|eventvwr|sdclt|computerdefaults|slui|wsreset|cmstp)\.exe")
| where match(child,"(powershell|cmd|wscript|cscript|mshta|rundll32)\.exe")
| append [ search index=endpoint EventCode=13
    (TargetObject="*\\ms-settings\\shell\\open\\command*"
     OR TargetObject="*\\mscfile\\shell\\open\\command*"
     OR TargetObject="*\\Classes\\exefile\\shell\\*"
     OR TargetObject="*\\Folder\\shell\\open\\command*")
  | eval regkey_hijack=1 ]
| stats values(child) as children values(integ) as integrity values(CommandLine) as cmds
        values(TargetObject) as hijack_keys by host, user, parent
| sort - children
```

## Triage guidance

- **Likely malicious:** `fodhelper.exe`/`eventvwr.exe`/`sdclt.exe`/`computerdefaults.exe` spawning `powershell.exe`/`cmd.exe`/`mshta.exe` at High integrity; a preceding write to `ms-settings`/`mscfile`/`exefile` `shell\open\command` hijack keys; child command line with encoded/download content; on a workstation with no admin activity ticket.
- **Likely benign / expected:** A user genuinely opening Event Viewer, Optional Features, Backup/Restore, or Windows Update settings; legitimate admin elevation. Baseline normal interactive usage of these binaries per host.
- **Pivot next:** What ran elevated next (credential dumping HUNT-08, persistence, RMM install — detection lane); registry-hijack key contents; correlate with the initial-access chain (HUNT-12).

## References

- https://attack.mitre.org/groups/G0069/
