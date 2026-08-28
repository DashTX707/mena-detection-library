# Hunt: OilRig defense evasion — sensitive registry modification & post-execution file deletion

- **Hypothesis:** If OilRig is operating on a host, then `reg.exe`/API registry writes to *sensitive* keys (LSA, Run, proxy, firewall) and deletion of payload files shortly after their execution will appear together — a configuration-change-then-cleanup footprint that a normal user process would not produce.
- **ATT&CK:**
  - T1112 — Modify Registry (defense-evasion)
  - T1070.004 — Indicator Removal: File Deletion (defense-evasion)
- **Actor procedure:** OilRig **uses `reg.exe` to modify system configuration** and **deletes files associated with its payload after execution** to remove evidence.
- **Why a hunt, not a rule:** registry-write and file-delete volume is enormous — updaters, installers and the OS churn both constantly. A blanket alert is unusable. The hunt narrows to *sensitive keys* and to deletes that closely follow a write+execute of the same file by the same process — correlation and baselining work, not a single-event rule.

## Data sources required

- Sysmon EID 12/13/14 (registry add/set/delete) filtered to LSA, `Run`/`RunOnce`, `Internet Settings\ProxyServer`, firewall policy keys
- Sysmon EID 11 (file create) + EID 23/26 (file delete / FileDeleteDetected)
- Windows Security 4688 for `reg.exe` command lines

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint source=*Sysmon*
| eval key=lower(TargetObject)
| eval sensitive=if(match(key,"(currentcontrolset\\\\control\\\\lsa|\\\\run(once)?\\\\|internet settings\\\\proxyserver|sharedaccess\\\\parameters\\\\firewallpolicy)"),1,0)
| eval evt=case(EventCode IN (12,13,14),"reg_mod", EventCode=11,"file_write", EventCode IN (23,26),"file_delete", 1=1,null())
| where isnotnull(evt) AND (sensitive=1 OR evt="file_delete")
| bin _time span=15m
| stats values(evt) as events values(key) as keys values(TargetFilename) as files
        values(Image) as procs dc(evt) as kinds by _time, host
| where kinds >= 2 OR keys!=""
| sort -_time
```

## Triage guidance

- **Likely malicious:** a write to LSA `Notification Packages`/`Run`/proxy/firewall-policy keys by a script host or unsigned process (correlate with detection-lane password-filter/firewall hunts); a payload file created, executed, and deleted within minutes by the same non-updater process; deletion of files in `%TEMP%`/`\ProgramData` right after C2 activity.
- **Likely benign / expected:** software installers/updaters modifying Run keys and cleaning up temp files; GPO-driven proxy/firewall changes; browser cache churn. Baseline by signed publisher and known management tooling.
- **Pivot next:** recover the deleted filename/hash from EDR and pivot to masquerading (HUNT-07) and staging (HUNT-05); if an LSA/firewall key was touched, cross-check the detection-lane password-filter-DLL and netsh-firewall rules and escalate.

## References

- https://attack.mitre.org/groups/G0049/
