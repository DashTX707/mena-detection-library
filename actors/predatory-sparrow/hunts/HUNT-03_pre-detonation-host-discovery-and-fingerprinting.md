# Hunt: Predatory Sparrow — pre-detonation host discovery & per-OS fingerprinting inside the estate

- **Hypothesis:** Immediately before it wipes, the Meteor toolchain **fingerprints each host and enumerates running processes** so it can branch per-OS and free file handles for destruction. If the actor is staged in our estate in the minutes-to-hours before a synchronized detonation, the observable is a **tight, low-variance discovery burst on many hosts at once**: OS-version checks (T1082) that select the correct component set (a separate `envxp.bat` path for Windows XP; distinct lock-screen images for XP/7/10), and process enumeration (T1057) driven by the wiper's configurable `processes_to_kill` list. Because this discovery is *scripted, identical across hosts, and clustered in time* — not the organic, varied discovery of an admin or a scanner — the finding is the **synchronization and uniformity**: the same discovery commands, from the same parent lineage (a `.vbs`/batch chain), firing across a fleet within a narrow window. A single host running `systeminfo` is nothing; twenty hosts running the *same* fingerprint-then-enumerate sequence in the same ten minutes is a detonation about to happen.
- **ATT&CK:**
  - T1082 — System Information Discovery (execution/discovery) — per-OS branching (`envxp.bat` for XP; distinct XP/7/10 lock-screen assets) requires host OS/version fingerprinting immediately before payload selection.
  - T1057 — Process Discovery (discovery) — the encrypted `msconf.conf` carries a `processes_to_kill` list the wiper enumerates and terminates to free handles and disable defences just before/while wiping.

- **Actor procedure:** The toolchain fingerprints the host OS to choose components — SentinelLabs found a dedicated legacy path (`envxp.bat`) for Windows XP and OS-specific lock-screen images for XP/7/10, indicating explicit per-OS branching. The Meteor wiper's encrypted configuration (`msconf.conf`, XOR key `abcdz`) contains a configurable `processes_to_kill` list, which the wiper enumerates and terminates prior to and during the wipe to release file handles and stop defensive processes. Both actions are transient and are *immediately followed by destruction* — which is precisely why they are hunt candidates rather than reliable standalone detections: in a single-host post-mortem the evidence is usually wiped. The only durable signal is *cross-host*, caught in the pre-detonation window while the discovery is fanning out but the wipe has not yet fired.

- **Why a hunt, not a rule:** `systeminfo`, `tasklist`, `ver`, `wmic os get`, and process enumeration are among the most common benign commands on any Windows estate — an alert on them is unusable. The malicious signal is not the command but the **pattern**: identical scripted discovery, spawned from a `wscript`/`cscript`→`cmd.exe` batch lineage, replicated across many hosts inside a short window that lines up with a staged scheduled task. Establishing that "same sequence, many hosts, tight window, wiper-consistent parentage" requires cross-host correlation and lineage judgement — hunt work, not a single-event rule. A durable relational analytic *may* fall out (e.g., "process-discovery command whose grandparent is `wscript.exe` running a `.vbs` and which is observed on ≥N hosts within M minutes") and that is a fair handoff to detection-engineering.

## Data sources required

- EDR process-creation telemetry with full command line and **parent/grandparent lineage** (Sysmon EID 1 / Defender `DeviceProcessEvents`): discovery binaries and their `wscript`/`cscript`/`cmd.exe` ancestry
- Cross-host time correlation capability (the whole hunt is a fleet-wide burst query, not a per-host one)
- Scheduled-task and script-staging context from the destructive-detection lane (`mstask` at 23:55, `resolve.vbs`, the `setup.bat`→`update.bat`→`cache.bat` chain) to tie discovery to imminent detonation
- Baseline of sanctioned inventory/monitoring tools that legitimately run fleet-wide discovery on a schedule (SCCM, Nessus, Tanium) — from the hunting wiki

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — find the *synchronized, wiper-parented* discovery burst, not the individual command

```kusto
let window = 15m;
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName in~ ("systeminfo.exe","tasklist.exe","ver","wmic.exe","qprocess.exe","reg.exe")
      or ProcessCommandLine has_any ("os get","get-process","tasklist","systeminfo","ProductName","CurrentVersion")
// wiper-consistent lineage: discovery spawned by a script host / batch chain, not by an interactive admin shell
| where InitiatingProcessParentFileName in~ ("wscript.exe","cscript.exe","cmd.exe")
      or InitiatingProcessFileName in~ ("cmd.exe","wscript.exe","cscript.exe")
| where InitiatingProcessCommandLine has_any (".vbs",".bat","resolve","setup","cache","envxp","update")
      or InitiatingProcessCommandLine !has "sccm"        // drop known-benign management chains (baseline in wiki)
| summarize hosts = dcount(DeviceName), hostset = make_set(DeviceName, 60),
            cmds = make_set(ProcessCommandLine, 15), first = min(TimeGenerated), last = max(TimeGenerated)
         by bin(TimeGenerated, window), FileName, InitiatingProcessParentFileName
| where hosts >= 10                                       // synchronized fan-out = pre-detonation staging, not one admin
| extend spread = last - first
| order by hosts desc
```

## Triage guidance

- **Likely malicious:** the *same* OS-fingerprint + process-enumeration sequence appearing on 10+ hosts inside one short window, spawned from a `wscript.exe`/`cscript.exe` running a `.vbs` or from a named batch chain (`setup.bat`/`cache.bat`/`envxp.bat`); discovery that co-occurs on hosts where a scheduled task named `mstask` (23:55) was just created or where Defender exclusions were just added; process enumeration explicitly targeting security/backup processes immediately before file-modification bursts begin.
- **Likely benign / expected:** SCCM/Tanium/Nessus/Lansweeper inventory sweeps run identical discovery fleet-wide on a schedule — these are the dominant false positive and must be baselined by their service account, source host, and known cadence in the wiki; login scripts and monitoring agents also fingerprint OS at logon. The differentiator is **parentage and companion activity**: sanctioned tools run under their own service context with no `.vbs`/wiper-named parent and no adjacent scheduled-task/Defender-exclusion staging.
- **Pivot next:** a synchronized, script-parented discovery burst that is *not* an approved inventory tool is a detonation-imminent signal — escalate to incident-response-coordinator immediately, do not wait to confirm the wipe. Pivot to the destructive-detection lane on the same host set (T1053.005 `mstask`, T1685 Defender exclusions, T1490 shadow-copy/boot sabotage, T1485/T1561.002 wipe) and to HUNT-01/HUNT-02 for the entry and recon that preceded it. Isolate the affected hosts and the parent jump host before the 23:55 (or equivalent staged) trigger fires.

## References

- https://www.sentinelone.com/labs/meteorexpress-mysterious-wiper-paralyzes-iranian-trains-with-epic-troll/
- https://attack.mitre.org/techniques/T1082/
- https://attack.mitre.org/techniques/T1057/
