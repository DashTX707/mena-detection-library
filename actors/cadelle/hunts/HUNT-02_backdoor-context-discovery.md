# Hunt: Cadelspy host-context discovery — application-window titles and system profiling

- **Hypothesis:** If Backdoor.Cadelspy is profiling a victim, then the same untrusted background process performing surveillance capture will also enumerate open application-window titles and gather system/host information — giving operators context on which apps the victim uses and the machine profile. The anomaly is an unexpected relationship: window-title enumeration and system-info APIs originating from a process that is *also* a persistent, non-interactive background binary rather than a foreground app or a legitimate inventory/management agent.
- **ATT&CK:**
  - T1010 — Application Window Discovery (discovery)
  - T1082 — System Information Discovery (discovery)
- **Actor procedure:** Cadelspy collects the titles of open application windows on the infected host to see which programs the victim is using and the content of active windows, and gathers system information (host/system details) to profile the victim environment for its operators. Both feed the same broad-surveillance dossier the backdoor compresses for exfiltration.
- **Why a hunt, not a rule:** `EnumWindows`/`GetWindowText` and `GetSystemInfo`/`GetComputerName`/systeminfo-style enumeration are ubiquitous benign APIs — every window manager, accessibility tool, inventory agent, and installer calls them — so they are un-alertable in isolation. This is hunt-only: the signal exists only *in the context of the backdoor process*, i.e. window-title reads correlated to the same process identified as doing multi-sensor capture (HUNT-01) or `.cab` staging. Attackers trivially change binary names, so the hunt keys on the process→behavior relationship, not on any static indicator.

## Data sources required

- Sysmon EID 1 / Security 4688 — process creation, image path, parent, integrity/signature
- EDR API telemetry — `EnumWindows`/`GetForegroundWindow`/`GetWindowTextW`, and `GetSystemInfo`/`GetNativeSystemInfo`/`GetComputerNameW` attributed to a process (where instrumented)
- Sysmon EID 1 command-line — LOLBin discovery fallbacks (`systeminfo`, `hostname`, `wmic os get`, `net config`) — used to catch dropper-driven profiling even without API telemetry
- Correlation input — process identifiers flagged by HUNT-01 (multi-sensor capture) and HUNT-03 (peripheral/print theft)

## Query starting point

Platform: `Splunk SPL`

```
``` start from processes already implicated in surveillance behavior ```
index=edr (api IN ("EnumWindows","GetWindowTextW","GetForegroundWindow","GetSystemInfo","GetNativeSystemInfo","GetComputerNameW"))
| eval prockey=coalesce(process_guid,ProcessGuid,lower(Image))
| stats values(api) as discovery_apis dc(api) as api_variety by prockey, host, Image
| where api_variety>=2 AND like(discovery_apis,"%Window%") AND (like(discovery_apis,"%System%") OR like(discovery_apis,"%Computer%"))
``` keep only untrusted / non-foreground-app processes ```
| search NOT Image IN ("*\\explorer.exe","*\\taskmgr.exe","*\\ProcessHacker.exe","*\\SearchApp.exe","*\\msmpeng.exe","*\\sccm*","*\\ccmexec.exe")
| append [
    search index=endpoint (EventCode=1 OR EventCode=4688)
      (CommandLine="*systeminfo*" OR CommandLine="*wmic os get*" OR CommandLine="*hostname*" OR CommandLine="*net config*")
    | eval parent=lower(coalesce(ParentImage,Parent_Process_Name))
    | where NOT match(parent,"(cmd|powershell)\.exe$") OR match(parent,"(temp|appdata|programdata|users\\\\public)")
    | stats count values(CommandLine) as profiling_cmds by host, parent ]
| table host, Image, discovery_apis, parent, profiling_cmds
```

## Triage guidance

- **Likely malicious:** A persistent background process (unsigned, in temp/AppData/ProgramData) that enumerates window titles AND reads system/computer info, especially when the same process identifier already appears in HUNT-01 (multi-sensor capture) or HUNT-03; discovery bursts on a fixed timer with no interactive user session.
- **Likely benign / expected:** Accessibility software, window managers, RMM/inventory/asset agents (SCCM/CCMExec, Lansweeper), EDR itself, installers running one-time system profiling. Baseline the approved inventory tooling per host and suppress.
- **Pivot next:** Do not treat this hunt as a finding on its own — it corroborates. If the enumerating process matches a HUNT-01/HUNT-03 process, escalate the *combined* case to incident-response-coordinator. If discovery is real but unattributed, mark inconclusive and pivot to the process's file-write and network behavior for the backdoor's `.cab` staging and C2.

## References

- https://attack.mitre.org/software/S0454/
- https://attack.mitre.org/techniques/T1010/
- https://attack.mitre.org/techniques/T1082/
- https://www.securityweek.com/apparently-linked-iran-spy-groups-target-middle-east/
- https://securityaffairs.com/42641/breaking-news/cadelle-and-chafer-iranian-hackers.html
