# Hunt: Infy (Prince of Persia) — low-signal host profiling burst correlated with beacon

- **Hypothesis:** Infy/Foudre act as downloader-profilers: they fingerprint the host and post the profile to C2 so the operator can pick "machines of interest" for the higher-value Tonnerre implant. Any single profiling call is invisible noise — but if an implant is present, then a *single short-lived process* fires a **tight burst** of profiling primitives back-to-back (computer name, username, OS version, CPU ID, machine GUID, drive/disk enumeration) *and* enumerates running processes (partly to spot AV), and does so in the *same minute window* that the host makes its first outbound beacon. The falsifiable signature is the co-location in one process lineage: system-info discovery + process discovery + an immediately-following small HTTP(S) POST. Each primitive alone is ubiquitous; the burst-then-beacon stack on one non-interactive process is the finding.
- **ATT&CK:**
  - T1082 — System Information Discovery (discovery) — implant profiles computer name, username, OS version, CPU ID, machine GUID and drive/disk info and posts it to C2 to rank victims; hunt the burst, not the single call.
  - T1057 — Process Discovery (discovery) — implant enumerates running processes as part of recon and to identify security products; hunt in the tight lineage window alongside the system-info burst.
  - T1071.001 — Web Protocols (command-and-control) — *context/corroborator*: the profile is posted to C2 on a fixed ~5-minute HTTP(S) beacon; the beacon time-bounds the profiling burst. (Detection-lane technique; cited as the correlating egress event.)
  - T1518.001 — Security Software Discovery (discovery) — *context*: the same recon enumerates/probes AV (Kaspersky, Avast, Trend Micro) so the implant can abort if AV is present. (Detection-lane technique; cited as a companion of the process-discovery burst.)

- **Actor procedure:** Foudre is explicitly a downloader/victim-profiler: it collects host profile data — computer name, username, OS version, CPU ID, machine GUID, drive enumeration and disk info — and posts it to C2 to identify high-value machines before pulling Tonnerre. Infy and Tonnerre enumerate running processes as part of reconnaissance and to identify security products, and Infy checks for AV directories (`GetFileAttributesA` against Kaspersky/Avast/Trend Micro) and will decline to install if AV is present. The implant then beacons on a fixed ~5-minute HTTP interval, posting the collected system information. The profiling is fast, scripted, and machine-driven — a dense cluster of API calls from one process, quite unlike a human running `systeminfo`/`tasklist` interactively.
- **Why a hunt, not a rule:** `GetComputerName`, `GetVersionEx`, machine-GUID reads, drive enumeration and process listing are among the most common calls in all of Windows — an alert on any one, or even a naive "N discovery calls" threshold, floods the SOC (every login script, inventory agent and installer trips it). The signal only exists as a *tight burst in one short-lived, non-interactive process lineage* that also produces an outbound beacon — a correlation and baselining problem, i.e. hunt work. If the burst-plus-beacon shape proves separable from benign inventory tooling on this estate, hand the process-lineage correlation (Level-4 relational observable) to detection-engineering; the individual discovery API is not alertable.

## Data sources required

- EDR / Sysmon process-creation (EID 1) + API/registry telemetry to observe the profiling primitives (machine-GUID key `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, `Win32_ComputerSystem`/`Win32_Processor` WMI, drive enumeration) and process-listing behavior from one process.
- Network/proxy egress (Zeek `http.log`, proxy) for the co-occurring outbound POST / fixed-interval beacon that time-bounds the burst.
- Optional: file-access telemetry on AV install directories (Kaspersky/Avast/Trend Micro paths) for the security-software-discovery corroborator.

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — find a single process that stacks system-info + process discovery, then require a beacon from the same host inside the window.

```kusto
let window = 10m;
let profilers = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where ProcessCommandLine has_any ("systeminfo","MachineGuid","Win32_ComputerSystem","Win32_Processor","wmic os","tasklist","Get-Process")
        or FileName in~ ("systeminfo.exe","tasklist.exe","wmic.exe")
    | summarize burst=count(), verbs=make_set(FileName,15), first=min(Timestamp), last=max(Timestamp)
             by DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessAccountName
    | where burst >= 4 and (last - first) < window                 // dense machine-driven burst, not interactive
    | where InitiatingProcessFileName !in~ ("cscript.exe","gpscript.exe","ccmexec.exe","sccm.exe"); // baseline inventory
profilers
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemotePort in (80,443) and ActionType == "ConnectionSuccess"
    | project beaconTime=Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessId
  ) on DeviceName, InitiatingProcessId
| where beaconTime between (first .. last + window)                // beacon co-located with the profiling burst
| project first, last, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, burst, verbs, beaconTime, RemoteUrl, RemoteIP
| order by first desc
```

## Triage guidance

- **Likely malicious:** a single short-lived, non-interactive process (especially a rundll32/DLL-loader lineage from HUNT-03, or an unsigned binary in a user-writable path) fires 4+ distinct profiling primitives and a process listing within a few minutes, reads `MachineGuid`, and the host beacons to an external low-reputation host in the same window — the Foudre profile-and-report pattern; extra weight if the process also touches AV install directories (T1518.001) or the beacon target matches a short-hex DGA domain from HUNT-01.
- **Likely benign / expected:** inventory/asset agents (SCCM/ConfigMgr, Intune, Lansweeper, Nessus/Qualys), login scripts and installers legitimately gather the exact same host facts on a schedule — baseline and exclude those process identities and their known egress. Interactive admin use of `systeminfo`/`tasklist` in a console session is expected; the discriminators are non-interactive lineage, burst density, and the co-located beacon to unfamiliar infrastructure.
- **Pivot next:** on a match, resolve the beacon target through HUNT-01 (cert/DGA) and the detection-lane C2 hunts, capture the parent loader for HUNT-03 memory analysis, and check whether Tonnerre-stage collection followed (HUNT-05, plus detection-lane keylog/screenshot/audio). A confirmed profile-and-beacon from an implant lineage is a live compromise — escalate to incident-response-coordinator.

## References

- https://unit42.paloaltonetworks.com/prince-of-persia-infy-malware-active-in-decade-of-targeted-attacks/
- https://unit42.paloaltonetworks.com/unit42-prince-persia-ride-lightning-infy-returns-foudre/
- https://research.checkpoint.com/2021/after-lightning-comes-thunder/
- https://attack.mitre.org/techniques/T1082/
- https://attack.mitre.org/techniques/T1057/
- https://attack.mitre.org/techniques/T1071/001/
- https://attack.mitre.org/techniques/T1518/001/
