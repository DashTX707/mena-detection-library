# Hunt: SideWinder — low-signal fingerprinting & in-memory decode blending inside the loader lineage

- **Hypothesis:** If the SideWinder chain has executed on a host, then the individually-invisible primitives — a system-time query, an in-memory Base64/decrypt-and-load step that never touches disk — will not appear in isolation but *clustered inside a tight, anomalous process lineage*: mshta.exe (remote URL) → obfuscated JavaScript → in-memory .NET ModuleInstaller, with environment fingerprinting (system time, RAM size, `nlssorting.dll`/AV enumeration) and staged in-memory decode all firing within the same short window under a process tree that began with Office/EQNEDT32 or a LNK. On their own, `GetSystemTime` and an in-memory decode are ubiquitous and un-alertable; the finding is these low-signal acts *co-occurring* under the SideWinder loader lineage, where they have no business being.
- **ATT&CK:**
  - T1124 — System Time Discovery (discovery) — SideWinder tooling queries system time as part of environment fingerprinting/gating; ubiquitous alone, meaningful only inside the loader lineage window.
  - T1140 — Deobfuscate/Decode Files or Information (stealth) — each stage decodes/decrypts the next in memory: the JavaScript Base64-decodes the serialized .NET ModuleInstaller, and the Backdoor Loader decrypts the StealerBot implant before loading it — little discrete on-disk signal, hunted via the process/CLR lineage rather than a file artifact.

- **Actor procedure:** After the CVE-2017-11882 exploit or LNK launches mshta.exe against a remote HTA, a heavily-obfuscated JavaScript stage runs under mshta: it enumerates installed .NET Framework versions, sets `COMPLUS_Version`, Base64-decodes a serialized .NET ModuleInstaller and loads it directly in memory (reflective loading, no PE on disk). ModuleInstaller performs anti-analysis system checks (RAM > ~950 MB, probe for `nlssorting.dll`), queries system time, and enumerates ~137 security-product process names via WMI before deploying the Backdoor Loader, which in turn decrypts and loads StealerBot in memory. The decode/decrypt and time/environment checks are deliberate low-signal steps designed to leave minimal discrete telemetry.
- **Why a hunt, not a rule:** `T1124` system-time queries and generic in-memory decode routines are among the noisiest, lowest-fidelity signals on any Windows host — alerting on either would bury an analyst, and the decode leaves essentially no discrete artifact to key on. Their value is purely *contextual*: they become meaningful only when correlated inside the narrow mshta→JavaScript→in-memory-.NET lineage over a few minutes. That correlation and lineage-reconstruction is hunt work — reasoning about which un-alertable primitives cluster under an anomalous parent — not a standalone detection. The high-fidelity anchors in this tree (EQNEDT32→mshta, `COMPLUS_Version` manipulation, side-load) belong to the detection lane; this hunt exists to catch the *stealthier* co-occurring steps and to confirm scope when an anchor fires.

## Data sources required

- EDR / Sysmon process-creation with full command line + parent lineage (EID 1) — reconstruct mshta→script→.NET tree
- Sysmon EID 7 (image/module load) and CLR/AMSI script-block + assembly-load telemetry — catch in-memory .NET load and decode without a disk artifact
- Process environment-variable and API-behavior telemetry (`COMPLUS_Version` set; `GetSystemTime`/`GetLocalTime` and RAM/`nlssorting.dll` checks by a freshly-spawned .NET process)
- WMI-Activity operational log (SecurityCenter2 / AntiVirusProduct enumeration co-occurring in the same window)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — anchor on the mshta/.NET loader lineage, then confirm the low-signal decode + time/environment fingerprinting clustered inside it

```kusto
// Anchor: mshta (remote URL) or a freshly-spawned .NET process under an Office/EQNEDT32/LNK ancestor
let anchors = DeviceProcessEvents
    | where TimeGenerated > ago(14d)
    | where (FileName =~ "mshta.exe" and ProcessCommandLine has_any ("http://","https://",".hta","RunHTMLApplication"))
         or (InitiatingProcessFileName in~ ("eqnedt32.exe","winword.exe","excel.exe","explorer.exe")
             and ProcessCommandLine has_any ("COMPLUS_Version","mshta"))
    | project AnchorTime = TimeGenerated, DeviceName, anchorPid = ProcessId, ProcessCommandLine, InitiatingProcessFileName;
// Low-signal co-occurrence within a tight window on the same host: system-time query + in-memory decode/.NET load + AV enumeration
let lowsignal = union
    ( DeviceProcessEvents
        | where ProcessCommandLine has_any ("GetSystemTime","w32tm","systeminfo","Get-Date","time /t") ),  // T1124-ish surface
    ( DeviceEvents
        | where ActionType in ("ClrLoad","AmsiScan","PowerShellCommand")
             or AdditionalFields has_any ("FromBase64","Reflection.Assembly","RunHTMLApplication","nlssorting") ) // T1140 / in-mem load
    | project LsTime = TimeGenerated, DeviceName, LsProcess = InitiatingProcessFileName, ActionType, ProcessCommandLine;
anchors
| join kind=inner (lowsignal) on DeviceName
| where LsTime between (AnchorTime .. (AnchorTime + 10m))     // clustered inside the loader window, not scattered
| summarize signals = make_set(strcat(ActionType, ":", LsProcess), 20), lowsignal_events = count(),
            window_start = min(AnchorTime), window_end = max(LsTime)
         by DeviceName, ProcessCommandLine
| where lowsignal_events >= 2                                 // >=2 co-occurring low-signal acts under the anchor = stacked
| order by lowsignal_events desc
```

## Triage guidance

- **Likely malicious:** a system-time query and an in-memory Base64/`Reflection.Assembly` decode-and-load firing within minutes of an mshta-remote-URL or `COMPLUS_Version`-setting process, under an Office/EQNEDT32/LNK ancestor; probes for `nlssorting.dll` and a RAM-size check by the same freshly-spawned .NET process; the same short window also carrying WMI SecurityCenter2/AntiVirusProduct enumeration (~137-process fingerprint). The *stack* of low-signal acts under the anchor is the tell.
- **Likely benign / expected:** `w32tm`/`Get-Date`/`systeminfo` run by admins, logon scripts, monitoring agents and software installers — expected in isolation and outside any mshta/.NET-loader lineage; legitimate .NET applications loading assemblies in memory; AV/EDR products themselves enumerating security processes. None of these should sit *inside* an mshta-remote-URL process tree — the lineage is what separates signal from noise. A lone time query or a lone decode with no anchor is not a finding.
- **Pivot next:** if the low-signal cluster confirms under a live mshta/.NET lineage, you have an executing SideWinder chain — escalate to incident-response-coordinator, capture memory for the in-memory ModuleInstaller/StealerBot (nothing on disk to grab), and pivot to persistence (T1547.001/T1053.005), credential theft (T1003.001/T1555.003) and C2 (T1071.001) from the detection pack. Cross-reference HUNT-03 to see whether a re-tooled variant follows any quarantine. Retain the decode/lineage pattern for cti-expert; the ubiquity of the primitives means it stays a hunt, not a rule.

## References

- https://securelist.com/sidewinder-apt-updates-its-toolset-and-targets-nuclear-sector/115847/
- https://thehackernews.com/2024/10/sidewinder-apt-strikes-middle-east-and.html
- https://attack.mitre.org/groups/G0121/
- https://attack.mitre.org/techniques/T1124/
- https://attack.mitre.org/techniques/T1140/
