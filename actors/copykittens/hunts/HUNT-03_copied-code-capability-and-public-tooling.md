# Hunt: CopyKittens — copied-code capability development and public-tool acquisition, hunted at downstream use

- **Hypothesis:** CopyKittens is defined by reliance on copied/public code — a "technically unsophisticated but persistent" group that assembles custom malware (Matryoshka, TDTESS, Vminst, NetSrv, ZPP) from borrowed code and operationalizes off-the-shelf offensive tools (Cobalt Strike, Empire, Mimikatz, Metasploit/Meterpreter, NBTScanner). The capability *development* and tool *acquisition* are off-victim, but the tell that they landed here is the downstream tool-use fingerprint: default/known-signature framework artifacts (Cobalt Strike default named pipes/beacon profiles, Empire PowerShell module patterns, Mimikatz command lines, Meterpreter injection, NBTScanner banners) appearing together on hosts that *also* show the custom-loader lineage (rundll32-hosted DLL, NetSrv loader, TDTESS service). Because the group copies rather than innovates, their toolchain leaves recognizable, code-reuse-linked artifacts — the hunt is to find those known-tool fingerprints co-located with the custom-malware family markers, which is what distinguishes a CopyKittens operation from a lone commodity-tool false positive.
- **ATT&CK:**
  - T1587.001 — Develop Capabilities: Malware (resource-development) — self-developed Matryoshka/TDTESS/Vminst/NetSrv/ZPP assembled from copied code; hunted via malware-family clustering and code-reuse markers of the custom loaders landing on hosts.
  - T1588.002 — Obtain Capabilities: Tool (resource-development) — operationalized Cobalt Strike, Empire, Mimikatz, Metasploit/Meterpreter, NBTScanner; hunted at the point of downstream on-victim tool use where the acquisition finally becomes observable.

- **Actor procedure:** CopyKittens builds a small family of custom tools — Matryoshka RAT (DNS C2), the TDTESS backdoor (Windows-service persistence, HTTP reverse shell), Vminst (lateral movement), NetSrv (a Cobalt Strike loader), and ZPP (archiver) — frequently stitched together from public/copied code (T1587.001). Alongside these they lean heavily on unmodified public offensive frameworks (T1588.002): Cobalt Strike and NetSrv for beaconing, Empire for PowerShell post-exploitation, Mimikatz for LSASS credential dumping, Metasploit/Meterpreter shellcode injected via rundll32-hosted components, and NBTScanner for internal network discovery. Because little is bespoke, both the custom loaders and the commodity tools carry well-known, reuse-linked signatures — which is precisely why the group is trackable despite low sophistication.
- **Why a hunt, not a rule:** Developing malware and downloading Cobalt Strike happen entirely off our estate — unobservable. And commodity tools are dual-use: a naive "Cobalt Strike beacon" or "Mimikatz string" rule fires on red-team engagements, pentests, sanctioned admin scripts and EDR test traffic. The signal that this is *CopyKittens* is the **clustering** — several borrowed-tool fingerprints appearing together, and specifically co-located with the group's custom-loader lineage (NetSrv/TDTESS/rundll32-DLL) — judged against sanctioned-tooling inventory. That clustering and code-reuse attribution is hunt work; the individual high-fidelity tool signatures (Mimikatz LSASS, Empire/CS PowerShell, NBTScanner) already live as rules in the detection pack (T1003.001, T1059.001, T1046) and this hunt correlates across them rather than re-alerting.
- Note: T1003.001, T1059.001 and T1046 named below are **detection-lane** techniques cited only as the downstream anchors this hunt pivots through; the coverage this hunt owns is the two resource-development ids above.

## Data sources required

- EDR process-creation + command-line + named-pipe + image-load telemetry (Cobalt Strike default pipes/beacon, Empire modules, Mimikatz, Meterpreter injection)
- Sysmon (EID 1/7/17/18) for module loads, named pipes, and rundll32/DLL loader lineage (NetSrv/TDTESS custom loaders)
- Sanctioned offensive-tooling inventory (approved red-team hosts, pentest windows, EDR test signatures) for suppression
- Threat-intel: CopyKittens custom-malware family markers (Matryoshka/TDTESS/NetSrv/ZPP) and code-reuse indicators for clustering

## Query starting point

Platform: `EDR (Microsoft Defender / CrowdStrike-style) via KQL` — cluster multiple borrowed-tool fingerprints per host and intersect with custom-loader lineage

```kusto
let window = 21d;
// Weak per-tool fingerprints; the finding is >=2 distinct families on one host
let tools = DeviceProcessEvents
    | where Timestamp > ago(window)
    | extend fam = case(
        ProcessCommandLine has_any ("sekurlsa","logonpasswords","lsadump") or FileName =~ "mimikatz.exe", "mimikatz",
        ProcessCommandLine has_any ("-enc","-encodedcommand","IEX","Invoke-Empire","System.Net.WebClient"), "ps_empire_cs",
        FileName has_any ("nbtscan.exe","nbtscanner.exe") or ProcessCommandLine has "nbtscan", "nbtscanner",
        InitiatingProcessFileName =~ "rundll32.exe" and FileName endswith ".dll" and FolderPath has_any ("\\Temp\\","\\Users\\","\\AppData\\"), "rundll32_loader",
        "")
    | where isnotempty(fam)
    | summarize families=make_set(fam), hits=count(), procs=make_set(ProcessCommandLine,20) by DeviceName;
// Custom-loader / named-pipe lineage that marks a CopyKittens toolchain (NetSrv/TDTESS/CS default pipe)
let loaders = DeviceEvents
    | where Timestamp > ago(window)
    | where ActionType == "NamedPipeEvent" and PipeName has_any ("\\msagent_","\\postex_","\\status_","\\MSSE-")
          or (ActionType == "ServiceInstalled" and FolderPath has_any ("\\Temp\\","\\Users\\"))
    | summarize pipe_or_svc=make_set(coalesce(PipeName, FolderPath),20) by DeviceName;
tools
| where array_length(families) >= 2                    // >=2 borrowed-tool families = cluster
| join kind=leftouter (loaders) on DeviceName
| project DeviceName, families, hits, has_custom_loader = isnotempty(pipe_or_svc), pipe_or_svc, procs
| order by array_length(families) desc, has_custom_loader desc
```

## Triage guidance

- **Likely malicious:** one host showing two or more distinct borrowed-tool families (e.g., Mimikatz LSASS access **and** Empire/Cobalt Strike encoded PowerShell **and** NBTScanner sweeps) within a tight window, especially co-located with a custom-loader signal (rundll32-hosted DLL from a temp/user path, a Cobalt-Strike default named pipe, or a service installed from a temp path — NetSrv/TDTESS). Code-reuse markers matching the Matryoshka/TDTESS families raise confidence toward attribution.
- **Likely benign / expected:** sanctioned red-team and pentest engagements reproduce this exact cluster — always check the sanctioned-tooling inventory and change calendar first; EDR/AV self-tests and security-training labs emit Mimikatz/Meterpreter strings; some admin automation uses encoded PowerShell and `WebClient`. A single family on one host inside an approved window is expected; multi-family clustering on a production host with no change ticket is not.
- **Pivot next:** if the cluster is real and unsanctioned, pivot to credential-access blast radius (detection pack T1003.001 — what did Mimikatz touch), lateral movement (T1021.002 Vminst/SMB), the C2 channel (HUNT-01 Matryoshka DNS, detection pack T1071.001 TDTESS HTTP), and persistence (T1543.003 service / T1547.001 run-keys). Confirmed multi-tool intrusion escalates to incident-response-coordinator; feed newly-observed custom-loader markers back to threat-intel for family clustering.

## References

- https://www.clearskysec.com/wp-content/uploads/2017/07/Operation_Wilted_Tulip.pdf
- https://attack.mitre.org/groups/G0052/
- https://attack.mitre.org/techniques/T1587/001/
- https://attack.mitre.org/techniques/T1588/002/
