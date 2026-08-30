# Hunt: Tropic Trooper — post-foothold recon burst & post-op file-deletion cleanup

- **Hypothesis:** If the actor has a fresh web-shell foothold, then within a short window we should see a *recon burst* — a cluster of native discovery commands (`systeminfo`/`hostname`/`ver` for host info; `ipconfig`/`route`/`arp`/`net` for network config) plus the `i.bat` ICMP ping-sweep loop — all descending from `w3wp.exe`/`cmd.exe` on a web server that has no business running interactive admin commands, with output redirected to text files. Then, once tooling has done its job, a *cleanup tell*: rapid deletion of those same recon `.txt` files, dropped tools (Fscan/Swor/Neo-reGeorg) and intermediate artifacts by the same lineage. The finding is the shape — a tight discovery burst under a web-server process, optionally bookended by a deletion sweep of what it just created — not any one benign command. Individually these commands are ubiquitous; concentrated under `w3wp.exe` in a window they are the tell.
- **ATT&CK:**
  - T1082 — System Information Discovery (discovery) — actor enumerates OS/arch/config on compromised servers to tailor payloads/side-load targets; hunted only inside a tight recon-burst lineage window.
  - T1016 — System Network Configuration Discovery (discovery) — actor enumerates network config and adjacent hosts to plan pivoting/proxy placement; hunted in the same recon-burst context.
  - T1070.004 — Indicator Removal: File Deletion (defense-impairment) — actor removes intermediate tools and recon output after use (and iterates evasion-updated web shells to shrink footprint); hunted via file-delete auditing of what the same lineage just created.

- **Actor procedure:** After the China Chopper foothold, Tropic Trooper runs commands through the web shell and drops `i.bat` to perform ICMP ping sweeps, writing reachable-host results to text files for targeting (`T1018` in the detection lane). Around it, the actor collects host/system information (OS, architecture, configuration) to tailor payloads and side-load targets, and enumerates network configuration and adjacent hosts to plan pivoting and Neo-reGeorg proxy placement. After tooling is used, the actor removes intermediate tools and artifacts to reduce footprint, and iterated a new web-shell variant specifically carrying defense-evasion updates. So the on-victim story is: foothold -> concentrated discovery burst writing `.txt` output -> lateral tooling -> deletion of the recon output and dropped tools. The discovery commands are noisy in isolation; what localizes them is the *web-server parent process* and the *burst concentration*, and the cleanup is caught by watching deletions of files the same lineage created.
- **Why a hunt, not a rule:** `systeminfo`, `ipconfig`, `hostname`, `arp` and `ping` are among the most-run commands on Windows — admins, scripts, monitoring and login scripts fire them constantly, so a per-command alert is hopeless. And file deletion is normal everywhere (temp cleanup, updaters, user activity), so alerting on deletes is equally untenable. The signal is emergent and contextual: these commands *concentrated in a short window under an IIS worker/web-shell lineage* on a server that shouldn't be doing interactive recon, and deletions *of the very files that lineage just wrote*. Building that per-lineage burst window and the create-then-delete linkage is correlation over process-tree and file telemetry — hunt work. If the "≥N discovery verbs under `w3wp.exe` in M minutes" burst proves stable, hand detection-engineering that scoped lineage analytic; the raw commands and raw deletions stay in the hunt.

## Data sources required

- EDR / Sysmon process-create (EID 1) with full command line **and parent lineage** — to attribute discovery commands to a `w3wp.exe`/web-shell ancestor and cluster them into a burst
- Process-create for `cmd.exe`/`ping.exe`/`systeminfo.exe`/`ipconfig.exe`/`net.exe`/`arp.exe`/`route.exe` and `i.bat`
- EDR / Sysmon file-create (EID 11) and file-delete (EID 23 / Defender `FileDeleted`) — to link recon `.txt`/tool drops to their later deletion by the same lineage
- (Where available) command-line / shell-history and Recycle Bin / USN journal for deletion reconstruction after the fact

## Query starting point

Platform: `Microsoft Defender XDR (KQL)` — cluster discovery verbs under a web-server lineage, then check for deletion of what that lineage created

```kusto
let win = 30d;
let discoveryVerbs = dynamic(["systeminfo","hostname","ver","ipconfig","route","arp","net ","nbtstat","ping "]);
// (a) discovery burst descending from a web-server / web-shell process
let burst = DeviceProcessEvents
    | where TimeGenerated > ago(win)
    | where InitiatingProcessFileName in~ ("w3wp.exe","cmd.exe","powershell.exe","i.bat")
         or InitiatingProcessParentFileName =~ "w3wp.exe"
    | where ProcessCommandLine has_any (discoveryVerbs)
    | summarize verbs = make_set(FileName, 15), verbCount = dcount(FileName),
                cmds = make_list(ProcessCommandLine, 40),
                first = min(TimeGenerated), last = max(TimeGenerated),
                webParent = anyif(InitiatingProcessFileName, InitiatingProcessFileName =~ "w3wp.exe")
            by DeviceName, InitiatingProcessId
    | extend burstMinutes = datetime_diff('minute', last, first)
    | where verbCount >= 3 and burstMinutes <= 20;      // concentrated recon, not scattered admin
// (b) cleanup: same host deleting recon .txt / tool artifacts shortly after
let cleanup = DeviceFileEvents
    | where TimeGenerated > ago(win)
    | where ActionType == "FileDeleted"
    | where FileName endswith ".txt" or FileName has_any ("fscan","swor","neo","regeorg","i.bat",".dll")
    | where InitiatingProcessFileName in~ ("cmd.exe","w3wp.exe","powershell.exe","colorcpl.exe")
    | summarize deleted = make_set(FileName, 25), delCount = count(),
                delFirst = min(TimeGenerated), delLast = max(TimeGenerated) by DeviceName;
burst
| join kind=leftouter (cleanup) on DeviceName
| project DeviceName, webParent, verbs, verbCount, burstMinutes, first, last, deleted, delCount
| sort by verbCount desc
// Discovery burst under w3wp.exe (+ later deletion of recon .txt / tools) = post-foothold recon+cleanup
```

## Triage guidance

- **Likely malicious:** 3+ distinct discovery verbs (`systeminfo`+`ipconfig`+`net`+`ping` …) within ~20 minutes all parented by `w3wp.exe`/a web-shell `cmd.exe` on an IIS/Umbraco server; `i.bat` running a `ping` loop with output redirected to a `.txt`; and — bookending it — deletion of those `.txt` files or of `fscan`/`swor`/`neo-regeorg`/side-load DLLs by the same lineage. A web server that has never interactively run `systeminfo` suddenly running the full recon set is high-signal.
- **Likely benign / expected:** admins and monitoring agents running `ipconfig`/`systeminfo`/`ping` interactively or on a schedule (baseline the parents — `explorer.exe`, SCCM, RMM, login scripts are expected; `w3wp.exe` is not); temp-file and log cleanup by updaters and the OS; legitimate batch jobs that enumerate and then tidy up. A single discovery command, or deletions with no preceding web-shell recon burst, are not the finding — the web-server lineage and the burst concentration are the discriminators.
- **Pivot next:** on a confirmed burst, pivot up to the web shell (detection pack T1505.003 `App_Web_*.dll`, T1190) and down to what the recon fed — lateral movement (T1046 Fscan, T1021.002), credential dumping (T1003.001 mimikatz), tunneling (T1090.001 Neo-reGeorg / T1572 FRP). Reconstruct deleted files from USN/Recycle Bin/backups for scope. A live post-foothold recon burst means an active intrusion in progress — escalate to incident-response-coordinator. If the lineage-burst pattern is stable, hand detection-engineering the scoped analytic.

## References

- https://securelist.com/new-tropic-trooper-web-shell-infection/113737/
- https://www.trendmicro.com/en_us/research/21/l/collecting-in-the-dark-tropic-trooper-targets-transportation-and-government-organizations.html
- https://attack.mitre.org/groups/G0081/
- https://attack.mitre.org/techniques/T1082/
- https://attack.mitre.org/techniques/T1016/
- https://attack.mitre.org/techniques/T1070/004/
