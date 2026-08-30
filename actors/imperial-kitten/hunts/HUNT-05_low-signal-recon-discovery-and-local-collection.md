# Hunt: Imperial Kitten — low-signal perimeter scanning, host discovery & local data collection

- **Hypothesis:** If Imperial Kitten has an operator hands-on-keyboard inside our estate (or is profiling us from outside), then three individually-ubiquitous, low-signal behaviors cluster in a way normal activity does not: (1) **external active scanning** of our perimeter (nmap-style service sweeps) that precedes an exploit or VPN-login attempt from the same/adjacent infrastructure; (2) a **burst of system-information discovery** commands (`systeminfo`, `whoami`, `ipconfig /all`, `net user/group`, `nltest`) run in quick succession under one process lineage — the actor profiling the host it just landed on; and (3) **local data collection** — files of interest copied/staged into a single archive or working directory before exfil. Each command is run a thousand times a day benignly; the finding is the *temporal cluster under implant/Office/remote-logon parentage* — recon-burst lineage, staging fan-in, and scan-then-access correlation — not any single command.
- **ATT&CK:**
  - T1595 — Active Scanning (reconnaissance) — actor uses nmap/public scanners to map our exposed services; hunt at the network edge for scan patterns that time-correlate with a follow-on exploit/VPN attempt from related infrastructure.
  - T1082 — System Information Discovery (discovery) — implants and hands-on activity enumerate host/system/network details to profile and select targets; hunt the *burst* of discovery commands under a single suspicious parent.
  - T1005 — Data from Local System (collection) — actor collects files of interest for espionage; hunt the staging pattern (bulk read/copy fan-in to one archive/dir) rather than the individual reads.

- **Actor procedure:** Imperial Kitten used **nmap** for public scanning/service discovery and, after foothold, ran **SoftPerfect NetScan** and nmap internally to enumerate hosts and services. Implants and interactive activity enumerated host, network and browser/visitor information to profile victims and pick high-value targets. Files and data of interest were collected from compromised hosts for espionage and exfiltrated over the implants' C2 (IMAP email / Discord / HTTP). All three techniques are deliberately low-signal — common, cheap, and easily lost in normal admin/user noise — which is why they anchor a correlation hunt rather than a standalone alert.
- **Why a hunt, not a rule:** `systeminfo`, `whoami`, `net group`, a file copy, or an inbound port probe are each so common that alerting on any one produces pure noise — this is a data-based / low-signal correlation problem, not a detection. The signal is in *stacking anomaly primitives on one entity*: an improper-frequency burst (many discovery commands in seconds), an unexpected-relationship parent (the burst spawned by EXCEL.EXE, python.exe, a service, or a fresh remote logon rather than an admin script), and a volume/fan-in outlier (dozens of business files copied into one staging folder in minutes). External scanning is largely off-victim and weakly attributable at the endpoint — its value is edge-network correlation with a follow-on access attempt. If a robust, precise composite emerges (e.g. ≥5 distinct discovery utilities within 60s under a non-shell Office/implant parent — Summiting Level 3, a behavioral-chain observable), hand that to detection-engineering as a scoped analytic.

## Data sources required

- EDR process-creation telemetry with full command line and parent lineage (Sysmon EID 1 / DeviceProcessEvents) — for the discovery-burst and staging-tool signals
- Perimeter/IDS + firewall connection logs (source IP→ASN, ports, connection fanout) — for external active-scanning detection and scan-then-access correlation
- File-event telemetry (Sysmon EID 11 / DeviceFileEvents) and archiver process usage (rar/7z/zip, `Compress-Archive`) — for the local-collection staging pattern
- East-west connection telemetry for internal NetScan/nmap fanout (cross-ref detection lane T1046)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — recon-burst under suspicious parent, plus staging fan-in

```kusto
// (a) discovery-command BURST under one process tree (improper-frequency + unexpected-parent)
let discoveryTools = dynamic(["systeminfo.exe","whoami.exe","ipconfig.exe","net.exe","net1.exe",
  "nltest.exe","tasklist.exe","hostname.exe","query.exe","arp.exe","route.exe","netstat.exe","reg.exe"]);
DeviceProcessEvents
| where TimeGenerated > ago(14d)
| where FileName in~ (discoveryTools)
| summarize distinctTools = dcount(FileName), tools = make_set(FileName, 15),
    firstT = min(TimeGenerated), lastT = max(TimeGenerated)
    by DeviceName, InitiatingProcessId, parent = InitiatingProcessFileName, acct = AccountName
| extend burstSecs = datetime_diff("second", lastT, firstT)
| where distinctTools >= 5 and burstSecs <= 120                 // >=5 distinct recon tools within 2 min
| where parent !in~ ("cmd.exe","powershell.exe")                // ...NOT from an interactive admin shell
    or parent in~ ("EXCEL.EXE","WINWORD.EXE","python.exe","pythonw.exe","wscript.exe","services.exe")
| join kind=leftouter (
    // (b) local-collection staging: bulk file copy/archive on the same host shortly after
    DeviceProcessEvents
    | where FileName in~ ("rar.exe","7z.exe","7za.exe","winrar.exe") or ProcessCommandLine has "Compress-Archive"
    | project DeviceName, stageTime = TimeGenerated, stageCmd = ProcessCommandLine
  ) on DeviceName
| order by distinctTools desc
// PIVOT: for external T1595, correlate perimeter scan-source ASNs with any follow-on VPN/exploit attempt (HUNT-04 / detection T1190)
```

## Triage guidance

- **Likely malicious:** five-plus distinct discovery utilities fired within a two-minute window under a non-shell parent (EXCEL.EXE, python.exe, wscript.exe, a service), on a host with no admin/scripting role; that burst followed by an archiver (rar/7z/`Compress-Archive`) fanning many business documents into one staging file; an external port-scan sweep of our perimeter from an ASN that then appears in a VPN-login or exploit attempt. The stack of recon-burst + staging on one host is the espionage-actor profile.
- **Likely benign / expected:** logon scripts, GPO, SCCM/inventory agents, monitoring tools and admin troubleshooting run these exact commands constantly — often many in sequence — and backup/IT jobs archive files legitimately; security scanners and asset-discovery tools generate perimeter and east-west scan traffic. Baseline the inventory/monitoring service accounts and admin hosts and exclude them; require the *unexpected parent* and *tight burst window* (and, for collection, the fan-in of unrelated business files) rather than the commands alone. Routine `whoami`/`ipconfig` is noise.
- **Pivot next:** on a confirmed recon-burst-plus-staging host, identify what was staged and where it was heading (pivot to the email-C2 / Discord / HTTP exfil surface — detection lane T1041/T1071.003/T1102), check the same host and lineage for the implant footprint (HUNT-03) and lateral-movement tooling (NetScan/PAExec — detection T1046/T1021.002), and preserve the staging archive. Confirmed collection-and-staging under implant parentage is active espionage — escalate to incident-response-coordinator. For external scanning with a scan-then-access correlation, feed the source ASN/IP to the perimeter-blocklist and the valid-account hunt (HUNT-04).

## References

- https://www.crowdstrike.com/en-us/blog/imperial-kitten-deploys-novel-malware-families/
- https://attack.mitre.org/techniques/T1595/
- https://attack.mitre.org/techniques/T1082/
- https://attack.mitre.org/techniques/T1005/
