# Hunt: Homeland Justice hack-and-leak staging (bulk local collection → archive → exfil over web-shell C2)

- **Hypothesis:** If Storm-0842 is running the "steal-then-publicize" half of its operation before the destructive stage, then on compromised servers we should find the collection-to-exfil pipeline: **bulk local file reads/staging** of sensitive content into a working directory, **large archive creation** (zip/rar/7z or split volumes) over that staged directory, and then an **anomalously large outbound transfer from a web/SharePoint server** — folded into the ClientBin.aspx web-shell socket relay so it blends with server traffic. The hunt keys on volume-outlier + unexpected-relationship anomalies stacked on one host: a server that is normally a *sink* for traffic suddenly reading broadly, producing a big archive, and sourcing a large egress.
- **ATT&CK:**
  - T1005 — Data from Local System (collection) — bulk read/stage, not routine file access
  - T1560 — Archive Collected Data (collection) — large archive over a staged directory
  - T1041 — Exfiltration Over C2 Channel (exfiltration) — large egress folded into web-shell sockets

- **Actor procedure:** Per AA22-264A the actor collected sensitive Albanian government data from compromised systems, aggregated and archived it for staged public release, and moved it out via the web shell's socket-relay capability — `ClientBin.aspx` / `App_Web_bckwssht.dll` accepts an HTTP POST carrying a Base64 IP:port and opens a second socket to that address (detection-pack T1071.001). Stolen data was then leaked incrementally through the Homeland Justice persona (see HUNT-05). Void Manticore/Karma operations against Israel follow the same theft-then-leak pattern.
- **Why a hunt, not a rule:** Each stage is LOW-signal alone — bulk local reads are high-volume normal activity, archiving utilities are standard admin tools, and exfil folded into a web server's own outbound sockets blends with legitimate traffic. A rule on "7z.exe ran" or "server made an outbound connection" drowns in noise. The discriminating signal is the *sequence and the actor-role inversion*: a host (especially a SharePoint/IIS server that should mostly receive) reading broadly, then producing a large archive over exactly those staged files, then sourcing a large egress — three volume/relationship anomalies chained on one host in order. That correlation over disparate data sources is judgement-heavy → hunt. Durable core (Summiting Level 3-4): *a web/SharePoint server initiating a large outbound data transfer after local archive creation* — robust because exfil-after-staging is intrinsic to hack-and-leak; hand the egress-volume-outlier-from-server-role piece to detection-engineering once per-host egress baselines exist.

## Data sources required

- EDR file-operation telemetry (DeviceFileEvents): per-process/-host read fan-out + archive-extension file creation (`.zip/.rar/.7z/.001`)
- Sysmon EID 1 (process create): archiving-utility execution (7z/rar/tar/makecab/PowerShell Compress-Archive) with command line
- Network egress / proxy / firewall byte counts per host — outbound volume outliers, especially from server-role hosts
- IIS/web logs + web-shell C2 correlation (POST to unusual .aspx → server-initiated outbound socket — cross-ref T1071.001)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — collection→archive→egress chained on one host, server-role weighted

```kusto
// Stage A+B: broad local reads followed by large archive creation on the same host
let archives =
    DeviceFileEvents
    | where Timestamp > ago(14d) and ActionType == "FileCreated"
    | where FileName has_any (".zip",".rar",".7z",".tar",".001",".cab")
    | summarize archiveCount = count(), archiveDirs = make_set(FolderPath,10),
                archTime = min(Timestamp) by DeviceName, InitiatingProcessFileName;
let bulkread =
    DeviceFileEvents
    | where Timestamp > ago(14d) and ActionType in ("FileAccessed","FileModified")
    | summarize distinctFiles = dcount(FolderPath) by DeviceName, bin(Timestamp,1h)
    | where distinctFiles > 1000
    | summarize readHost = any(DeviceName) by DeviceName;
// Stage C: outbound byte volume outlier per host (weight server roles)
let egress =
    DeviceNetworkEvents
    | where Timestamp > ago(14d) and ActionType == "ConnectionSuccess"
    | summarize bytesOut = sum(tolong(parse_json(AdditionalFields).SentBytes)) by DeviceName
    | summarize avg=avg(bytesOut), sd=stdev(bytesOut);   // fleet baseline for z-score
archives
| join kind=inner bulkread on DeviceName
| project DeviceName, InitiatingProcessFileName, archiveCount, archiveDirs, archTime
| order by archTime desc
// Then: for each hit host, compute its egress z-score vs `egress` baseline and flag >3 stdev,
//   and check IIS logs for a preceding POST-to-.aspx + server-initiated outbound socket.
```

## Triage guidance

- **Likely malicious:** a host — most of all a SharePoint/IIS/file server — that reads across thousands of sensitive files, creates a large (or split-volume) archive over those staged directories, and then sources an outbound transfer far above its own baseline; archive creation in a temp/staging path with a generic name; egress correlated in time with a POST to an unusual `.aspx` endpoint and the web server opening an outbound socket to an external IP:port (web-shell relay). Stack all three stages on one host before calling it.
- **Likely benign / expected:** backup jobs, log shipping, DB dumps, software distribution, and legitimate large file transfers produce archives and big egress on a known cadence from known accounts/paths — allowlist scheduled backup/archive jobs by host + process + destination. A workstation zipping a project folder is routine; a server inverting its normal receive-heavy role to send a large archive is not. Single-stage hits are inconclusive.
- **Pivot next:** confirmed collection→archive→exfil chain → identify the archive contents and destination IP/ASN, pivot to the web shell (detection-pack T1505.003/T1071.001) and the entry account (HUNT-03), and cross to HUNT-05 to watch for the same data surfacing on the Homeland Justice/Karma leak channels. Confirmed active exfiltration of sensitive data is an incident → **escalate to IR**; the theft typically precedes the destructive stage (HUNT-01), so treat it as early warning and pre-position for wiper staging.

## References

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a
- https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/
- https://attack.mitre.org/techniques/T1005/
- https://attack.mitre.org/techniques/T1560/
- https://attack.mitre.org/techniques/T1041/
