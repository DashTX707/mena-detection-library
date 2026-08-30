# Hunt: Pioneer Kitten credential-bearing file harvest across local systems and network shares

- **Hypothesis:** If Pioneer Kitten is assembling the credential package that underpins their "full domain control" resale, then beyond dumping LSASS/NTDS they will quietly **read credential-bearing files** — config files with embedded passwords, key stores, VPN profiles, exported hives — from **local systems and network shared drives**, sweeping many files/hosts in a short window from a single foothold identity. The tells are (a) a single account/process reading an unusually broad set of credential-suggestive files, and (b) that same identity fanning out across many file-server shares it has never touched before. A honeytoken credential file placed on shares gives a near-zero-false-positive tripwire. The hunt keys on unexpected-relationship + volume-outlier + never-before-seen-share-access stacked on one identity.
- **ATT&CK:**
  - T1552.001 — Unsecured Credentials: Credentials In Files (credential-access) — searching for and harvesting credentials stored in files, including honeytoken tripwires
  - T1039 — Data from Network Shared Drive (collection) — collecting data (and credential-bearing files) from network shared drives across the estate

- **Actor procedure:** Fox Kitten searches compromised systems for credentials stored in files and collects data from network shared drives to locate configuration files, credentials and data of interest — material that both enables lateral movement/privilege escalation and forms the salable access package. Reads of credential-bearing files leave little discrete signal individually, and share reads are high-volume and mostly legitimate, so the actor's bulk-harvest sweep hides inside normal file-server traffic.
- **Why a hunt, not a rule:** A single file read — even of `web.config` or a `.kdbx` — is indistinguishable from routine admin/user work and far too common to alert on; network-share reads are among the highest-volume events in any enterprise. There is no clean per-event signature. The finding only emerges from **stacking anomalies on one entity**: one identity reading a broad *variety* of credential-suggestive files (volume outlier) across shares it has *never* accessed before (never-before-seen relationship) in a tight window (improper timing) — a baseline-heavy, judgement-driven correlation, i.e. hunt work. The exception is the honeytoken: a planted credential file that no legitimate process should ever open is precise enough to hand to detection-engineering as a high-fidelity tripwire alert.

## Data sources required

- File-access auditing: Windows Security 4663 (object access) on file servers and shares; EDR file-read (`FileAccessed`) telemetry
- File-share access logs: 5140/5145 (network share + detailed file share access) for cross-share fan-out
- Honeytoken inventory: planted decoy credential files (fake `.kdbx`, `passwords.xlsx`, `unattend.xml`) with alerting on any access
- Process/identity context (Sysmon EID 1 / DeviceProcessEvents) to attribute reads to a foothold process and correlate with credential-dumping (cross-ref detection pack T1003.001/T1003.003)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR + Security Events)` — one identity, broad credential-file variety, never-before-seen share fan-out

```kusto
// (a) Honeytoken tripwire — any access to a planted decoy credential file is malicious by construction
let honeytokens = dynamic([@"\\fileserv\hr\passwords_DO_NOT_OPEN.kdbx", @"\\fileserv\it\domain_admin_creds.xlsx"]);
SecurityEvent
| where EventID == 4663 and ObjectName in~ (honeytokens)
| project TimeGenerated, Account, Computer, ObjectName, ProcessName, AccessMask
// ---
// (b) Bulk credential-file variety read by one identity, fanning across never-before-seen shares
let credExt = dynamic([".kdbx",".ovpn",".pfx",".config","unattend.xml","web.config","password","credential",".rdp",".ppk"]);
let priorShares = SecurityEvent
    | where TimeGenerated between (ago(60d)..ago(3d)) and EventID in (5140,5145)
    | summarize by Account, ShareName;                  // shares each identity normally touches
SecurityEvent
| where TimeGenerated > ago(3d) and EventID == 4663 and AccessMask has_any ("0x1","0x80","ReadData")
| where ObjectName has_any (credExt)
| extend ShareName = tostring(split(ObjectName, "\\")[3])
| join kind=leftanti priorShares on Account, ShareName   // never-before-seen share for this account
| summarize distinctFiles = dcount(ObjectName), fileTypes = dcount(tostring(extract(@"(\.[a-z0-9]+)$",1,ObjectName))),
            shares = dcount(ShareName), sample = make_set(ObjectName, 25),
            window = max(TimeGenerated) - min(TimeGenerated)
         by Account, Computer
| where distinctFiles >= 10 and fileTypes >= 3 and window < 2h   // broad variety, tight burst
| order by distinctFiles desc
```

## Triage guidance

- **Likely malicious:** any access at all to a honeytoken credential file (no legitimate reason exists); one identity reading a broad variety of credential-suggestive files across multiple shares it has never previously accessed, in a tight burst; the reading process being a foothold/RMM/tunneling process rather than an interactive user session; credential-file harvest time-correlated with LSASS/NTDS dumping (T1003) or with the resale-staging cluster in HUNT-01.
- **Likely benign / expected:** backup/DLP/indexing/AV agents read across shares broadly and continuously — allowlist their service accounts; admins and IaC pipelines legitimately open `web.config`/`.ppk`/`.rdp` on hosts they own; migration and audit projects cause bursty share access by known accounts on a scheduled basis. A known service account or a user reading files on shares it routinely uses is expected; a foothold identity touching never-before-seen shares with credential-file variety in a two-hour burst is not.
- **Pivot next:** confirmed bulk credential-file harvest is package-assembly for access resale — pivot to HUNT-01 (foothold-for-resale correlation), force-rotate every credential exposed in the read set, hunt the same identity for LSASS/NTDS dumping and lateral movement (detection pack T1003.001/T1003.003/T1021), and if a honeytoken fired or a broad sweep is confirmed, escalate to incident-response-coordinator. Hand the honeytoken-access tripwire to detection-engineering as a standing high-fidelity alert.

## References

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a
- https://attack.mitre.org/groups/G0117/
- https://attack.mitre.org/techniques/T1552/001/
- https://attack.mitre.org/techniques/T1039/
