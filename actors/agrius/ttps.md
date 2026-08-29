# Agrius (G1030) — ATT&CK Technique Mapping

> Attribution: Iran-nexus, destructive/wiper operator — medium-high confidence. MITRE ID: G1030.
> Enriched from MITRE ATT&CK G1030 + SentinelLabs & Unit 42 reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **34** across **11** tactics. First pack with meaningful **Impact**-tactic coverage.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure | [T1583](https://attack.mitre.org/techniques/T1583/) | Agrius typically uses commercial VPN services such as ProtonVPN to anonymize last-hop traffic into victim networks. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Agrius exploits internet-facing applications for initial access, including widespread attempts to exploit CVE-2018-13379 in Fortinet FortiOS SSL-VPN and SQL-injection activity against web applications. |
| Valid Accounts: Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Agrius acquires valid domain credentials through brute force, spraying and dumping, then reuses them for follow-on lateral movement and RDP access via compromised accounts. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Following exploitation, Agrius deploys variants of the ASPXSpy web shell (observed filenames Uploader.aspx, xcopy.aspx, css.aspx) on internet-facing servers to maintain access and proxy follow-on commands. |
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Agrius deployed the IPsec Helper .NET backdoor post-exploitation and registered it as a Windows service for persistence. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Agrius uses ASPXSpy web shells to enable follow-on command execution via cmd.exe on compromised servers. |
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | The MultiLayer wiper uses a DeleteLogs() function to create a scheduled task that launches a batch script once, which then removes all Windows Event Logs before self-cleanup. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | Agrius deployed base64-encoded variants of the ASPXSpy web shell that decode at runtime to evade static detection. |
| Impair Defenses: Disable or Modify Tools | [T1685](https://attack.mitre.org/techniques/T1685/) | Agrius used several mechanisms to disable security tooling: modifying EDR-related services to prevent auto-start on reboot, and abusing vulnerable signed drivers — GMER64.sys/gmer64.sys (renamed AGMT.sys, via loader agmt.exe) and Rentdrv2 (via loader drvIX.exe) — to selectively stop and remove security-software processes (BYOVD). |
| Indicator Removal: Clear Windows Event Logs | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) | The MultiLayer wiper clears all Windows Event Logs via a scheduled batch script as an anti-forensic step during its destructive routine. |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | Agrius masqueraded tooling by renaming binaries — e.g. the Plink tunneling tool renamed to systems.exe, and the GMER driver renamed AGMT.sys — to blend with legitimate system files. |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | The MultiLayer wiper removes all files it uses (dropped assembly, batch scripts, itself) after execution to remain stealthy and hinder forensics. |
| Indicator Removal: Timestomp | [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | The MultiLayer wiper timestomps files by overwriting LastAccessTime, LastWriteTime and CreationTime — setting NTFS timestamps to 1601-01-01 and non-NTFS to 1980-01-01 — a well-known anti-forensic technique. |
| Obfuscated Files or Information: Embedded Payloads | [T1027.009](https://attack.mitre.org/techniques/T1027/009/) | Agrius wipers (e.g. MultiLayer) carry embedded payloads — a dropped assembly file and batch scripts — that are written out and executed at runtime, then deleted. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Agrius used Mimikatz (filename Mimi.exe) and ProcDump to dump LSASS memory and capture credentials in victim environments. |
| OS Credential Dumping: Security Account Manager | [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Agrius dumped the SAM database on victim machines to capture local account credentials. |
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | Agrius engaged in brute-forcing activity via SMB within victim environments to obtain valid credentials. |
| Brute Force: Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Agrius performed password spraying via SMB against many accounts in victim environments. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Agrius used open-source port scanners — WinEggDrop and NimScan — to perform detailed scans of hosts of interest inside victim networks. |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) | Agrius used the NBTscan tool to enumerate remote, accessible hosts in victim environments. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Agrius tunnels RDP traffic through deployed web shells and via the Plink tool to access victim environments with compromised accounts and move laterally. |
| Lateral Tool Transfer | [T1570](https://attack.mitre.org/techniques/T1570/) | Agrius downloaded follow-on payloads for execution from legitimate file-sharing services such as ufile.io and easyupload.io, and moved tooling between hosts inside victim networks. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Agrius gathered data from database and other critical servers in victim environments prior to using wiping mechanisms as an anti-analysis/anti-forensics step. |
| Automated Collection | [T1119](https://attack.mitre.org/techniques/T1119/) | Agrius used a custom tool, Sqlextractor (binary sql.net4.exe), to query SQL databases and automatically identify and extract PII (ID numbers, passport scans, emails, addresses), saving results to CSV files. |
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Agrius staged data for exfiltration in a local working folder, C:\windows\temp\s\, before archiving and transfer. |
| Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Agrius used 7zip to archive extracted data (producing .7z / .ezip files) in preparation for exfiltration. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Agrius exfiltrated staged data using tools such as PuTTY, pscp.exe and WinSCP, connecting outbound to command-and-control servers over SSH/SCP. |

## Impact

| Technique | ID | Notes |
|---|---|---|
| Data Destruction | [T1485](https://attack.mitre.org/techniques/T1485/) | Agrius's defining behavior: after data theft, it deploys wipers (Apostle, DEADWOOD/Detbosit, Fantasy, MultiLayer, PartialWasher, BFG Agonizer) to destroy data on victim endpoints and servers, rendering them unusable and covering the actors' tracks — often masqueraded as ransomware. |
| Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | Agrius masqueraded destructive operations as ransomware, dropping ransom notes as a ruse; the Apostle wiper was later rewritten into fully functional ransomware, and the Moneybird ransomware was deployed in later Israeli-targeted attacks. In many incidents the 'ransomware' was cover for irrecoverable wiping. |
| Inhibit System Recovery | [T1490](https://attack.mitre.org/techniques/T1490/) | The MultiLayer wiper deletes all Volume Shadow Copies and then removes the Volume Shadow Copy (VSS) service itself to prevent data restoration before destroying the disk. |
| Disk Wipe: Disk Content Wipe | [T1561.001](https://attack.mitre.org/techniques/T1561/001/) | Agrius wipers destroy on-disk content — e.g. BFG Agonizer offers modes to write ~420 MB of binary data to a target device to make a drive unusable and to wipe files in specified folders; MultiLayer and PartialWasher similarly overwrite/destroy file and drive content. |
| Disk Wipe: Disk Structure Wipe | [T1561.002](https://attack.mitre.org/techniques/T1561/002/) | Agrius wipers corrupt disk structures to prevent boot: BFG Agonizer opens a handle to \\.\PhysicalDrive0, detects MBR/GPT partition style, and overwrites the first 6 sectors (boot sector); MultiLayer opens \\.\PhysicalDrive0 and wipes the first 512 bytes so the system can no longer boot. |
| Service Stop | [T1489](https://attack.mitre.org/techniques/T1489/) | Agrius stops and removes services to enable destruction and disable defenses — abusing GMER/Rentdrv2 drivers to stop and remove security-software processes/services, and removing the Volume Shadow Copy (VSS) service during the MultiLayer wipe. |
| System Shutdown/Reboot | [T1529](https://attack.mitre.org/techniques/T1529/) | After corrupting disk structures, Agrius wipers ensure the victim system can no longer boot and trigger shutdown/reboot to finalize the destructive impact, leaving endpoints inoperable. |
