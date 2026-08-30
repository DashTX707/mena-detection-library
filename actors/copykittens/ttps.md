# CopyKittens — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **41** across **11** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Actors registered large numbers of typosquatting/masquerading domains impersonating legitimate CDNs, security vendors and services to host C2 and blend malicious traffic — e.g. alkamaihd.com/.net (fake Akamai), akamaitechnology.tech, cloudflare-statics.com, gstatic.online/ssl-gstatic.online (fake Google), twiter-statics.info, fbstatic-a.space, mcafee-analyzer.com, digicert.online, windefender.org, cortana-search.com. |
| Compromise Infrastructure: Server | [T1584.004](https://attack.mitre.org/techniques/T1584/004/) | Actors compromised legitimate third-party websites (including news outlets such as the Jerusalem Post and other organizational sites) to stage watering-hole redirects and host malicious content. |
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Actors developed custom malware including the Matryoshka RAT (v1 and v2), the TDTESS backdoor, the Vminst lateral-movement tool, the NetSrv Cobalt Strike loader and the ZPP archiver — frequently assembled from copied/public code. |
| Develop Capabilities: Digital Certificates | [T1587.003](https://attack.mitre.org/techniques/T1587/003/) | Actors used code-signing digital certificates to sign malware and used SSL/TLS certificates on masquerading C2 domains to increase apparent legitimacy of their infrastructure. |
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | Actors created fake personas and social-media accounts and fake news/organization websites to support social-engineering and lure delivery. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Actors obtained and operationalized publicly available offensive tools — Cobalt Strike, the Empire PowerShell post-exploitation framework, Mimikatz, Metasploit/Meterpreter, and NBTScanner — a defining characteristic of the group (reliance on copied/public tooling). |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Drive-by Compromise | [T1189](https://attack.mitre.org/techniques/T1189/) | Actors used strategic web compromise (watering-hole) attacks — injecting malicious redirect/exploit code into legitimate websites (e.g. news outlets) so that visitors from targeted organizations were profiled and served exploits/malware. |
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Actors sent spearphishing emails carrying weaponized Office documents (macro-enabled and exploit-laden) themed around news, government and defense topics to deliver first-stage payloads. |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Actors sent spearphishing emails containing links to attacker-controlled fake websites and CDN-masquerading domains that delivered malware or harvested credentials. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Infection depended on a user opening a weaponized document and enabling macros (or running a delivered executable), which then executed the first-stage loader; one lure chain exploited CVE-2017-0199 in Office/WordPad. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Actors used PowerShell — including the Empire framework and Cobalt Strike PowerShell payloads — for post-exploitation execution, staging and command execution. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | The TDTESS backdoor installs itself as a Windows service to achieve persistence and run with elevated privileges, calling out to its C2 for instructions. |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Matryoshka RAT establishes persistence via registry Run keys / autostart entries so the implant re-launches at logon. |
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Actors created scheduled tasks to persist and re-launch implant components (Matryoshka and loader payloads) across reboots. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| System Binary Proxy Execution: Rundll32 | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Actors used rundll32.exe to proxy-execute malicious DLL payloads (including Matryoshka components and Meterpreter injection), abusing the signed Windows binary to launch code and evade application controls. |
| Subvert Trust Controls: Code Signing | [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | Actors signed malware with code-signing certificates to subvert trust controls and reduce detection/warning prompts on execution. |
| Hide Artifacts: Hidden Window | [T1564.003](https://attack.mitre.org/techniques/T1564/003/) | Actors ran components with hidden windows to conceal execution from the interactive user. |
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) | Matryoshka injects a Meterpreter payload/shellcode into a running process (via rundll32-loaded components) to execute in the context of a legitimate process. |
| Modify Registry | [T1112](https://attack.mitre.org/techniques/T1112/) | Implants read and modify registry keys for persistence and configuration storage. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | Implants decode/deobfuscate embedded configuration, staged payloads and DNS-tunneled data at runtime. |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | Actors obfuscated payloads and encoded data within DNS queries/responses (Matryoshka DNS tunneling) to hinder analysis and evade content inspection. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Actors named C2 domains and hosts to impersonate trusted CDNs and services (Akamai, Google/gstatic, Cloudflare, Twitter, Facebook, McAfee, DigiCert, Windows Defender) and used update-themed hostnames (winupdate64, javaupdate, mswordupdate17) so traffic and artifacts appear benign. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | Matryoshka RAT records keystrokes to capture credentials and other sensitive typed data. |
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Actors used Mimikatz to dump credentials from LSASS memory on compromised hosts to enable privilege escalation and lateral movement. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Actors used NBTScanner to enumerate NetBIOS/network services and identify hosts on the internal network for lateral movement. |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) | Actors enumerated remote hosts on the internal network (via NBTScanner and native commands) to map lateral-movement targets. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | Matryoshka and loader components collect system information (OS, host configuration) for profiling and to tailor follow-on payloads. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | Implants enumerate running processes to select injection targets and detect analysis/security tooling. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: SMB/Windows Admin Shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Actors used the Vminst tool and SMB/admin-share access to move laterally and deploy implants to additional hosts after harvesting credentials. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | Matryoshka RAT captures screenshots of the victim desktop for espionage collection. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Matryoshka RAT collects and uploads files of interest from the local system, and steals stored passwords. |
| Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Actors used the ZPP console compression utility (and bundled Ionic.Zip/DotNetZip) to archive collected data prior to exfiltration. |
| Archive Collected Data: Archive via Custom Method | [T1560.003](https://attack.mitre.org/techniques/T1560/003/) | Actors used a custom archiving/compression method (ZPP) to bundle data with a self-developed routine rather than a standard off-the-shelf tool. |
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Actors staged collected and archived data locally (temp/working directories) prior to exfiltration. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Signature behavior: the Matryoshka RAT uses DNS as its command-and-control channel, encoding commands and data within DNS queries and responses to attacker nameservers (e.g. nameserver.win, dnsserv.host, gtld-servers.services / .solutions / .zone lookalikes, gsvr-static.co staged subdomains). |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | The TDTESS backdoor communicates with its C2 over HTTP, periodically calling the server for new instructions using HTTP basic authentication; Cobalt Strike/NetSrv beacons also use HTTP(S). |
| Data Encoding: Standard Encoding | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | Actors encode C2 data (including within DNS tunneling) using standard encoding schemes to embed commands and exfiltrated data in protocol fields. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | The TDTESS backdoor and Matryoshka RAT can download and execute additional files/payloads on the compromised host from C2. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | Actors routed and relayed C2 through intermediary infrastructure and CDN-masquerading domains to obscure the true C2 source. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Matryoshka RAT exfiltrates collected files, passwords, screenshots and keystrokes back through its established C2 channel. |
| Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Matryoshka uses DNS as an exfiltration channel, tunneling stolen data out inside DNS queries (a non-web, non-primary-C2 protocol) to blend with normal name-resolution traffic. |
