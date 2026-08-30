# Tortoiseshell (G0139) — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium-high confidence. MITRE ID: G0139.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **74** across **13** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Gather Victim Host Information | [T1592](https://attack.mitre.org/techniques/T1592/) | In the Yellow Liderc watering-hole operations, bespoke JavaScript injected into compromised legitimate websites fingerprints visiting hosts (browser, OS, configuration) and exfiltrates the profile to attacker-controlled infrastructure to select targets for follow-on IMAPLoader delivery. |
| Gather Victim Host Information: Software | [T1592.002](https://attack.mitre.org/techniques/T1592/002/) | The injected profiling JavaScript enumerates browser/software attributes of visitors to compromised watering-hole sites to distinguish intended targets from incidental traffic. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Registered domains for fake recruiting/job sites, fake-persona infrastructure, browser-profiling exfiltration endpoints, and C2. |
| Acquire Infrastructure: Web Services | [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | Used attacker-controlled web services/domains to receive exfiltrated visitor-fingerprint data from watering-hole JavaScript. |
| Establish Accounts | [T1585](https://attack.mitre.org/techniques/T1585/) | Built elaborate long-con fake personas (e.g. the TA456 'Marcella Flores' persona) maintained over long periods to build rapport with targets before delivering malware. |
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | Created fake recruiter/social-media personas (LinkedIn/Facebook) to run job-recruitment-themed social engineering against targets. |
| Establish Accounts: Email Accounts | [T1585.002](https://attack.mitre.org/techniques/T1585/002/) | Established email accounts used both for social-engineering correspondence and, for IMAPLoader, as mailbox infrastructure for IMAP-based command-and-control. |
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Developed custom malware including Backdoor.Syskit (in both Delphi and .NET) and the .NET IMAPLoader implant. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Leveraged publicly available tools including ProcDump, NSSM, PAExec/PsExec and Mimikatz alongside custom implants. |
| Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | Hosted malicious installers/payloads on fake recruiting and job-application websites designed to be delivered to targeted audiences. |
| Stage Capabilities: Drive-by Target | [T1608.004](https://attack.mitre.org/techniques/T1608/004/) | Compromised legitimate (primarily Israel-related maritime/logistics) websites and injected bespoke JavaScript to stage strategic web compromises against their visitors. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Supply Chain Compromise | [T1195](https://attack.mitre.org/techniques/T1195/) | Compromised IT/managed service providers (primarily in Saudi Arabia) as a stepping stone to reach their downstream customers — the defining Tortoiseshell tradecraft. |
| Supply Chain Compromise: Compromise Software Supply Chain | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Abused compromised IT-provider software/administration channels to distribute malware to downstream customer environments. |
| Trusted Relationship | [T1199](https://attack.mitre.org/techniques/T1199/) | Exploited the trusted access that compromised IT/managed service providers already held into their customers' networks to gain initial access downstream. |
| Drive-by Compromise | [T1189](https://attack.mitre.org/techniques/T1189/) | Conducted strategic web compromises (watering holes) — injecting profiling JavaScript into legitimate sites and delivering payloads to selected visitors (Yellow Liderc / IMAPLoader). |
| Phishing: Spearphishing via Service | [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | Used social-media/job-recruitment services (LinkedIn/Facebook fake personas) to deliver lures and links outside corporate mail controls. |
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | In some IMPERIAL KITTEN intrusions used SQL injection against public-facing web applications to gain initial access. |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | Used stolen/legitimate credentials (harvested from compromised IT providers and via credential theft) to access downstream systems and move within victim networks. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Executed PowerShell tooling including get-logon-history.ps1 for reconnaissance and used PowerShell to download and run payloads. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Ran commands and dropped/executed batch and staged executables (e.g. %Windir%\temp\bak.exe) via the Windows command shell. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Used VBScript-based scripting/droppers in social-engineering delivery chains. |
| Command and Scripting Interpreter: JavaScript | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | Injected bespoke JavaScript into compromised watering-hole websites to fingerprint and target visitors. |
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Relied on targets clicking recruitment-themed links delivered via social media / fake personas to reach payloads. |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Relied on targets running malicious files (fake job-application installers / weaponized documents) to execute custom .NET implants. |
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) | Used WMI for execution and remote command running during hands-on-keyboard activity. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Created scheduled tasks to persist and execute payloads on compromised hosts. |
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Used NSSM (Non-Sucking Service Manager) to install malware as a Windows service for persistence. |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Used registry Run keys / startup locations for autostart persistence of implants. |
| Hijack Execution Flow: DLL Search Order Hijacking | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | IMAPLoader is loaded via DLL side-loading / search-order hijacking of a legitimate signed host process. |

## Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Valid Accounts: Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Obtained domain-admin-level access on at least two compromised networks, then used those privileged domain accounts to broaden access (several hundred hosts infected in some environments). |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| System Binary Proxy Execution: Mshta | [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Delivered/loaded IMAPLoader components via HTA files executed through mshta to proxy execution and evade defenses. |
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) | Custom .NET implants used process injection to run in the context of legitimate processes. |
| Reflective Code Loading | [T1620](https://attack.mitre.org/techniques/T1620/) | Loaded .NET payloads reflectively in memory (IMAPLoader / custom implants) to avoid writing the full payload to disk. |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated implant code and configuration to hinder analysis and detection. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Stored/transferred encrypted or encoded payloads and configuration to evade content inspection. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | Decoded/deobfuscated staged payloads at runtime (including via certutil in the Symantec-observed toolset). |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | Named payloads and staged binaries to blend in (e.g. bak.exe, sha.exe) and used recruitment-themed lures to appear legitimate. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Staged executables in trusted-looking locations/names such as %Windir%\temp\bak.exe to reduce suspicion. |
| Modify Registry | [T1112](https://attack.mitre.org/techniques/T1112/) | Modified registry values including HKLM\...\CurrentVersion\Policies\System\Enablevmd and \Sendvmd during Syskit operations. |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Deleted staged tools and payload artifacts after use to hinder investigation. |
| Subvert Trust Controls: Code Signing | [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | Abused signed/side-loaded legitimate binaries to gain trust when loading IMAPLoader components. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Used ProcDump (and Mimikatz-style tooling) to dump LSASS memory for credential theft. |
| Credentials from Password Stores | [T1555](https://attack.mitre.org/techniques/T1555/) | Harvested credentials from local password stores using custom infostealers and public tools. |
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | Stole credentials from web browsers as part of the infostealer collection. |
| Credentials from Password Stores: Windows Credential Manager | [T1555.004](https://attack.mitre.org/techniques/T1555/004/) | Collected credentials stored in the Windows Credential Manager/vault. |
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | Deployed keylogging capability within infostealer implants to capture typed credentials. |
| Input Capture: Web Portal Capture | [T1056.003](https://attack.mitre.org/techniques/T1056/003/) | Used fake login / recruitment web portals to capture credentials submitted by targets. |
| Unsecured Credentials: Credentials In Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Collected credentials stored in files across compromised hosts as part of infostealer activity. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | Ran systeminfo and used info-gathering tools to enumerate host details. |
| System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | Ran ipconfig and related commands to enumerate network configuration. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | Ran whoami and get-logon-history.ps1 to enumerate the current user and prior logon history. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | Enumerated running processes on compromised hosts via info-gathering tools. |
| Account Discovery: Local Account | [T1087.001](https://attack.mitre.org/techniques/T1087/001/) | Enumerated local accounts using net.exe and info-gathering scripts. |
| Account Discovery: Domain Account | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Enumerated domain accounts and groups en route to domain-admin access. |
| Permission Groups Discovery: Local Groups | [T1069.001](https://attack.mitre.org/techniques/T1069/001/) | Enumerated local group membership to identify local administrators on compromised hosts. |
| Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | Checked for installed security/AV software prior to deploying payloads. |
| System Network Connections Discovery | [T1049](https://attack.mitre.org/techniques/T1049/) | Enumerated active network connections on compromised hosts. |
| System Service Discovery | [T1007](https://attack.mitre.org/techniques/T1007/) | Queried installed services on compromised hosts during hands-on activity. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | Enumerated files and directories to locate credentials and data of interest. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Used RDP to move laterally within compromised networks. |
| Remote Services: SMB/Windows Admin Shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Used PAExec/PsExec over SMB admin shares to execute payloads on remote hosts and spread within networks (several hundred hosts infected in some environments). |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | Captured screenshots of compromised desktops via infostealer capability. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Collected files and data of interest from compromised local systems for exfiltration. |
| Automated Collection | [T1119](https://attack.mitre.org/techniques/T1119/) | Used infostealer implants to automatically collect credentials, browser data and host information. |
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Staged collected data and tooling in temporary directories (e.g. %Windir%\temp) prior to exfiltration. |
| Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Archived collected data using utilities prior to exfiltration. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Used HTTP(S) web protocols for command-and-control and payload retrieval across Syskit and custom implants. |
| Application Layer Protocol: Mail Protocols | [T1071.003](https://attack.mitre.org/techniques/T1071/003/) | IMAPLoader uses IMAP email as its command-and-control channel — polling an attacker-controlled mailbox for commands and returning results by email, a signature Yellow Liderc / Imperial Kitten technique. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Downloaded additional tools and payloads onto compromised hosts (Syskit is a downloader-backdoor; PowerShell/certutil also used to pull files). |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | Encrypted C2 content (including within the IMAP mail-based channel) to defeat inspection. |
| Data Encoding: Standard Encoding | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | Encoded C2 data (e.g. base64) within mail/web channels. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | Routed C2 through intermediary infrastructure to obscure the true endpoints. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltrated collected credentials and data back over the established C2 channel (including via the IMAPLoader mail channel). |
| Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) | Watering-hole profiling JavaScript exfiltrated visitor host-fingerprint data to attacker-controlled web services/domains. |
