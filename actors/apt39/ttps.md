# APT39 (G0087) — ATT&CK Technique Mapping

> Attribution: Iran-nexus — high confidence. MITRE ID: G0087.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **53** across **11** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | APT39 has obtained and used publicly available tools including Mimikatz, ProcDump, Windows Credential Editor, PsExec, and PLINK. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | APT39 (Chafer) has used SQL injection against public-facing web/database servers as an initial-access vector, frequently followed by web-shell deployment. |
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | APT39 has sent spear-phishing emails with malicious attachments (often macro documents) to targeted individuals for initial access. |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | APT39 has sent spear-phishing emails with malicious links to credential-harvesting or malware-delivery pages. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | APT39 has used various command and scripting interpreters for execution on compromised hosts. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | APT39 has used PowerShell (including POWBAT/POWERSTATS-adjacent tooling) to execute commands and stage payloads. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | APT39 has used Visual Basic scripts and macros in delivery documents to execute payloads. |
| Command and Scripting Interpreter: Python | [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | APT39 has used Python-based tooling/scripts for execution on compromised systems. |
| Command and Scripting Interpreter: AutoHotKey & AutoIT | [T1059.010](https://attack.mitre.org/techniques/T1059/010/) | APT39 has used AutoIt-based scripting for execution and to automate malicious tasks. |
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | APT39 has relied on targets clicking malicious links delivered via spear-phishing to achieve execution. |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | APT39 has relied on targets opening malicious attachments (often macro-enabled documents) to execute payloads. |
| System Services: Service Execution | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | APT39 has executed payloads by creating/starting Windows services (including via PsExec) on local and remote hosts. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | APT39 has created scheduled tasks to establish persistence and to execute payloads on compromised systems. |
| Create Account: Local Account | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | APT39 has created local accounts on compromised systems to maintain persistent access. |
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | APT39 has deployed web shells (ANTAK and ASPXSpy) on Internet-facing IIS/web servers, often following SQL injection, to maintain persistent remote access and execute commands. |
| Event Triggered Execution: AppInit DLLs | [T1546.010](https://attack.mitre.org/techniques/T1546/010/) | APT39 has abused the AppInit_DLLs registry mechanism to load malicious DLLs for persistence. |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | APT39 has established persistence via Registry Run keys and Startup-folder entries to auto-execute malware at logon. |
| Boot or Logon Autostart Execution: Shortcut Modification | [T1547.009](https://attack.mitre.org/techniques/T1547/009/) | APT39 has modified/created shortcut (.lnk) files to establish persistence and trigger payload execution. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Obfuscated Files or Information: Software Packing | [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | APT39 has used packers/crypters to obfuscate malware payloads and hinder static analysis and signature detection. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | APT39 has encrypted and encoded payloads and staged data (including base64) to evade detection and inspection. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | APT39 has named malware and tools to masquerade as legitimate files/processes and placed them in plausible locations to blend in. |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | APT39 has deleted tools, logs, and payload files after use to remove forensic artifacts. |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | APT39 has used stolen/valid credentials to access systems and remote services (RDP, VPN, OWA), blending in with legitimate activity — a core APT39 access and persistence pattern. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | APT39 has decoded/deobfuscated payloads and staged data at runtime (including base64 decoding via certutil/scripts). |
| BITS Jobs | [T1197](https://attack.mitre.org/techniques/T1197/) | APT39 has used Background Intelligent Transfer Service (BITS) jobs to download/transfer files while evading detection. |
| Subvert Trust Controls: Code Signing Policy Modification | [T1553.006](https://attack.mitre.org/techniques/T1553/006/) | APT39 has modified code-signing/driver-signature enforcement policy to allow unsigned or attacker-controlled code to load. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| OS Credential Dumping | [T1003](https://attack.mitre.org/techniques/T1003/) | APT39 has used credential-dumping tools such as Mimikatz, ProcDump, and Windows Credential Editor to steal credentials from compromised hosts. |
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | APT39 has used ProcDump and Mimikatz to dump LSASS memory to extract credentials. |
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | APT39 has deployed custom keyloggers to capture keystrokes and harvest credentials and monitor persons of interest. |
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | APT39 has used brute-force and credential-guessing techniques to obtain account credentials. |
| Credentials from Password Stores | [T1555](https://attack.mitre.org/techniques/T1555/) | APT39 has harvested stored credentials from password stores on compromised systems. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Query Registry | [T1012](https://attack.mitre.org/techniques/T1012/) | APT39 has queried the Windows registry to gather system and configuration information on compromised hosts. |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) | APT39 has used tools such as nbtscan and custom scripts to identify remote systems on the victim network prior to lateral movement. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | APT39 has run whoami and similar commands to identify the current user and privilege context on compromised systems. |
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | APT39 has scanned victim networks to identify open ports and reachable services prior to lateral movement. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | APT39 has enumerated files and directories to locate data of interest and stage collection. |
| Network Share Discovery | [T1135](https://attack.mitre.org/techniques/T1135/) | APT39 has enumerated network shares to identify accessible data repositories for collection and lateral movement. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | APT39 has used RDP with stolen credentials for lateral movement within compromised environments. |
| Remote Services: SMB/Windows Admin Shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | APT39 has used PsExec and SMB/admin shares (e.g. ADMIN$, C$) to move laterally and execute payloads on remote hosts. |
| Remote Services: SSH | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | APT39 has used SSH (including PLINK) to access and move between compromised systems. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | APT39 has collected data and files of interest (PII, travel/movement records, documents) from compromised local systems as part of its personal-information tracking mission. |
| Input Capture | [T1056](https://attack.mitre.org/techniques/T1056/) | APT39 has captured user input using keyloggers and related tooling to monitor targeted individuals. |
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | APT39 has staged collected data locally (often archived) prior to exfiltration. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | APT39 has used custom tools to capture screenshots of targeted users' desktops as part of surveillance. |
| Clipboard Data | [T1115](https://attack.mitre.org/techniques/T1115/) | APT39 has collected clipboard data from compromised systems as part of its information-gathering. |
| Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | APT39 has archived collected data with utilities (e.g. WinRAR) prior to exfiltration. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | APT39 has used HTTP/HTTPS-based C2 for its backdoors (e.g. Remexi and web-shell interaction). |
| Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | APT39 has used DNS as a command-and-control channel for certain tooling. |
| Proxy: Internal Proxy | [T1090.001](https://attack.mitre.org/techniques/T1090/001/) | APT39 has used internal proxies/relays to route C2 traffic between compromised hosts inside victim networks. |
| Proxy: External Proxy | [T1090.002](https://attack.mitre.org/techniques/T1090/002/) | APT39 has routed C2 through external proxy infrastructure to obscure the true destination of traffic. |
| Web Service: Bidirectional Communication | [T1102.002](https://attack.mitre.org/techniques/T1102/002/) | APT39 has used legitimate web services for bidirectional C2 communication to blend with normal traffic. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | APT39 has downloaded additional tools and payloads onto compromised systems, including via certutil and BITS. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | APT39 has exfiltrated stolen data (credentials, PII, documents) back to attacker infrastructure over its established command-and-control channels. |
