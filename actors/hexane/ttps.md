# HEXANE (G1001) — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence. MITRE ID: G1001.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **63** across **13** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Gather Victim Identity Information | [T1589](https://attack.mitre.org/techniques/T1589/) | HEXANE conducted reconnaissance against target-organization personnel, gathering identity details of employees in IT and communications roles to enable social-engineering lures. |
| Gather Victim Identity Information: Email Addresses | [T1589.002](https://attack.mitre.org/techniques/T1589/002/) | HEXANE collected employee email addresses to build spearphishing target lists. |
| Gather Victim Org Information: Identify Roles | [T1591.004](https://attack.mitre.org/techniques/T1591/004/) | HEXANE identified individuals in specific roles (IT, communications, HR) at target organizations to tailor its recruitment-themed lures. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | HEXANE registered domains, some spoofing legitimate brands (e.g. a fake careers/recruitment site), for use in phishing and C2. |
| Acquire Infrastructure: DNS Server | [T1583.002](https://attack.mitre.org/techniques/T1583/002/) | HEXANE operated attacker-controlled DNS servers to support DanBot's DNS-tunneling C2 channel. |
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | HEXANE created fake LinkedIn personas impersonating HR/recruitment staff of a legitimate company to approach targeted employees. |
| Establish Accounts: Email Accounts | [T1585.002](https://attack.mitre.org/techniques/T1585/002/) | HEXANE established email accounts to support its social-engineering and phishing operations. |
| Compromise Accounts: Email Accounts | [T1586.002](https://attack.mitre.org/techniques/T1586/002/) | HEXANE compromised legitimate email accounts to lend credibility to its phishing and to send messages from trusted senders. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | HEXANE obtained and used tooling to support intrusion operations alongside its custom implants. |
| Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | HEXANE staged malware on attacker-controlled infrastructure (including the spoofed careers site) for delivery to targets. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | HEXANE leveraged valid credentials obtained via password spraying against internet-facing services (e.g. Exchange/OWA, O365) to gain and maintain access. |
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | HEXANE sent spearphishing emails carrying macro-enabled Microsoft Excel/Office attachments (DanDrop) that dropped the DanBot backdoor when macros were enabled. |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | HEXANE lured targets to a spoofed recruitment/careers website via links delivered through fake LinkedIn personas and email. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | HEXANE relied on targets opening malicious Office documents and enabling macros to execute the DanDrop dropper / DanBot payload. |
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | HEXANE induced victims to click links to attacker-controlled sites hosting malicious content. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | HEXANE used PowerShell scripts for execution, tooling and DNS-based post-exploitation activity. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | HEXANE used the Windows command shell to run commands and orchestrate its tooling on compromised hosts. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | HEXANE used VBA macros (DanDrop) embedded in Office documents to drop and execute the DanBot backdoor. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | HEXANE used scheduled tasks to establish persistence for its implants. |
| Event Triggered Execution: Windows Management Instrumentation Event Subscription | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | HEXANE used WMI event subscriptions to persistently trigger execution of its payloads. |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | HEXANE established persistence via Registry Run-key entries for its DanBot/DanDrop components. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | HEXANE obfuscated its payloads and scripts to hinder analysis and evade detection. |
| Obfuscated Files or Information: Command Obfuscation | [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | HEXANE obfuscated command-line and script content (including PowerShell and VBA) to evade detection. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | HEXANE stored payload components in encrypted/encoded form on disk to evade static detection. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | HEXANE's loaders and scripts decode/deobfuscate embedded payloads at runtime prior to execution. |

## Impair Defenses

| Technique | ID | Notes |
|---|---|---|
| Disable or Modify Tools | [T1685](https://attack.mitre.org/techniques/T1685/) | HEXANE took steps to impair host defensive tooling to reduce detection of its implants. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | HEXANE conducted brute-force attacks to obtain valid credentials for internet-facing services. |
| Brute Force: Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | HEXANE used password spraying — a small set of common passwords tried across many accounts — against Exchange/OWA and O365 to obtain initial access while avoiding lockouts. |
| Credentials from Password Stores | [T1555](https://attack.mitre.org/techniques/T1555/) | HEXANE used a credential-harvesting tool to steal credentials from password stores on compromised hosts. |
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | HEXANE deployed a tool to steal credentials saved in victims' web browsers. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Application Window Discovery | [T1010](https://attack.mitre.org/techniques/T1010/) | HEXANE enumerated open application windows on compromised hosts. |
| System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | HEXANE collected network-configuration details (IP addresses, domain) from compromised systems. |
| System Network Configuration Discovery: Internet Connection Discovery | [T1016.001](https://attack.mitre.org/techniques/T1016/001/) | HEXANE checked for internet connectivity from compromised hosts prior to establishing C2. |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) | HEXANE enumerated remote systems on the target network to support lateral movement. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | HEXANE collected the current username from compromised hosts. |
| System Network Connections Discovery | [T1049](https://attack.mitre.org/techniques/T1049/) | HEXANE enumerated active network connections on compromised hosts. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | HEXANE obtained lists of running processes on compromised systems. |
| Permission Groups Discovery: Local Groups | [T1069.001](https://attack.mitre.org/techniques/T1069/001/) | HEXANE enumerated local group memberships on compromised hosts. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | HEXANE collected host information such as OS version and machine name. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | HEXANE enumerated files and directories on compromised systems to locate data of interest. |
| Account Discovery | [T1087](https://attack.mitre.org/techniques/T1087/) | HEXANE enumerated user accounts within the target environment. |
| Account Discovery: Domain Account | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | HEXANE enumerated domain accounts to expand access and plan lateral movement. |
| Software Discovery | [T1518](https://attack.mitre.org/techniques/T1518/) | HEXANE enumerated installed software on compromised hosts, including to identify security tooling. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | HEXANE used RDP for lateral movement within compromised networks. |
| Internal Spearphishing | [T1534](https://attack.mitre.org/techniques/T1534/) | HEXANE used compromised internal mailboxes to send spearphishing messages to additional users within the target organization. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | HEXANE deployed a keylogger (a PowerShell/DNS keylogger and Milan components) to capture keystrokes from targeted users. |
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | HEXANE staged collected data locally on compromised hosts prior to exfiltration. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | HEXANE's tooling captured screenshots from compromised hosts. |
| Email Collection | [T1114](https://attack.mitre.org/techniques/T1114/) | HEXANE collected email content from compromised mailboxes as part of its espionage objectives. |
| Automated Collection | [T1119](https://attack.mitre.org/techniques/T1119/) | HEXANE's implants automatically collected files and system data of interest from compromised hosts. |
| Archive Collected Data | [T1560](https://attack.mitre.org/techniques/T1560/) | HEXANE archived collected data prior to exfiltration. |
| Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | HEXANE used utilities to compress/archive collected data before exfiltration. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | HEXANE's DanBot and Shark backdoors support HTTP(S)-based C2 communications as an alternative to DNS tunneling. |
| Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | HEXANE's signature DanBot backdoor tunnels C2 over DNS, embedding commands and exfiltrated data in DNS queries/responses to attacker-controlled name servers — a defining HEXANE tradecraft. |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | HEXANE encapsulates C2 traffic within the DNS protocol (DNS tunneling via DanBot) to conceal communications and bypass network filtering. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | HEXANE routed C2 through intermediary infrastructure to obscure the true location of its command-and-control. |
| Web Service: Bidirectional Communication | [T1102.002](https://attack.mitre.org/techniques/T1102/002/) | HEXANE's Marlin backdoor abuses Microsoft OneDrive / Graph API for bidirectional C2, receiving commands and returning results via a legitimate cloud service. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | HEXANE's implants download additional tools and payloads to compromised hosts. |
| Data Encoding: Standard Encoding | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | HEXANE encoded C2 data (embedded within DNS labels/HTTP) using standard encoding schemes. |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | HEXANE used non-standard ports for some C2 communications. |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | HEXANE encrypted C2 traffic using symmetric cryptography to protect command and exfiltration content. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | HEXANE exfiltrated collected data over its C2 channel, including embedded within DNS-tunneling traffic. |
| Exfiltration Over Web Service: Exfiltration to Cloud Storage | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | HEXANE exfiltrated data to cloud-storage services (e.g. via the Marlin backdoor's OneDrive channel). |
