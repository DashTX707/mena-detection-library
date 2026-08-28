# OilRig (G0049 / APT34) — ATT&CK Technique Mapping

> Source: official MITRE ATT&CK group page. Attribution: Iran-nexus (MOIS), high confidence. MITRE ID: G0049.
> Aliases: OilRig, COBALT GYPSY, IRN2, APT34, Helix Kitten, Evasive Serpens, Hazel Sandstorm, EUROPIUM, ITG13, Earth Simnavaz, Crambus, TA452

Total techniques mapped: **87** across **24** tactics.

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Account Discovery: Local Account | [T1087.001](https://attack.mitre.org/techniques/T1087/001/) | OilRig has run net user, net user /domain, net group "domain admins" /domain, and related commands to enumerate accounts. |
| Account Discovery: Domain Account | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | OilRig has run net user, net user /domain, net group "domain admins" /domain, and related commands to enumerate accounts. |
| Browser Information Discovery | [T1217](https://attack.mitre.org/techniques/T1217/) | OilRig has used a Chrome data dumper named MKG, and has used CDumper and EDumper to collect cookies. |
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | OilRig has used the publicly available tool SoftPerfect Network Scanner and custom tool GOLDIRONY. |
| Peripheral Device Discovery | [T1120](https://attack.mitre.org/techniques/T1120/) | OilRig has used tools to identify if a mouse is connected to a targeted system. |
| Permission Groups Discovery: Local Groups | [T1069.001](https://attack.mitre.org/techniques/T1069/001/) | OilRig has used net localgroup administrators to find local admins on systems. |
| Permission Groups Discovery: Domain Groups | [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | OilRig has used net group /domain, net group "domain admins" /domain, and related commands. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | OilRig has run tasklist on a victim's machine and used infostealers to capture processes. |
| Query Registry | [T1012](https://attack.mitre.org/techniques/T1012/) | OilRig has used reg query "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" on victim machines. |
| Software Discovery | [T1518](https://attack.mitre.org/techniques/T1518/) | OilRig has used browser data dumper tools to create a list of users with Google Chrome. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | OilRig has run hostname and systeminfo on a victim machine. |
| System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | OilRig has run ipconfig /all on a victim machine. |
| System Network Connections Discovery | [T1049](https://attack.mitre.org/techniques/T1049/) | OilRig has used netstat -an on a victim to get a listing of network connections. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | OilRig has run whoami on a victim machine. |
| System Service Discovery | [T1007](https://attack.mitre.org/techniques/T1007/) | OilRig has used sc query on a victim to gather information about services. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | OilRig has set up fake VPN portals, conference sign ups, and job application websites. |
| Compromise Accounts: Email Accounts | [T1586.002](https://attack.mitre.org/techniques/T1586/002/) | OilRig has compromised email accounts to send phishing emails. |
| Compromise Infrastructure: Server | [T1584.004](https://attack.mitre.org/techniques/T1584/004/) | OilRig has compromised an Israeli human resources site to use as a C2 server. |
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | OilRig actively developed and used a series of downloaders during 2022. |
| Establish Accounts: Cloud Accounts | [T1585.003](https://attack.mitre.org/techniques/T1585/003/) | OilRig has created M365 email accounts to be used as part of C2. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | OilRig has made use of publicly available tools including Plink and Mimikatz. |
| Obtain Capabilities: Code Signing Certificates | [T1588.003](https://attack.mitre.org/techniques/T1588/003/) | OilRig has obtained stolen code signing certificates to digitally sign malware. |
| Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | OilRig has hosted malware on fake websites designed to target specific audiences. |

## Command And Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | OilRig has used HTTP for C2, and has used HTTP to communicate between installed backdoors. |
| Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | OilRig has used DNS for C2 including the publicly available requestbin.net tunneling service. |
| Data Encoding: Standard Encoding | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | OilRig has used a VBS script to send the Base64-encoded name of the compromised computer. |
| Encrypted Channel: Asymmetric Cryptography | [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | OilRig has used the PowerExchange utility and other tools to create tunnels to C2. |
| Fallback Channels | [T1008](https://attack.mitre.org/techniques/T1008/) | OilRig's malware ISMAgent falls back to its DNS tunneling if unable to reach C2 server over HTTP. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | OilRig has downloaded remote files onto victim infrastructure. |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | OilRig has used the Plink utility and other tools to create tunnels to C2 servers. |
| Remote Access Tools | [T1219](https://attack.mitre.org/techniques/T1219/) | OilRig has incorporated remote monitoring and management tools including ngrok into operations. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Automated Collection | [T1119](https://attack.mitre.org/techniques/T1119/) | OilRig has used automated collection. |
| Clipboard Data | [T1115](https://attack.mitre.org/techniques/T1115/) | OilRig has used infostealer tools to copy clipboard data. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | OilRig has used PowerShell to upload files from compromised systems. |
| Data from Removable Media | [T1025](https://attack.mitre.org/techniques/T1025/) | OilRig has used Wireshark's usbcapcmd utility to capture USB traffic. |
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | OilRig has used browser data and credential stealer tools to stage stolen files in %TEMP%. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | OilRig has a tool called CANDYKING to capture a screenshot of the user's desktop. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | OilRig has used brute force techniques to obtain credentials. |
| Credentials from Password Stores | [T1555](https://attack.mitre.org/techniques/T1555/) | OilRig has used credential dumping tools such as LaZagne to steal credentials. |
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | OilRig has used credential dumping tools to steal credentials, and has used CDumper and EDumper. |
| Credentials from Password Stores: Windows Credential Manager | [T1555.004](https://attack.mitre.org/techniques/T1555/004/) | OilRig has used a credential dumping tool named VALUEVAULT to steal credentials. |
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OilRig has used credential dumping tools such as Mimikatz to steal credentials. |
| OS Credential Dumping: LSA Secrets | [T1003.004](https://attack.mitre.org/techniques/T1003/004/) | OilRig has used credential dumping tools such as LaZagne to steal credentials. |
| OS Credential Dumping: Cached Domain Credentials | [T1003.005](https://attack.mitre.org/techniques/T1003/005/) | OilRig has used credential dumping tools such as LaZagne to steal credentials. |
| Unsecured Credentials: Credentials In Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | OilRig has used credential dumping tools to steal credentials to accounts. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | OilRig has used various types of scripting for execution. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | OilRig has used PowerShell scripts for execution, including use of a macro to run a PowerShell command. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | OilRig has used macros to deliver malware, and has used batch scripts. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | OilRig has used VBScript macros for execution, and has used VBS droppers to deploy/deliver malware. |
| Exploitation for Client Execution | [T1203](https://attack.mitre.org/techniques/T1203/) | OilRig has exploited CVE-2024-30088 to run arbitrary code in the context of SYSTEM. |
| Password Policy Discovery | [T1201](https://attack.mitre.org/techniques/T1201/) | OilRig has used net.exe in a script with net accounts /domain to find password policy. |
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | OilRig has delivered malicious links to achieve execution on the target system. |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | OilRig has delivered macro-enabled documents requiring targets to click enable content. |
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) | OilRig has used WMI for execution. |

## Persistence, Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | OilRig has used a compromised Domain Controller to create a service on a remote host. |

## Stealth

| Technique | ID | Notes |
|---|---|---|
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | An OilRig macro has run a PowerShell command to decode file contents, and OilRig has used certutil to decode base64-encoded files. |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | OilRig has deleted files associated with their payload after execution. |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | OilRig has used .doc file extensions to mask malicious executables. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | OilRig has named a downloaded copy of the Plink tunneling utility as \ProgramData\Adobe.exe. |
| Obfuscated Files or Information: Indicator Removal from Tools | [T1027.005](https://attack.mitre.org/techniques/T1027/005/) | OilRig has tested malware samples to determine AV detection and subsequently modified samples. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | OilRig has encrypted and encoded data in malware, including by using base64. |
| System Binary Proxy Execution: Compiled HTML File | [T1218.001](https://attack.mitre.org/techniques/T1218/001/) | OilRig has used a CHM payload to load and execute another malicious file. |

## Defense Impairment

| Technique | ID | Notes |
|---|---|---|
| Disable or Modify System Firewall: Windows Host Firewall | [T1686.003](https://attack.mitre.org/techniques/T1686/003/) | OilRig has modified Windows firewall rules to enable remote access. |
| Subvert Trust Controls: Code Signing | [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | OilRig has signed its malware with stolen certificates. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | OilRig has exfiltrated data via Microsoft Exchange and over FTP separately. |

## Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Exploitation for Privilege Escalation | [T1068](https://attack.mitre.org/techniques/T1068/) | OilRig has exploited the Windows Kernel Elevation of Privilege vulnerability CVE-2024-30088. |

## Initial Access, Persistence

| Technique | ID | Notes |
|---|---|---|
| External Remote Services | [T1133](https://attack.mitre.org/techniques/T1133/) | OilRig uses remote services such as VPN, Citrix, or OWA to persist in an environment. |

## Credential Access, Collection

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | OilRig has employed keyloggers including KEYPUNCH and LONGWATCH. |

## Persistence, Credential Access, Defense Impairment

| Technique | ID | Notes |
|---|---|---|
| Modify Authentication Process: Password Filter DLL | [T1556.002](https://attack.mitre.org/techniques/T1556/002/) | OilRig has registered a password filter DLL in order to drop malware. |

## Persistence, Defense Impairment

| Technique | ID | Notes |
|---|---|---|
| Modify Registry | [T1112](https://attack.mitre.org/techniques/T1112/) | OilRig has used reg.exe to modify system configuration. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Office Application Startup: Outlook Home Page | [T1137.004](https://attack.mitre.org/techniques/T1137/004/) | OilRig has abused the Outlook Home Page feature for persistence. |
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | OilRig has used web shells, often to maintain access to a victim network. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | OilRig has sent spearphishing emails with malicious attachments to potential victims. |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | OilRig has sent spearphishing emails with malicious links to potential victims. |
| Phishing: Spearphishing via Service | [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | OilRig has used LinkedIn to send spearphishing links. |
| Supply Chain Compromise | [T1195](https://attack.mitre.org/techniques/T1195/) | OilRig has leveraged compromised organizations to conduct supply chain attacks. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | OilRig has used Remote Desktop Protocol for lateral movement. |
| Remote Services: SSH | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | OilRig has used Putty to access compromised systems. |

## Execution, Persistence, Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | OilRig has created scheduled tasks that run a VBScript to execute a payload on victim machines. |

## Initial Access, Persistence, Privilege Escalation, Stealth

| Technique | ID | Notes |
|---|---|---|
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | OilRig has used compromised credentials to access other systems on a victim network. |
| Valid Accounts: Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | OilRig has used an exfiltration tool named STEALHOOK to retrieve valid domain credentials. |

## Stealth, Discovery

| Technique | ID | Notes |
|---|---|---|
| Virtualization/Sandbox Evasion: System Checks | [T1497.001](https://attack.mitre.org/techniques/T1497/001/) | OilRig has used macros to verify if a mouse is connected to a compromised machine. |

## Initial Access (Ics)

| Technique | ID | Notes |
|---|---|---|
| Drive-by Compromise (ICS) | [T0817](https://attack.mitre.org/techniques/T0817/) | OilRig utilized watering hole attacks to collect credentials for ICS network access. |
| Spearphishing Attachment (ICS) | [T0865](https://attack.mitre.org/techniques/T0865/) | OilRig used spearphishing emails with malicious Microsoft Excel spreadsheet attachments. |
| Valid Accounts (ICS) | [T0859](https://attack.mitre.org/techniques/T0859/) | OilRig utilized stolen credentials to gain access to victim machines. |

## Execution (Ics)

| Technique | ID | Notes |
|---|---|---|
| Scripting (ICS) | [T0853](https://attack.mitre.org/techniques/T0853/) | OilRig embedded a macro with both a VBScript and a PowerShell script in emails. |

## Command And Control (Ics)

| Technique | ID | Notes |
|---|---|---|
| Standard Application Layer Protocol (ICS) | [T0869](https://attack.mitre.org/techniques/T0869/) | OilRig communicated with command and control using HTTP requests. |
