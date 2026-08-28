# MuddyWater (G0069) — ATT&CK Technique Mapping

> Source: official MITRE ATT&CK group page. Attribution: Iran-nexus (MOIS), high confidence. MITRE ID: G0069.
> Aliases: MuddyWater, Earth Vetala, MERCURY, Static Kitten, Seedworm, TEMP.Zagros, Mango Sandstorm, TA450, MuddyKrill

Total techniques mapped: **68** across **17** tactics.

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | MuddyWater has performed credential dumping with Mimikatz and procdump64.exe. |
| OS Credential Dumping: LSA Secrets | [T1003.004](https://attack.mitre.org/techniques/T1003/004/) | MuddyWater has performed credential dumping with LaZagne. |
| OS Credential Dumping: Cached Domain Credentials | [T1003.005](https://attack.mitre.org/techniques/T1003/005/) | MuddyWater has performed credential dumping with LaZagne. |
| Unsecured Credentials: Credentials In Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | MuddyWater has run a tool that steals passwords saved in victim email. |
| Credentials from Password Stores | [T1555](https://attack.mitre.org/techniques/T1555/) | MuddyWater has performed credential dumping with LaZagne and other tools, including by dumping passwords saved in victim email. |
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | MuddyWater has run tools including Browser64 to steal passwords saved in victim web browsers. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | MuddyWater has used malware to collect the victim's IP address and domain name. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | MuddyWater has used malware that can collect the victim's username. |
| System Network Connections Discovery | [T1049](https://attack.mitre.org/techniques/T1049/) | MuddyWater has used a PowerShell backdoor to check for Skype connections on the target machine. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | MuddyWater has used malware to obtain a list of running processes on the system. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | MuddyWater has used malware that can collect the victim's OS version and machine name. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | MuddyWater has used malware that checked if the ProgramData folder had folders or files with keywords 'Kasper,' 'Panda,' or 'ESET.' |
| Account Discovery: Domain Account | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | MuddyWater has used cmd.exe net user /domain to enumerate domain users. |
| Software Discovery | [T1518](https://attack.mitre.org/techniques/T1518/) | MuddyWater has used a PowerShell backdoor to check for Skype connectivity on the target machine. |
| Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | MuddyWater has used malware to check running processes against a hard-coded list of security tools often used by malware researchers. |

## Stealth

| Technique | ID | Notes |
|---|---|---|
| Obfuscated Files or Information: Steganography | [T1027.003](https://attack.mitre.org/techniques/T1027/003/) | MuddyWater has stored obfuscated JavaScript code in an image file named temp.jpg. |
| Obfuscated Files or Information: Compile After Delivery | [T1027.004](https://attack.mitre.org/techniques/T1027/004/) | MuddyWater has used the .NET csc.exe tool to compile executables from downloaded C# code. |
| Obfuscated Files or Information: Command Obfuscation | [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | MuddyWater has used Daniel Bohannon's Invoke-Obfuscation framework and obfuscated PowerShell scripts. The group has also used other obfuscation methods, including Base64 obfuscation of VBScripts and PowerShell commands. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | MuddyWater has disguised malicious executables and used filenames and Registry key names associated with Windows Defender. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | MuddyWater has decoded base64-encoded PowerShell, JavaScript, and VBScript. |
| System Binary Proxy Execution: CMSTP | [T1218.003](https://attack.mitre.org/techniques/T1218/003/) | MuddyWater has used CMSTP.exe and a malicious INF to execute its POWERSTATS payload. |
| System Binary Proxy Execution: Mshta | [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | MuddyWater has used mshta.exe to execute its POWERSTATS payload and to pass a PowerShell one-liner for execution. |
| System Binary Proxy Execution: Rundll32 | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | MuddyWater has used malware that leveraged rundll32.exe in a Registry Run key to execute a .dll. |
| Social Engineering for Impact: Impersonation | [T1684.001](https://attack.mitre.org/techniques/T1684/001/) | MuddyWater has used support@microsoftonlines[.]com to send phishing emails that masqueraded as security updates from Microsoft. MuddyWater has also impersonated TMCell (Altyn Asyr CJSC), the primary mobile operator in Turkmenistan. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | MuddyWater has used C2 infrastructure to receive exfiltrated data. |
| Exfiltration Over Web Service: Exfiltration to Cloud Storage | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | MuddyWater has attempted to exfiltrate data to Wasabi, a cloud storage service, using Rclone. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) | MuddyWater has used malware that leveraged WMI for execution and querying host information. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | MuddyWater has used PowerShell for execution. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | MuddyWater has used a custom tool for creating reverse shells. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | MuddyWater has used VBScript files to execute its POWERSTATS payload, as well as macros. |
| Command and Scripting Interpreter: Python | [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | MuddyWater has developed tools in Python including Out1. |
| Command and Scripting Interpreter: JavaScript | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | MuddyWater has used JavaScript files to execute its POWERSTATS payload. |
| Exploitation for Client Execution | [T1203](https://attack.mitre.org/techniques/T1203/) | MuddyWater has exploited the Office vulnerability CVE-2017-0199 for execution. |
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | MuddyWater has distributed URLs in phishing e-mails that link to lure documents. |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | MuddyWater has attempted to get users to open malicious PDF attachment and to enable macros and launch malicious Microsoft Word documents. Additionally, MuddyWater has used a Word document with a malicious Visual Basic for Applications (VBA) macro. |
| User Execution: Malicious Copy and Paste | [T1204.004](https://attack.mitre.org/techniques/T1204/004/) | MuddyWater has leveraged ClickFix type tactics enticing victims to copy and paste malicious PowerShell code. |
| Inter-Process Communication: Component Object Model | [T1559.001](https://attack.mitre.org/techniques/T1559/001/) | MuddyWater has used malware that has the capability to execute malicious code via COM, DCOM, and Outlook. |
| Inter-Process Communication: Dynamic Data Exchange | [T1559.002](https://attack.mitre.org/techniques/T1559/002/) | MuddyWater has used malware that can execute PowerShell scripts via DDE. |

## Execution, Persistence, Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | MuddyWater has used scheduled tasks to establish persistence. |

## Command And Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | MuddyWater has used HTTP for C2 communications. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | MuddyWater has used NordVPN to proxy phishing emails, making them appear to originate from France. |
| Proxy: External Proxy | [T1090.002](https://attack.mitre.org/techniques/T1090/002/) | MuddyWater has controlled POWERSTATS from behind a proxy network to obfuscate the C2 location. MuddyWater has used a series of compromised websites that victims connected to randomly to relay information to command and control (C2). MuddyWater has also used go-socks5 variants to bypass firewalls and Network Address Translation (NAT). |
| Web Service: Bidirectional Communication | [T1102.002](https://attack.mitre.org/techniques/T1102/002/) | MuddyWater has used web services including OneHub to distribute remote access tools. |
| Multi-Stage Channels | [T1104](https://attack.mitre.org/techniques/T1104/) | MuddyWater has used one C2 to obtain enumeration scripts and monitor web logs, but a different C2 to send data back. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | MuddyWater has used malware that can upload additional files to the victim's machine. MuddyWater has used PowerShell commands to install remote management and monitoring (RMM) software on the victim's machine. |
| Data Encoding: Standard Encoding | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | MuddyWater has used tools to encode C2 communications including Base64 encoding. |
| Remote Access Software: Remote Desktop Software | [T1219.002](https://attack.mitre.org/techniques/T1219/002/) | MuddyWater has leveraged RMM solutions including ScreenConnect, AteraAgent, SimpleHelp, Action1, Level, and PDQ to facilitate follow-on actions. |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | MuddyWater has used ports 8043 and 8848 for botnet C2 communication. |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | MuddyWater has used AES to encrypt C2 responses. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | MuddyWater has stored a decoy PDF file within a victim's %temp% folder. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | MuddyWater has used malware that can capture screenshots of the victim's machine. |
| Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | MuddyWater has used the native Windows cabinet creation tool, makecab.exe, likely to compress stolen data. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Office Application Startup: Office Template Macros | [T1137.001](https://attack.mitre.org/techniques/T1137/001/) | MuddyWater has used a Word Template, Normal.dotm, for persistence. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | MuddyWater has exploited the Microsoft Exchange memory corruption vulnerability (CVE-2020-0688). |
| Phishing | [T1566](https://attack.mitre.org/techniques/T1566/) | MuddyWater has sent phishing emails to targets from the email address support@microsoftonlines[.]com. |
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | MuddyWater has compromised third parties and used compromised accounts to send spearphishing emails with targeted attachments. MuddyWater has also sent spearphishing emails with the attachment Cybersecurity.doc, which served as the primarily payload. |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | MuddyWater has sent targeted spearphishing e-mails with malicious links. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Exploitation of Remote Services | [T1210](https://attack.mitre.org/techniques/T1210/) | MuddyWater has exploited the Microsoft Netlogon vulnerability (CVE-2020-1472). |
| Internal Spearphishing | [T1534](https://attack.mitre.org/techniques/T1534/) | MuddyWater has used compromised mailboxes within target organizations to send spearphishing emails. |

## Persistence, Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | MuddyWater has added Registry Run key KCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemTextEncoding to establish persistence. |

## Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Abuse Elevation Control Mechanism: Bypass User Account Control | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | MuddyWater uses various techniques to bypass UAC. |

## Execution, Stealth

| Technique | ID | Notes |
|---|---|---|
| Hijack Execution Flow: DLL | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | MuddyWater maintains persistence on victim networks through side-loading dlls to trick legitimate programs into running malware. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | MuddyWater has established domains, some of which appeared to spoof legitimate domains for use in operations. |
| Acquire Infrastructure: Web Services | [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | MuddyWater has used file sharing services including OneHub, Sync, and TeraBox to distribute tools. |
| Obtain Capabilities: Malware | [T1588.001](https://attack.mitre.org/techniques/T1588/001/) | MuddyWater has used publicly available malware for operations, likely to blend in with other cybercriminals. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | MuddyWater has used legitimate tools ConnectWise, RemoteUtilities, and SimpleHelp to gain access to the target environment. |

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Gather Victim Network Information: Network Topology | [T1590.004](https://attack.mitre.org/techniques/T1590/004/) | MuddyWater has mapped target networks; access to this information and more is then shared/sold to other Iran threat actors. |

## Defense Impairment

| Technique | ID | Notes |
|---|---|---|
| Disable or Modify Tools | [T1685](https://attack.mitre.org/techniques/T1685/) | MuddyWater can disable the system's local proxy settings. |
