# Gaza Cybergang / Molerats (G0021) — ATT&CK Technique Mapping

> Attribution: Palestinian-nexus, politically motivated — high confidence. MITRE ID: G0021.
> Enriched from MITRE ATT&CK G0021 + public reporting (see intel/cti-pipeline.json for per-technique sources).

Total techniques mapped: **36** across **9** tactics.

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Gaza Cybergang sends spearphishing emails with malicious Microsoft Word/Excel and PDF attachments carrying regional-politics lures (Israeli-Palestinian affairs, Hamas/Fatah, diplomatic themes) to deliver Spark, SharpStage and IronWind. |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Gaza Cybergang sends phishing emails containing malicious links, including geofenced links (NimbleMamba) and Dropbox-hosted links (IronWind) that gate delivery to intended regional victims. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Sends malicious links via email that trick users into opening a RAR/archive and running an embedded executable. |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Delivers files via email that trick users into clicking Enable Content to run an embedded macro, or into opening weaponized XLL/.accdb files leading to IronWind. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Uses PowerShell implants and PowerShell execution stages (observed in SharpStage and MoleNet chains). |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Spark, SharpStage, DropBook, MoleNet and Pierogi execute commands via the Windows command shell (cmd.exe). |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Uses various implants built with VBScript on target machines, including macro-embedded VBS droppers. |
| Command and Scripting Interpreter: Python | [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | DropBook is a Python-based backdoor compiled with PyInstaller, executing Python-implemented backdoor logic on the victim. |
| Command and Scripting Interpreter: JavaScript | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | Uses various implants including those built with JavaScript on target machines. |
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) | SharpStage and MoleNet use WMI for execution and host reconnaissance. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Creates scheduled tasks to persistently run VBScripts and to relaunch the SharpStage backdoor. |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Saves malicious files within AppData and Startup folders and sets Run keys to maintain persistence (SharpStage, MoleNet). |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) | The IronWind multi-stage loader downloads and injects shellcode into a target process to run follow-on stages in memory. |
| System Binary Proxy Execution: Msiexec | [T1218.007](https://attack.mitre.org/techniques/T1218/007/) | Uses msiexec.exe to execute an MSI payload as a proxy for malicious code execution. |
| Subvert Trust Controls: Code Signing | [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | Uses forged/abused Microsoft code-signing certificates on malware to appear trusted. |
| Obfuscated Files or Information: Software Packing | [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | The Spark backdoor is packed (Enigma protector) to hinder static analysis and detection. |
| Obfuscated Files or Information: HTML Smuggling | [T1027.006](https://attack.mitre.org/techniques/T1027/006/) | IronWind initial-access chains use HTML smuggling to reconstruct and drop the malicious archive/payload client-side, evading gateway inspection. |
| Obfuscated Files or Information: Compression | [T1027.015](https://attack.mitre.org/techniques/T1027/015/) | Delivers compressed executables within ZIP/RAR files to victims to evade content inspection. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | Decompresses ZIP files once on the victim machine and decodes staged/encoded payloads at runtime (Spark, SharpStage, DropBook). |
| Virtualization/Sandbox Evasion: User Activity Based Checks | [T1497.002](https://attack.mitre.org/techniques/T1497/002/) | Spark performs anti-analysis/user-activity checks before executing to avoid detonating in sandboxes. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| System Location Discovery: System Language Discovery | [T1614.001](https://attack.mitre.org/techniques/T1614/001/) | Spark, DropBook and SharpStage check the system's keyboard/language settings so the malware runs only on Arabic-language systems; NimbleMamba similarly geofences delivery — a signature Gaza Cybergang victim-gating behavior. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | Spark, DropBook, SharpStage and MoleNet collect host information (OS, hostname, hardware) and report it to C2. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | Spark gathers the victim's username/owner information as part of host profiling. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | DropBook enumerates files and directories on the victim to select data of interest. |
| Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | MoleNet enumerates installed security/AV software on the victim to inform follow-on tooling. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | Obtains a list of active processes on the victim and sends them to C2 servers. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | Uses the public tool BrowserPasswordDump10 to dump passwords saved in victim browsers. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | SharpStage and the Pierogi backdoor capture screenshots of the victim's desktop for espionage. |

## Command And Control

| Technique | ID | Notes |
|---|---|---|
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Uses executables and backdoors (DropBook, SharpStage, MoleNet, IronWind, Pierogi) to download additional malicious files and follow-on stages onto the victim. |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Spark and IronWind communicate with C2 over HTTP/web protocols. |
| Data Encoding: Standard Encoding | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | Spark encodes C2 data using standard encoding (e.g. base64) before transmission. |
| Web Service | [T1102](https://attack.mitre.org/techniques/T1102/) | DropBook and SharpStage use legitimate web/cloud services (Dropbox, Google Drive, Facebook, Simplenote, Quora) as the C2 medium to blend with normal SaaS traffic — a signature Gaza Cybergang tradecraft. |
| Web Service: Bidirectional Communication | [T1102.002](https://attack.mitre.org/techniques/T1102/002/) | DropBook receives commands and NimbleMamba tasks/returns data through the Dropbox/Facebook/Simplenote APIs, using the cloud service for full bidirectional C2. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Spark exfiltrates collected victim data back over its established C2 channel. |
| Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) | DropBook exfiltrates stolen data to attacker-controlled cloud-service accounts rather than dedicated C2 infrastructure. |
| Exfiltration Over Web Service: Exfiltration to Cloud Storage | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | NimbleMamba and DropBook exfiltrate collected files to actor-controlled Dropbox cloud storage. |
