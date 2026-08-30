# POLONIUM — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **42** across **9** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | POLONIUM developed at least seven bespoke backdoors — CreepyDrive/CreepyBox and CreepySnail (PowerShell/.NET), and DeepCreep, MegaCreep, FlipCreep, TechnoCreep and PapaCreep (C#/C++) — plus a modular set of custom keylogger, screenshot, webcam, reverse-shell and exfiltration components. |
| Obtain Capabilities: Malware | [T1588.001](https://attack.mitre.org/techniques/T1588/001/) | The group incorporated publicly available keylogger code and libraries (e.g., AForge.NET for webcam capture, MegaApiClient for Mega) into its custom modules rather than writing all functionality from scratch. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | POLONIUM operationalized publicly available tooling including Plink (PuTTY SSH tunneling) and the AirVPN service; AirVPN usage overlaps with MOIS-affiliated groups. |
| Acquire Infrastructure: Virtual Private Server | [T1583.003](https://attack.mitre.org/techniques/T1583/003/) | The group acquired dedicated virtual private servers (via hosting provider HostGW) for command-and-control and tunneling. Infrastructure was IP-only with no domain names, reducing DNS-based detection. |
| Acquire Infrastructure: Web Services | [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | POLONIUM stood up 20+ malicious OneDrive applications and abused Dropbox and Mega cloud accounts as C2 infrastructure, embedding OAuth refresh tokens in implants so that C2 traffic blends with legitimate cloud-service usage. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Primary initial-access vector: exploitation of internet-facing Fortinet FortiOS SSL-VPN appliances via the path-traversal vulnerability CVE-2018-13379. Approximately 80% of Microsoft-observed victims ran Fortinet devices; the flaw allows retrieval of system files (including VPN credential/session data) from an unauthenticated endpoint. |
| External Remote Services | [T1133](https://attack.mitre.org/techniques/T1133/) | The group leverages Fortinet SSL-VPN external remote access to enter victim networks, using credentials obtained via CVE-2018-13379 exploitation or from Fortinet VPN credentials leaked online in September 2021. |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | POLONIUM used valid VPN account credentials for access; some victims' Fortinet VPN credentials had been leaked online in September 2021 and were reused by the actor to authenticate. |
| Trusted Relationship | [T1199](https://attack.mitre.org/techniques/T1199/) | Microsoft observed supply-chain-style access through compromised IT service providers, using a trusted third-party relationship to reach downstream Israeli victim organizations. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | CreepyDrive and CreepySnail are PowerShell implants that execute attacker commands on compromised hosts; CreepyDrive reads tasking from cloud storage and runs it via PowerShell. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | The C#/C++ backdoors (DeepCreep, MegaCreep, TechnoCreep, PapaCreep) execute received commands through the Windows command shell (cmd.exe) and return output over their C2 channels. |
| Shared Modules | [T1129](https://attack.mitre.org/techniques/T1129/) | POLONIUM fragments functionality across separate DLLs (e.g., PRLib.dll, MainZero.dll, Cert.dll, Sess.dll, yetty.dll) loaded at runtime, so no single component reveals the full attack chain. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | POLONIUM establishes persistence for its backdoors via Windows scheduled tasks that relaunch the implants. |
| Boot or Logon Autostart Execution: Shortcut Modification | [T1547.009](https://attack.mitre.org/techniques/T1547/009/) | The group places LNK shortcut files in the Startup folder so that backdoor components execute automatically at user logon. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| System Binary Proxy Execution: InstallUtil | [T1218.004](https://attack.mitre.org/techniques/T1218/004/) | DeepCreep is executed via the signed Microsoft .NET InstallUtil.exe utility to proxy execution of the malicious assembly and evade application controls. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | The backdoors decode/deobfuscate strings and payloads at runtime using ROT13, Base64 and AES to hide C2 commands, tokens and configuration. |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | POLONIUM modules delete files (including their own artifacts and collected/staged data) after use to reduce forensic footprint. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Implant and module executables are named to impersonate legitimate software — e.g., Mega.exe, DropBox.exe, OnDrive.exe, WinUpdate.dll, WinSc.exe, Device.exe, Regestries.exe and 'Microsoft Malware Protection.exe' — to blend into normal system/software directories. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | The .NET backdoors are protected with the AsStrongAsFuck obfuscator and encode/encrypt embedded strings and payloads to evade static detection. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | Backdoors enumerate files and directories on compromised hosts to locate documents and data of interest for collection. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | The implants enumerate running processes on the host as part of environment reconnaissance. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | Backdoors collect host/system information (OS, machine identifiers) which, alongside the username, is Base64-encoded into C2 beacons for victim tracking. |
| System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | The implants gather the host's network configuration and IP address; the IP is Base64-encoded and included in outbound web requests to the C2. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | The implants collect the logged-in username, which is Base64-encoded into the C2 request URIs to identify the victim. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | POLONIUM deploys a custom keylogger module that supports Hebrew and Arabic keyboard layouts (console output encoded as Windows-1255 for Hebrew), capturing victim keystrokes to a log for later exfiltration. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | A dedicated screenshot module (e.g., WinSc.exe) periodically captures the victim's screen for espionage collection. |
| Video Capture | [T1125](https://attack.mitre.org/techniques/T1125/) | POLONIUM uses an AForge.NET-based webcam-capture module (e.g., Device.exe) to record video/still images from the victim's camera. |
| Clipboard Data | [T1115](https://attack.mitre.org/techniques/T1115/) | The group captures clipboard contents from compromised hosts as part of its data-collection tooling. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | POLONIUM is espionage-focused on stealing confidential documents; modules collect files of interest from the local system for archiving and exfiltration. |
| Archive Collected Data: Archive via Library | [T1560.002](https://attack.mitre.org/techniques/T1560/002/) | Before exfiltration, collected data is compressed into ZIP archives via a code library within the .NET modules. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | CreepySnail and CreepyDrive communicate over HTTP(S) to C2 (custom servers and cloud APIs); machine username and IP are Base64-encoded into the request URIs. PapaCreep uses TCP with fake HTTP headers to mimic web traffic. |
| Application Layer Protocol: File Transfer Protocols | [T1071.002](https://attack.mitre.org/techniques/T1071/002/) | FlipCreep uses an FTP server for command-and-control (observed on ports such as 2121/21), and several exfiltration modules push data over FTP. |
| Web Service: Bidirectional Communication | [T1102.002](https://attack.mitre.org/techniques/T1102/002/) | Signature tradecraft: CreepyDrive/CreepyBox, DeepCreep and MegaCreep use legitimate cloud services (OneDrive, Dropbox, Mega) for bidirectional C2 — tasking is placed in files such as data.txt/cd.txt in the cloud directory and results are written back (response.json). OAuth refresh tokens are embedded in the implants so traffic goes only to legitimate cloud endpoints. |
| Data Encoding: Standard Encoding | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | Implants Base64-encode the machine username and IP address embedded in outbound web requests, and encode C2 command/response data. |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | MegaCreep encrypts its command-and-response channel with AES symmetric encryption, storing encrypted commands in Mega cloud storage. |
| Non-Application Layer Protocol | [T1095](https://attack.mitre.org/techniques/T1095/) | TechnoCreep communicates with its C2 over raw TCP sockets (e.g., port 1302) rather than an application-layer protocol. |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | C2 and exfiltration channels use non-standard ports including 8080, 63047, 5055, 1302, 2121 and 1433, complicating port-based filtering. |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | POLONIUM uses Plink (PuTTY SSH) to build SSH tunnels (including redundant tunnels) for network access and C2 relaying to their VPS infrastructure. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | The group routes activity through the AirVPN service (shared with MOIS-affiliated groups) and VPS relays to proxy and obscure the true source of their connections. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Backdoors download additional modules and tools (keylogger, screenshot, webcam, reverse shell, tunneling) to the victim from cloud storage or C2 to extend capability. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Several backdoors exfiltrate collected data back over their existing C2 channels (raw TCP, FTP, HTTP) to the actor's VPS servers. |
| Exfiltration Over Web Service: Exfiltration to Cloud Storage | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | CreepyDrive/CreepyBox, DeepCreep and MegaCreep exfiltrate stolen files to attacker-controlled OneDrive, Dropbox and Mega accounts, so exfiltration flows only to legitimate cloud-service domains. |
