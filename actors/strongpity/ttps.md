# StrongPity — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **38** across **11** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Actors register typosquatting domains that closely mimic legitimate software vendors to host trojanized installers — e.g. ralrab[.]com (vs rarlab.com), winrar[.]it, winrar[.]be, and true-crypt[.]com (a replica of the TrueCrypt site). C2/distribution domains such as updserv-east-cdn3[.]com and downloading.internetdownloading[.]co were also registered. |
| Compromise Infrastructure: Server | [T1584.004](https://attack.mitre.org/techniques/T1584/004/) | StrongPity operates a three-tier command-and-control infrastructure using layered upstream servers (multi-hop) to thwart forensic investigation and hide the operators' true endpoint. |
| Stage Capabilities: Drive-by Target | [T1608.004](https://attack.mitre.org/techniques/T1608/004/) | Actors stand up watering-hole/replica download sites (fake WinRAR and TrueCrypt pages) so that users seeking encryption and archiving software are served an attacker-controlled page from which a trojanized installer is delivered. |
| Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | Actors host trojanized legitimate-software installers (WinRAR, TrueCrypt, CCleaner, Opera, Skype, VLC, Driver Booster, 7-Zip, WinBox) on their staging/distribution infrastructure for delivery to redirected victims. |
| Develop Capabilities: Code Signing Certificates | [T1587.002](https://attack.mitre.org/techniques/T1587/002/) | Actors use self-signed / attacker-controlled code-signing certificates to sign trojanized droppers and components so they appear more trustworthy at execution time. |
| Develop Capabilities: Digital Certificates | [T1587.003](https://attack.mitre.org/techniques/T1587/003/) | Actors provision TLS/SSL certificates for the HTTPS C2 channel used by the exfiltration component. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Drive-by Compromise | [T1189](https://attack.mitre.org/techniques/T1189/) | Signature delivery vector: watering-hole / drive-by. Users seeking legitimate encryption and utility software are redirected to actor-controlled replica sites that deliver a trojanized installer instead of the genuine application. |
| Content Injection | [T1659](https://attack.mitre.org/techniques/T1659/) | In the 2017 campaign, delivery used on-path HTTP content injection / 'on-the-fly' browser redirection most likely operating at the ISP level: a victim's plain-HTTP download request for a legitimate application was transparently redirected to a trojanized version. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | The victim runs the trojanized installer (e.g. WinRAR, TrueCrypt, CCleaner, VLC), which installs the legitimate application as a decoy while silently dropping the StrongPity dropper and components. |
| System Services: Service Execution | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | StrongPity components execute via a Windows service installed by the dropper, launching the persistent backdoor payload. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | StrongPity has used PowerShell to execute commands/scripts on the compromised host as part of its component chain. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | The StrongPity2 component (wmpsvn32.exe) persists via an HKCU\Software\Microsoft\Windows\CurrentVersion\Run entry named 'Help Manager', pointing at the payload staged in %temp%\lang_be29c9f3-83we. |
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | The StrongPity dropper installs a Windows service to persist and auto-launch the backdoor/exfiltration components across reboots. |
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | StrongPity has used scheduled tasks (alongside services and Run keys) to maintain execution of its components on compromised hosts. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Masquerading: Masquerade Task or Service | [T1036.004](https://attack.mitre.org/techniques/T1036/004/) | Actors name services/tasks and the autorun entry to look benign (e.g. Run-key value 'Help Manager', components named wmpsvn32.exe, procexp.exe, nvvscv.exe) so persistence blends with legitimate Windows/utility software. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Trojanized installers reuse the exact filenames and branding of the legitimate applications (e.g. wrar531.exe, WinRAR-x64-531it.exe, TrueCrypt-Setup-7.1a.exe), and dropped components mimic legitimate tool names (procexp.exe = SysInternals Process Explorer) to evade suspicion. |
| Subvert Trust Controls: Code Signing | [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | StrongPity droppers/components are code-signed (self-signed / actor certificates) to subvert trust controls and reduce user and security-product suspicion. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Configuration is stored in encrypted .cab blobs (prst.cab, wrlck.cab), and collected data is zipped then XOR-encrypted (per-byte nibble-swap XOR, chunked) into hidden .sft files before exfiltration, obscuring both config and staged data. |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | After the exfiltration component reads the hidden .sft archive fragments and sends them to the C2, the .sft files are deleted from disk to remove evidence of collection and exfiltration. |
| Hide Artifacts: Hidden Window | [T1564.003](https://attack.mitre.org/techniques/T1564/003/) | StrongPity components run with hidden windows to operate without a visible UI on the victim desktop. |

## Impair Defenses

| Technique | ID | Notes |
|---|---|---|
| Disable or Modify Tools | [T1685](https://attack.mitre.org/techniques/T1685/) | StrongPity adds its own directories to the Windows Defender scan-exclusion list so its files are not scanned, impairing endpoint defenses. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Adversary-in-the-Middle | [T1557](https://attack.mitre.org/techniques/T1557/) | The 2017 delivery relied on a man-in-the-middle positioned in the network path (assessed at the ISP level) to intercept and rewrite software-download traffic to serve trojanized binaries. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | Before executing, StrongPity checks for the presence of security products (notably ESET and Bitdefender) and adapts its behavior accordingly. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | StrongPity enumerates running processes on the host as part of its environment checks and targeting logic. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | The File Searcher component recursively enumerates the file system hunting for documents of interest by file extension (and for the presence of specific encryption/remote-admin tools such as putty.exe, filezilla.exe, winscp.exe, mstsc.exe, mRemoteNG.exe). |
| Local Storage Discovery | [T1680](https://attack.mitre.org/techniques/T1680/) | StrongPity enumerates local and removable storage volumes to locate documents and data for collection. |
| System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | StrongPity gathers system network configuration information from the compromised host. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | Early StrongPity toolkits shipped multiple modular components including a keylogger to capture user input on infected systems (documented in the original 2016 waterhole reporting alongside the file-collection modules). |
| Automated Collection | [T1119](https://attack.mitre.org/techniques/T1119/) | The File Searcher component automatically and continuously collects documents matching the target extensions and copies them for staging without operator interaction per file. |
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Collected documents are first copied into a zip archive, which is then chunk-encrypted into hidden .sft files staged locally in the malware directory prior to exfiltration. |
| Archive Collected Data: Archive via Custom Method | [T1560.003](https://attack.mitre.org/techniques/T1560/003/) | Collected data is archived into a zip and then transformed by a custom XOR routine (per-byte least/most-significant-nibble XOR, chunked up to 53 times, with N/O prefix markers on the first vs continuation fragments) into .sft files — a bespoke archive/encoding method. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | StrongPity supports self-update and can pull additional components/commands from the C2, transferring tools onto the compromised host. |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | StrongPity uses HTTP/HTTPS web protocols for command-and-control and for exfiltrating the .sft archive fragments to its C2 servers. |
| Encrypted Channel: Asymmetric Cryptography | [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | C2 communication between the first tier and the upstream target is protected with SSL/TLS (HTTPS), encrypting the exfiltration channel. |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | First-tier C2 communication uses HTTPS over the unusual TCP port 1402 rather than 443. |
| Proxy: Multi-hop Proxy | [T1090.003](https://attack.mitre.org/techniques/T1090/003/) | StrongPity relays C2 through a three-tier/multi-hop proxy chain so that the victim only ever contacts a first-layer node, hiding the true upstream operator infrastructure. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | The Exfiltration component sends the collected, encrypted .sft archive fragments to the C2 server over the same HTTPS channel used for command-and-control. |
| Automated Exfiltration | [T1020](https://attack.mitre.org/techniques/T1020/) | Once documents are collected and staged into .sft files, StrongPity automatically exfiltrates them to the C2 without per-file operator action, then deletes the local copies. |
