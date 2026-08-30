# SideWinder — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **46** across **12** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Phishing for Information: Spearphishing Link | [T1598.003](https://attack.mitre.org/techniques/T1598/003/) | SideWinder sends spear-phishing messages containing links, and uses lure themes tailored to the victim (government, maritime/port authority, nuclear-agency topics) to profile and engage targets before delivering payloads. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | SideWinder develops and continuously maintains its own bespoke tooling — the StealerBot modular toolkit, the ModuleInstaller .NET downloader and the Backdoor Loader — regenerating new modified malware variants (often within hours) when a version is detected. |
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | SideWinder registers large numbers of look-alike / typosquatted domains impersonating regional governments, ministries and port authorities (e.g. mofa-gov-sa.direct888[.]net masquerading as the Saudi Ministry of Foreign Affairs, depo-govpk[.]com, portdedjibouti[.]live, pncert[.]info) to host lures and staging/C2. |
| Stage Capabilities: Upload Tool | [T1608.002](https://attack.mitre.org/techniques/T1608/002/) | SideWinder stages next-stage payloads (HTA/JavaScript, .NET modules) on attacker-controlled servers and uses server-side polymorphism plus geofencing so the staging server only serves the malicious payload to requests originating from targeted countries/victims, returning benign content otherwise. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Primary initial-access vector: spear-phishing emails carrying weaponized Microsoft Office documents (DOCX/RTF) or ZIP archives, with lures impersonating government bodies, port authorities (e.g. Port of Alexandria) and nuclear-energy agencies relevant to the target's region and sector. |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | SideWinder also delivers ZIP archives containing Windows LNK shortcut files, or links that fetch a malicious HTA hosted on an attacker-controlled website; opening the LNK invokes mshta.exe against the remote JavaScript payload. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Infection requires the victim to open the malicious Office document, triggering remote template injection and the CVE-2017-11882 exploit. |
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | In the LNK/link delivery variant the victim must click a link or launch the shortcut file, which runs mshta.exe against the attacker-hosted JavaScript. |
| Exploitation for Client Execution | [T1203](https://attack.mitre.org/techniques/T1203/) | Weaponized documents exploit CVE-2017-11882 in the Microsoft Office Equation Editor (EQNEDT32.EXE) to execute embedded shellcode, which launches mshta.exe to retrieve the next stage from a remote server. |
| System Binary Proxy Execution: Mshta | [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Both the exploit and LNK chains invoke the signed Windows LOLBIN mshta.exe to download and execute a remote HTA/JavaScript payload (via mshtml.RunHTMLApplication), proxying execution through a trusted binary. |
| Command and Scripting Interpreter: JavaScript | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | A heavily obfuscated JavaScript file executed via mshta enumerates installed .NET Framework versions, sets the COMPLUS_Version environment variable, decodes a Base64 .NET serialized Downloader Module (ModuleInstaller) and loads it directly into memory. |
| Inter-Process Communication: Dynamic Data Exchange | [T1559.002](https://attack.mitre.org/techniques/T1559/002/) | SideWinder has historically abused Microsoft Office Dynamic Data Exchange (DDE) in weaponized documents to execute code on victim hosts. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | The ModuleInstaller downloader establishes persistence for the Backdoor Loader on the host so StealerBot survives reboots; persistence mechanisms (registry Run key vs. other autostart) are rotated when behavioral detections occur. |
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | As an alternate persistence mechanism the loader chain can register a scheduled task to relaunch the malicious loader; SideWinder switches between autostart persistence methods to evade behavioral detection. |

## Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Abuse Elevation Control Mechanism: Bypass User Account Control | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | StealerBot includes functionality to escalate privileges by bypassing Windows User Account Control (UAC). |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Reflective Code Loading | [T1620](https://attack.mitre.org/techniques/T1620/) | The Base64-decoded .NET Downloader Module (ModuleInstaller) and subsequent StealerBot components are loaded and executed directly in memory rather than written to disk as PE files, reducing on-disk artifacts. |
| Hijack Execution Flow: DLL | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | The chain uses DLL side-loading: a legitimate signed application loads a malicious 'Backdoor Loader' DLL (observed variants named propsys.dll, vsstrace.dll, JetCfg.dll, policymanager.dll, winmm.dll, xmllite.dll, dcntel.dll, UxTheme.dll) that decrypts and loads StealerBot in memory. Loader file names and host applications are rotated when detected. |
| Modify Registry | [T1112](https://attack.mitre.org/techniques/T1112/) | ModuleInstaller/StealerBot write configuration and persistence data to the registry and modify registry values as part of installation and to store loader configuration. |
| Virtualization/Sandbox Evasion: System Checks | [T1497.001](https://attack.mitre.org/techniques/T1497/001/) | The Downloader Module performs anti-sandbox/anti-analysis system checks, including verifying installed RAM is greater than ~950 MB and detecting whether nlssorting.dll is loaded, to avoid executing in analysis environments. |
| Virtualization/Sandbox Evasion: Time Based Evasion | [T1497.003](https://attack.mitre.org/techniques/T1497/003/) | SideWinder combines geofenced/server-side delivery with environmental checks so payloads only detonate on genuine in-region victims and withhold from sandboxes and out-of-scope requests. |
| Obfuscated Files or Information: Command Obfuscation | [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | The JavaScript stage is heavily obfuscated and the .NET modules use control-flow flattening to hinder static and dynamic analysis. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Payloads are Base64-encoded and encrypted at multiple stages (serialized .NET Downloader Module, the StealerBot implant decrypted by the Backdoor Loader) to evade static detection and store components on disk in encrypted form. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | Each stage decodes/decrypts the next: JavaScript Base64-decodes the serialized .NET module, and the Backdoor Loader decrypts the StealerBot implant before loading it into memory. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Side-loaded malicious DLLs adopt the names of legitimate system libraries (propsys.dll, winmm.dll, xmllite.dll, UxTheme.dll, etc.) and staging/C2 domains impersonate real ministries and port authorities to blend malicious activity with legitimate resources. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | A StealerBot module steals saved passwords from web browsers on the compromised host. |
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | StealerBot includes functionality to steal Windows account credentials (including intercepting RDP credentials and harvesting Windows/system credential material) from the compromised host. |
| Input Capture: GUI Input Capture | [T1056.002](https://attack.mitre.org/techniques/T1056/002/) | StealerBot includes a phishing/credential-capture module that presents a fake Windows credential prompt to trick the victim into entering their password. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | The Downloader Module uses WMI queries to enumerate installed antivirus/security products (reading AV productState values) and checks running processes against a list of ~137 security-tool process names, then adapts its execution/persistence path accordingly. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | The loader enumerates running processes (comparing against its ~137-entry security-tool list) to fingerprint the defensive environment before deploying the backdoor. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | The Downloader Module and StealerBot collect host system information (OS/.NET Framework versions, RAM size, loaded modules) to guide staging and evasion. |
| System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | StealerBot gathers network configuration information from compromised hosts as part of its host-reconnaissance modules. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | SideWinder tooling identifies the current user/owner of the compromised host to support targeting and credential-theft decisions. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | StealerBot enumerates files and directories on the compromised host to locate documents and data of espionage interest prior to exfiltration. |
| System Time Discovery | [T1124](https://attack.mitre.org/techniques/T1124/) | SideWinder tooling queries system time as part of environment fingerprinting. |
| Software Discovery | [T1518](https://attack.mitre.org/techniques/T1518/) | Beyond security products, the loader enumerates installed .NET Framework versions and other software to select compatible execution paths. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | StealerBot includes a module that captures screenshots of the victim's desktop for espionage. |
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | StealerBot logs keystrokes on the compromised host to capture credentials and sensitive input. |
| Automated Collection | [T1119](https://attack.mitre.org/techniques/T1119/) | StealerBot's file-stealer module automatically collects files of interest from the host (and connected media) for exfiltration. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | StealerBot steals documents and sensitive files from the local system for espionage purposes. |
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Collected files, screenshots and keylog data are staged locally by StealerBot before exfiltration to C2. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | StealerBot and the loader chain communicate with attacker-controlled C2 servers over HTTP/HTTPS to retrieve modules/commands and exfiltrate data, using look-alike domains (e.g. portdedjibouti[.]live, mofa-gov-sa.direct888[.]net, depo-govpk[.]com). |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | The multi-stage chain repeatedly retrieves next-stage components from remote servers — mshta fetches the HTA/JavaScript, ModuleInstaller downloads the Backdoor Loader and StealerBot modules, and StealerBot can pull additional payloads via a C++ downloader. |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | StealerBot encrypts its C2 communications, obscuring commands and exfiltrated data on the wire. |
| Remote Access Software | [T1219](https://attack.mitre.org/techniques/T1219/) | StealerBot provides an interactive reverse-shell module giving operators hands-on-keyboard remote control of the compromised host. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Collected files, keystrokes, screenshots and credentials are exfiltrated to SideWinder C2 servers over the implant's encrypted command-and-control channel. |
| Automated Exfiltration | [T1020](https://attack.mitre.org/techniques/T1020/) | StealerBot automatically exfiltrates the data collected by its modules to C2 without per-file operator interaction. |
