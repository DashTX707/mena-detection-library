# Arid Viper — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **40** across **11** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | Arid Viper creates and operates fake social-media personas (often attractive-persona / romance profiles) to build rapport with targets before delivering weaponized apps or links; the tradecraft underpins its romance and social-engineering lures. |
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Actors register persona-style hyphenated domains (e.g. luis-dubuque[.]in, conner-margie[.]com, grace-fraser[.]site) that they solely operate and control as C2 servers for both Android and Windows implants; the naming convention (first-last name across varied TLDs) is a recognizable actor signature. |
| Acquire Infrastructure: Web Services | [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | Actors stand up Google Firebase projects (e.g. skippedtestinapp.firebaseio.com, jolia-16e7b.appspot.com) to use Firebase Cloud Messaging as a resilient, low-signal C2 channel for Android spyware, blending with legitimate Google traffic. |
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Arid Viper maintains a large in-house malware development program, iterating custom implant families across languages — Micropsia (Delphi), PyMicropsia (Python), Arid Gopher (Go), BarbWire (C++), Rusty Viper (Rust) on Windows, and SpyC23/VAMP/FrozenCell/GnatSpy on Android. |
| Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | Actors host weaponized APKs and fake-update payloads on their own domains for download (e.g. hxxps://orin-weimann[.]com/abc/Update%20Services.apk, hxxps://jack-keys[.]site/download/okOqphD, hxxps://orin-weimann[.]com/abc/signal.apk), managing the infrastructure with ALFA TEaM webshells. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing via Service | [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | Actors socially engineer targets over messaging and social-media services using fake personas and romance lures, steering victims to install trojanized chat/dating apps (Telegram clones, Skipped Messenger) that carry SpyC23. |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Actors distribute links masquerading as legitimate app updates (WhatsApp, Messenger, Instagram, Google Play, Signal) — including via Arabic-language YouTube tutorial videos with Levantine-dialect narration — that lead to malicious APK downloads. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Victims are induced to click attacker-hosted download links (persona domains) believing they are legitimate app updates or messaging apps, initiating retrieval of the malicious payload. |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | On Windows, Micropsia/Arid Gopher executables are delivered masquerading as Word/PDF documents (Office icons, extremely long filenames hiding the .exe, benign decoy documents shown on launch); the victim double-clicks the file, executing the implant. |
| Command and Scripting Interpreter: Python | [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | PyMicropsia is written in Python and packaged with PyInstaller; it executes modular Python payloads (keylogger, screenshotter, credential stealer) and runs subprocesses with base64-encoded parameters. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Micropsia executes remote operator commands on the host via the Windows command shell as part of its RAT command set. |
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) | Implants use WMI to query installed antivirus products (Arid Gopher) and to enumerate USB devices (PyMicropsia). |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Boot or Logon Autostart Execution: Shortcut Modification | [T1547.009](https://attack.mitre.org/techniques/T1547/009/) | Arid Gopher creates a LNK shortcut in the Windows Startup folder (V1 named after the executable, V2 named NetworkBoosterUtilities.lnk) for execution at every logon; PyMicropsia deploys a .lnk into the Start Menu Programs\Startup folder via a dedicated payload SynLocSynMomentum.exe. |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Earlier Micropsia/PyMicropsia variants establish persistence through Registry Run keys under HKCU and startup-folder execution to survive reboot. |
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Actors administer their C2 infrastructure using ALFA TEaM webshells deployed on attacker-controlled servers. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Masquerading: Double File Extension | [T1036.007](https://attack.mitre.org/techniques/T1036/007/) | Arid Gopher uses extremely long filenames to push and hide the real .exe extension out of the visible filename, making the payload appear to be a document. |
| Masquerading: Masquerade File Type | [T1036.008](https://attack.mitre.org/techniques/T1036/008/) | Windows implants are given Microsoft Word/PDF icons and display benign decoy Word/PDF documents on execution so the running executable presents as a harmless document. |
| Virtualization/Sandbox Evasion: System Checks | [T1497.001](https://attack.mitre.org/techniques/T1497/001/) | SpyC23 employs anti-virtualization/anti-emulation checks — apps malfunction on emulated devices to frustrate dynamic analysis. |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | APKs and native libraries (libuoil.so, libdalia.so, lib-uoil.so) are heavily obfuscated with Base64-plus-substitution string encoding; Windows implants are packed/obfuscated (PyInstaller) to hinder static analysis. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | At runtime the implants decode Base64/substitution-encoded C2 server details embedded in native libraries (e.g. lib-uoil.so) and decode encoded strings/parameters before use. |

## Impair Defenses

| Technique | ID | Notes |
|---|---|---|
| Disable or Modify Tools | [T1685](https://attack.mitre.org/techniques/T1685/) | Android SpyC23 disables security notifications on Samsung, Huawei, Google, Oppo and Xiaomi devices to suppress warnings about its activity and permissions. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | PyMicropsia steals saved Chrome credentials via a dedicated 'Rapunzel' C2 command, enumerating browser profile paths on both Windows and POSIX systems; Android spyware harvests Facebook credentials. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Peripheral Device Discovery | [T1120](https://attack.mitre.org/techniques/T1120/) | PyMicropsia issues WMI queries to enumerate USB drives and detect newly inserted removable media for targeting. |
| Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | Arid Gopher queries installed antivirus products via WMI and adapts behavior — V2 deploys an 'Arid Helper' component if 360 Total Security is detected. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | Arid Gopher collects the OS version via RtlGetVersion(); Micropsia profiles the host as part of initial check-in. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | Implants build a unique victim identifier by combining the computer name, username and a random string for C2 registration/tracking. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | Implants enumerate files and directories to locate target documents by extension across the local system and removable media. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | Micropsia/PyMicropsia keylog via the GetAsyncKeyState API; PyMicropsia ships a dedicated keylogger payload (MetroIntelGenericUIFram.exe) writing timestamped logs to an HPFusionManagerDell directory. Android SpyC23 captures input/screen content via accessibility services. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | PyMicropsia captures screenshots with the Python 'mss' library; Arid Gopher uses the kbinani screenshot library and saves PNGs; Android SpyC23 monitors screen content through accessibility services. Screenshots are taken periodically and on C2 command. |
| Audio Capture | [T1123](https://attack.mitre.org/techniques/T1123/) | Arid Viper's arsenal records microphone audio; Android SpyC23 records calls via a CallRecService (using the libcallrecfix.so native library) and ambient audio through a checkRaw service. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Implants harvest documents of interest by extension (.doc, .docx, .xls, .xlsx, .pdf, .ppt, .pptx, .csv, .txt, .rtf, .odt, .mdb, .accdb) from the local system for exfiltration. |
| Automated Collection | [T1119](https://attack.mitre.org/techniques/T1119/) | Micropsia/PyMicropsia automatically and periodically collect screenshots, keystrokes and office documents without per-item operator interaction, driven by the implant's scheduled routines. |
| Data from Removable Media | [T1025](https://attack.mitre.org/techniques/T1025/) | PyMicropsia detects inserted USB/flash drives, lists their contents and exfiltrates files from removable media. |
| Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Micropsia/PyMicropsia compress collected Office documents into password-protected RAR archives using rar.exe prior to exfiltration. |
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Collected keystrokes, screenshots and documents are written to fixed working directories (e.g. HPFusionManagerDell) before being archived and exfiltrated. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | PyMicropsia communicates over HTTP POST with semicolon-delimited parameters to URI paths such as /zoailloaze/sfuxmiibif/[endpoint]; Micropsia and Arid Gopher (Laravel backend) use HTTP(S) web C2 to attacker persona domains. |
| Web Service | [T1102](https://attack.mitre.org/techniques/T1102/) | Android SpyC23 uses Google Firebase Cloud Messaging as its primary C2 channel (e.g. skippedtestinapp.firebaseio.com), with attacker-registered domains as secondary C2, and can receive updated C2 domains from the current C2 to switch infrastructure. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Implants download and execute additional payloads/modules from C2 on command (PyMicropsia URL-based download-and-execute; Arid Gopher 'd' download/execute and 'ra' process-execute commands). |
| Data Encoding: Standard Encoding | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | Implants encode C2 parameters and payload strings with Base64 (Android native libraries add string substitution — spaces/underscores replaced with hyphens; PyMicropsia passes base64-encoded subprocess parameters). |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Collected data (RAR archives, screenshots, keystroke logs, browser credentials, audio, SMS, contacts) is exfiltrated back over the same HTTP(S)/Firebase C2 channel to attacker infrastructure. |
