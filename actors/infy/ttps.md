# Infy — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **37** across **10** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Digital Certificates | [T1587.003](https://attack.mitre.org/techniques/T1587/003/) | The operator provisions attacker-controlled / self-signed TLS certificates and RSA key material to authenticate HTTP(S) C2 domains, part of building resilient, takedown-resistant infrastructure. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Primary initial-access vector across all generations: spear-phishing emails carrying a weaponized Word or PowerPoint attachment, or a self-executable archive attachment, tailored to Iranian dissidents, expatriates and diplomatic targets. Tonnerre lures used politically themed Word documents (e.g., a photo of Dorud city governor Mojtaba Biranvand and ISAAR-themed content). |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Execution relies on the victim opening the malicious document or double-clicking the self-extracting executable. Infy SFX archives present a fake video-player interface with a decoy readme.txt/image/video to social-engineer the user into clicking 'Run'; filenames follow ins*.exe and mpro*.dll patterns. |
| Office Template Macros | [T1137.001](https://attack.mitre.org/techniques/T1137/001/) | Tonnerre delivery uses macro-enabled Word documents: when the victim closes the document, a VBA macro extracts the embedded package to the temp directory as fwupdate.temp and executes it. |
| Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | The document weaponization uses VBA macro code to drop and launch the next-stage package (e.g., Tonnerre's fwupdate.temp), performing file writes and process execution from within Office. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Across generations the malware persists via autostart registry keys: Infy writes itself to the autorun registry key and activates after reboot; the Foudre loader writes itself to autostart in the Run key; Tonnerre also establishes a Registry Run key. |
| Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Tonnerre establishes persistence via a scheduled task that launches helper.exe on a recurring basis, complementing its Registry Run-key persistence. |
| Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | The Infy 'M' variant installs itself as a Windows service to persist across reboots on higher-value targets. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Rundll32 | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Foudre executes its malicious DLL via rundll32.exe after the system reboots, using a signed system utility to load the payload and blend with normal activity. |
| DLL | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | Infy deployed its backdoor as a hijacked 'CLMediaLibrary' Dynamic Link Library, and Foudre drops a malicious DLL loaded alongside a legitimate-looking loader — abusing DLL loading/hijack to execute the implant. |
| Right-to-Left Override | [T1036.002](https://attack.mitre.org/techniques/T1036/002/) | Infy has used deceptive filename and camouflage techniques (fake readme.txt, image/video decoys, misleading extensions) to disguise executable droppers as benign media/document files so victims run them. |
| System Checks | [T1497.001](https://attack.mitre.org/techniques/T1497/001/) | Infy uses window-name checks as an anti-analysis / prior-infection guard: it searches for a specific window (keylogger window 'TRON2VDLLB'; Foudre searches for a window named 'foudre<version>' with class 'TNRRDPKE') to detect an existing infection or analysis condition before proceeding. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | Foudre de-obfuscates its strings at runtime using an XOR-based decryption algorithm; Infy uses consistent string-encoding/decryption keys across the decade-long campaign and ZIP password obfuscation. |
| Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Infy ships payloads inside multi-layer SFX archives encrypted with the key '1qaz2wsx3edc', and compresses captured documents into password-protected archives (password 'Z8(2000_2001uI)') — encrypting/encoding stored files to evade static detection. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | Infy steals saved passwords and form data from browsers including Microsoft Edge, Internet Explorer, Chrome, Opera and Firefox. |
| Steal Web Session Cookie | [T1539](https://attack.mitre.org/techniques/T1539/) | Infy harvests browser cookies (along with history and form data) from Edge, IE, Chrome, Opera and Firefox; Tonnerre also collects cookies during system-information harvesting. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Application Window Discovery | [T1010](https://attack.mitre.org/techniques/T1010/) | The malware enumerates application windows by name/class (e.g., 'TRON2VDLLB', 'foudre<version>' / class 'TNRRDPKE') to detect prior infection and to support keylogging context. |
| Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | Infy checks for the presence of antivirus before installing: it uses GetFileAttributesA against AV installation directories and specifically checks for Kaspersky Labs, Avast and Trend Micro, and will avoid installation rather than risk alerting if AV is detected. Tonnerre also enumerates installed antivirus software. |
| Peripheral Device Discovery | [T1120](https://attack.mitre.org/techniques/T1120/) | Tonnerre steals files from external/removable devices, enumerating attached peripherals to locate data of interest; Infy also enumerates drives during system reconnaissance. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | The implants profile the host, collecting computer name, username, OS version, CPU ID, machine GUID, drive enumeration and disk info; this system profile is posted to C2 to identify high-value machines. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | Infy and Tonnerre enumerate running processes as part of reconnaissance (and to identify security products). |
| System Language Discovery | [T1614.001](https://attack.mitre.org/techniques/T1614/001/) | Infy's keylogger performs language identification of captured keystroke data (and the operation collects locale/timezone context), consistent with targeting of Persian-language dissident and diaspora communities. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | All generations keylog: Infy initiates a keylogger operating under window name 'TRON2VDLLB' and captures keystrokes with language identification; Foudre keylogs on a cycle with periodic clipboard capture; Tonnerre keylogs on victim machines of interest. |
| Clipboard Data | [T1115](https://attack.mitre.org/techniques/T1115/) | Infy harvests clipboard contents; Foudre captures the clipboard on a periodic (~10-second) cycle alongside keylogging. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | The Infy M variant and Tonnerre capture screenshots of the victim desktop for surveillance of dissidents and diplomatic targets. |
| Audio Capture | [T1123](https://attack.mitre.org/techniques/T1123/) | Infy M includes microphone/voice-recording capability (present in earlier versions, later selectively removed), and Tonnerre records sound from the victim machine for espionage. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Infy selectively harvests documents by extension (.doc/.docx/.xls/.xlsx/.ppt/.pptx/.pdf/.zip/.rar/.7z, etc.) and monitors target folders (Documents, Program Files, Users, Windows, boot, inetpub). Tonnerre steals files from predefined folders on the local system. |
| Automated Collection | [T1119](https://attack.mitre.org/techniques/T1119/) | The implants automatically and continuously collect keystrokes, clipboard, screenshots, browser data and documents-by-extension from monitored folders without per-item operator interaction. |
| Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Captured documents and collected data are compressed locally into password-protected archives (Infy document-capture password 'Z8(2000_2001uI)') prior to exfiltration, staging data on the host. |
| Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Infy compresses captured documents into password-protected ZIP archives (password 'Z8(2000_2001uI)') and uses ZIP password obfuscation as part of data collection before exfiltration. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | The implants beacon over HTTP(S): Infy checks in to its HTTP C2 on ~5-minute intervals and posts system information; Foudre uses HTTP POST for exfiltration and an HTTP 200 response from google.com as an internet-connectivity check; Tonnerre verifies its HTTP C2 by downloading a signature file and exfiltrates built-in collections over HTTP POST. |
| Domain Generation Algorithms | [T1568.002](https://attack.mitre.org/techniques/T1568/002/) | Foudre resolves C2 via a DGA computing a CRC32 hash of 'NRV1' + date components (producing .space/.site/.top domains); Tonnerre uses a DGA of the form 'NITV1{year}{month}{week}' across .site/.com/.win TLDs. Both use RSA signature verification so only attacker-authenticated domains are trusted, defeating naive sinkholing. |
| Asymmetric Cryptography | [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | Foudre and Tonnerre authenticate C2 using RSA signature verification of a downloaded signature file / domain, ensuring the client only trusts operator-controlled infrastructure; HTTPS C2 uses attacker-controlled/self-signed TLS certificates. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Foudre functions as a downloader/profiler that retrieves and installs the higher-value Tonnerre second-stage implant onto machines of interest, and the implants pull additional payloads/updates from C2. |
| Standard Encoding | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | C2 traffic and stored strings use consistent encoding/obfuscation (XOR string obfuscation, ZIP password/encoding) to obscure command and data content in transit and at rest. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | The implants exfiltrate collected data (system profile, keylogs, documents, screenshots) back over their HTTP(S) C2 channel via HTTP POST — Infy posts to C2 servers, Foudre and Tonnerre exfiltrate built-in collections over HTTP POST. |
| Exfiltration Over Unencrypted Non-C2 Protocol | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Tonnerre uses a second, command-directed exfiltration channel: operator-selected file uploads are sent over FTP to dedicated FTP servers, separate from the HTTP C2 channel. |
