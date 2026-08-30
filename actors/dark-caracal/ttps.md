# Dark Caracal — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **41** across **9** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Actors register C2 and staging domains through Porkbun and NameSilo, using disposable/low-cost TLDs (.top, .live, .club, .icu, .monster, .info). Both the original Dark Caracal and the 2020 Bandook resurgence share these registration services. |
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Actors maintain and evolve the Bandook RAT across builds — a full ~120-command version (March 2019), a signed full variant, and a slimmed 11-command signed version — and operate the Pallas Android implant and CrossRAT Java implant. |
| Obtain Capabilities: Code Signing Certificates | [T1588.003](https://attack.mitre.org/techniques/T1588/003/) | Actors obtained Certum (Polish CA) code-signing certificates to digitally sign Bandook executables across the 2019-2020 campaign, defeating reputation and signature-based trust checks. |
| Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | Actors stage the second-stage payload ZIP (containing a.png/b.png RC4 payload, the Invoke-PSImage untitled.png, and decoy draft.docx) on legitimate cloud services — Dropbox, Bitbucket and Amazon S3 — for retrieval by the PowerShell loader. |
| Stage Capabilities: Drive-by Target | [T1608.004](https://attack.mitre.org/techniques/T1608/004/) | In the 2018 operation the actors stood up a fake secure-messaging watering-hole site to distribute trojanized Android apps (Pallas) impersonating WhatsApp/Signal/Telegram/Primo and related utilities. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Actors deliver a ZIP archive containing a trojanized Microsoft Word document; lure themes include Office365/OneDrive/Azure notifications, government certificates (Dubai JAFZA) and shipment notifications. |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | The trojanized document's external-template feature reaches out through TinyURL/Bitly shortened links that redirect to the actor's macro/payload hosting. |
| Phishing: Spearphishing via Service | [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | In the 2018 campaign actors conducted social-engineering delivery through third-party services — Facebook groups/pages and WhatsApp messages — luring targets to install trojanized apps or open malicious content. |
| Drive-by Compromise | [T1189](https://attack.mitre.org/techniques/T1189/) | Actors operated a watering-hole / fake secure-messaging site to distribute trojanized Android applications (Pallas) to targets who browsed to it. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Actors rely on the victim opening a malicious file — trojanized Word documents and payloads disguised as Adobe Flash Player, Microsoft Office, or PDF files — to trigger the infection chain. |
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Targets are induced to click links (including from the fake secure-messaging site and social-engineering messages) to download and install trojanized Pallas Android apps. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Remotely fetched VBA macros execute inside Word to decrypt the embedded shape-object script and launch the next stage (dropping the PowerShell loader). |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | The macro drops and runs a PowerShell loader: fmx.ps1 plus sdmc.jpg (a base64-encoded PowerShell blob). The loader downloads the payload ZIP from cloud hosting, RC4-decrypts a.png/b.png into an executable, and extracts a hidden RC4 routine from a valid image (untitled.png, produced with Invoke-PSImage). |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Actors leverage Word document macros/command-shell invocations to download and execute secondary malware stages. |
| Command and Scripting Interpreter: Python | [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | The full ~120-command Bandook build supports execution of Python payloads (e.g., a bundled dpx.pyc) as well as Java payloads. |
| Native API | [T1106](https://attack.mitre.org/techniques/T1106/) | Bandook's Delphi loader and RAT use native Windows API calls to reconstruct, inject and execute payloads (including the process-hollowing sequence). |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Bandook establishes persistence by adding a Run key under HKEY_USERS\...\Software\Microsoft\Windows\CurrentVersion\Run; CrossRAT similarly persists on Windows via a registry Run key. |
| Create or Modify System Process: Launch Agent | [T1543.001](https://attack.mitre.org/techniques/T1543/001/) | On macOS, CrossRAT installs a Launch Agent (property list under ~/Library/LaunchAgents) to auto-start the Java implant at login. |
| Boot or Logon Autostart Execution: XDG Autostart Entries | [T1547.013](https://attack.mitre.org/techniques/T1547/013/) | On Linux, CrossRAT persists via an XDG autostart entry (~/.config/autostart) that relaunches the Java implant on desktop login. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Template Injection | [T1221](https://attack.mitre.org/techniques/T1221/) | The lure Word document abuses the Office 'external template' feature to fetch remote VBA macros at open time (via TinyURL/Bitly), keeping the delivered document itself macro-free at rest. An encrypted script is embedded in a document Shape object (o4QQLW7zXjLbj = ActiveDocument.Shapes(1).TextFrame.TextRange.Text). |
| System Binary Proxy Execution: Compiled HTML File | [T1218.001](https://attack.mitre.org/techniques/T1218/001/) | Actors have abused compiled HTML (.chm) files containing embedded commands to download and execute payloads via the trusted hh.exe/CHM handler. |
| Process Injection: Process Hollowing | [T1055.012](https://attack.mitre.org/techniques/T1055/012/) | The Delphi loader reconstructs Bandook in memory and uses process hollowing to inject and run it inside a legitimate Internet Explorer (iexplore.exe) process, masking the RAT under a trusted image. |
| Obfuscated Files or Information: Software Packing | [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | Actors pack the Bandook payload with UPX to hinder static analysis and signature detection. |
| Obfuscated Files or Information: Steganography | [T1027.003](https://attack.mitre.org/techniques/T1027/003/) | The loader hides an RC4-decryption routine and payload data inside a valid PNG image (untitled.png) using the Invoke-PSImage technique, embedding bytes in the RGB pixel values; the executable payload is split across a.png and b.png and concatenated. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Bandook stores base64-encoded and encrypted strings/config internally, and the loader chain uses base64 (sdmc.jpg) and RC4-encrypted payload files (a.png/b.png) to keep components opaque at rest. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | The PowerShell loader base64-decodes sdmc.jpg and RC4-decrypts a.png/b.png at runtime to reconstruct the executable payload before injection. |
| Subvert Trust Controls: Code Signing | [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | Bandook samples in the 2019-2020 campaign are digitally signed with Certum-issued code-signing certificates so they appear trusted and bypass reputation/signature checks. |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | After execution the loader deletes the downloaded ZIP and its extracted components from the Public folder, and displays a benign decoy document (draft.docx) to reduce suspicion. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | Bandook enumerates drives and produces file listings from default Windows directories to locate data of interest for exfiltration (commands @0004 list drives, @0005 list files). |
| System Network Configuration Discovery: Internet Connection Discovery | [T1016.001](https://attack.mitre.org/techniques/T1016/001/) | Bandook retrieves the victim's public IP address (command @0011) to profile the host's internet connectivity/geolocation. |
| Peripheral Device Discovery | [T1120](https://attack.mitre.org/techniques/T1120/) | Bandook enumerates connected drives/devices (command @0004 list drives) to map available storage and removable media on the host. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | On Windows, Bandook/Dark Caracal extracted the complete contents of the Pictures folder and other local files. On Android, Pallas harvested locally stored PII — SMS messages, call logs, contacts and stored photos — from compromised devices. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | Bandook captures desktop screenshots on demand (command @0003); CrossRAT also supports screen capture across platforms. |
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | The full Bandook build logs keystrokes to capture credentials and message content from the victim. |
| Audio Capture | [T1123](https://attack.mitre.org/techniques/T1123/) | Bandook records microphone audio on Windows; Pallas records ambient audio from compromised Android devices for surveillance. |
| Video Capture | [T1125](https://attack.mitre.org/techniques/T1125/) | Bandook captures webcam video/images on Windows; Pallas can capture from the device camera on Android. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Bandook communicates with its C2 over a TCP port using HTTP-style payloads that are Base64-encoded and suffixed with the marker string '&&&&'. Pallas/mobile implants control via standard HTTP. |
| Non-Application Layer Protocol | [T1095](https://attack.mitre.org/techniques/T1095/) | Bandook supports raw TCP-socket C2 (command @0002 download/execute via TCP socket), using direct socket communication in addition to HTTP-style payloads. |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | Bandook encrypts C2 traffic and payloads with AES in CFB mode using a hardcoded IV (0123456789123456), a fingerprint shared across the Dark Caracal / Operation Manul lineage. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | The PowerShell loader downloads the second-stage ZIP from Dropbox/Bitbucket/S3, and Bandook itself downloads and executes additional payloads over HTTP (command @0001) and TCP (command @0002). |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Bandook uploads collected files, screenshots, keystrokes and media back to its C2 over the same encrypted HTTP/TCP channel (command @0006 file upload). |
