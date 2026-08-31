# Madi — ATT&CK Technique Mapping

> Attribution: Iran-nexus — low-medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **14** across **7** tactics.

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Carefully selected targets received targeted emails carrying weaponized attachments — most notably PowerPoint slideshow (.pps) files such as 'Magic_Machine1123.pps' and 'Moses_pic1.pps', and executables disguised as documents/images. Delivery relied entirely on social engineering rather than software exploits. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Execution depended on the victim opening the lure. PowerPoint 'Activated Content' effects in the .pps files automatically ran an embedded trojan downloader when the slideshow was viewed; RTLO-disguised .scr executables ran when double-clicked. Distracting imagery (religious pictures, mathematical puzzles, missile-test and nuclear-explosion videos) was displayed to reassure the user nothing malicious had happened. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Masquerading: Right-to-Left Override | [T1036.002](https://attack.mitre.org/techniques/T1036/002/) | Attackers abused the Unicode Right-to-Left-Override (U+202E) character in filenames so that a screensaver executable such as one ending '.scr' rendered to the victim as an image file (e.g. displayed as 'picturcs..jpg' with an image icon), tricking users into launching the payload. |
| Obfuscated Files or Information: Software Packing | [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | The Madi binaries were packed with the legitimate UPX 3.07 packer to alter file signatures and hinder static/signature-based detection. |
| Masquerading: Match Legitimate Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | The dropped infostealer executed under the name iexplore.exe to blend in with the legitimate Internet Explorer process, running from user-profile directories such as 'c:\Documents and Settings\%USER%\Templates' (droppers were staged in '...\Printhood'). |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | The backdoor enumerated the victim's disk structure and searched for approximately 27 different data file types (documents, contracts, images, etc.) to identify material of interest for theft. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | The Delphi backdoor logged victim keystrokes as one of its nine core operational functions and forwarded the captured keystroke data to the C2 for retrieval. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | The backdoor captured screenshots both on a timed interval and event-triggered — specifically when the victim interacted with webmail, instant-messaging or social-media services (Gmail, Hotmail, Yahoo Mail, ICQ, Skype, Google+, Facebook) — to record sensitive communications. |
| Audio Capture | [T1123](https://attack.mitre.org/techniques/T1123/) | The backdoor recorded audio from the victim's microphone, writing recordings to disk as WAV files for later exfiltration to the C2. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | The infostealer collected sensitive files from the local system — stolen documents and contracts alongside keylogged data and screenshots — staging them for upload to the C2 servers, which doubled as stolen-data drops. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Infected systems communicated with the C2 over HTTP to a small set of web servers running Microsoft IIS 7.0 hosting a custom C# server-manager. The backdoor uploaded screenshots, keylog data and stolen files and received instructions and updated modules over this channel. |
| Non-Application Layer Protocol | [T1095](https://attack.mitre.org/techniques/T1095/) | Beyond HTTP, infected hosts performed ICMP ping checks against the C2 servers as a connectivity/availability check. Later Madi downloaders hard-coded C2 IP addresses directly, avoiding DNS name resolution. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | The downloader retrieved and installed additional data-stealing modules from the C2 and supported self-update and backdoor-update functionality, letting operators push new payloads and new C2 locators. The updated locator was written to a plain-text file on disk (config artifacts observed: FIE.dll, xdat.dll, SIK.dll). |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Stolen data — screenshots, keylogged input, documents and contracts, WAV audio — was uploaded over the same HTTP C2 channel to the IIS 7.0 servers, which acted as stolen-data drops for the operators. |
