# Group5 — ATT&CK Technique Mapping

> Attribution: Iran-nexus — low confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **15** across **6** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Group5 registered the domain assadcrimes.info (June 2015) to stage its watering-hole/malware site, falsely registering it under the stolen identity of Syrian opposition figure Noura Al-Ameer. The domain was hosted on the Iran-based provider Hostnegar (hostnegar.com) on shared hosting IP 212.7.195.171. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Group5 relied entirely on off-the-shelf/commodity capabilities rather than bespoke malware: the njRAT and NanoCore Windows RATs, the DroidJack Android RAT (SandroRAT lineage), and the Iranian-authored 'PAC Crypt' crypter (developer alias 'mr.tekide') used to pack the payloads for AV evasion. |
| Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | Group5 staged multiple malware variants on its actor-controlled watering-hole site assadcrimes.info, including malicious PPSX documents and Windows/Android droppers reachable via a fake Adobe Flash Player update download page, making payloads available for victim delivery. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Group5 delivered malicious PowerPoint slideshow (PPSX) attachments to Syrian opposition targets via email — the campaign opened with a 2015-10-03 spearphishing email to Noura Al-Ameer. The PPSX files embedded OLE Package objects triggered on animation to drop and execute the RAT payloads, themed around Syrian conflict / Assad war-crimes content. |
| Drive-by Compromise | [T1189](https://attack.mitre.org/techniques/T1189/) | Group5 operated assadcrimes.info as a watering hole seeded with scraped Syrian opposition and human-rights content to draw in targets, presenting a fake Adobe Flash Player update notification page whose HTML triggered download of decoy droppers carrying the RAT payloads. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Exploitation for Client Execution | [T1203](https://attack.mitre.org/techniques/T1203/) | Group5's PPSX documents exploited CVE-2014-4114 (the 'Sandworm'/OLE Package Manager vulnerability in Microsoft Office/PowerPoint) to silently drop and execute embedded malicious code when the slideshow was opened. |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Group5 relied on targets opening decoy-themed dropper files delivered from the watering hole or by email — e.g. 'alshohadaa alatfal.exe' (a decoy referencing child martyrs) and a first-stage .NET downloader masquerading as putty.exe — to gain execution of the njRAT/NanoCore payloads. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Group5 named its payloads after legitimate software to blend in: the first-stage downloader was delivered as putty.exe (impersonating the PuTTY SSH client) and the NanoCore RAT was dropped as dwm.exe (impersonating the Windows Desktop Window Manager). Decoy documents also used Syrian-opposition-plausible filenames. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Group5 obfuscated its RAT payloads with the 'PAC Crypt' crypter, which Base64-encoded the PE file, embedded it in the resource section, applied AES encryption, and wrapped it in a .NET packer stub to evade static AV detection. The crypter was compiled in debug mode, leaving PDB strings ('paccryptnano core dehgani-vds', 'paccrypt11njratmalii') exposing the 'mr.tekide' developer alias. |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Group5's RATs provided remote file-deletion capability, allowing operators to remove files (including their own artifacts) from infected systems. Listed by MITRE ATT&CK as a Group5 technique. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | Group5's njRAT and NanoCore RATs provided keystroke-logging and password-capture capability against infected Syrian opposition targets. Listed by MITRE ATT&CK as a Group5 technique. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | Group5's njRAT and NanoCore RATs allowed operators to watch the victim's screen / capture screenshots as part of surveillance of Syrian opposition figures. Listed by MITRE ATT&CK as a Group5 technique. |
| Audio Capture | [T1123](https://attack.mitre.org/techniques/T1123/) | Group5's RATs (njRAT/NanoCore on Windows, DroidJack on Android) supported microphone activation to record audio and listen in on targets' surroundings. |
| Video Capture | [T1125](https://attack.mitre.org/techniques/T1125/) | Group5's RATs (njRAT/NanoCore on Windows, DroidJack on Android) supported webcam/camera activation to capture video and images of targets. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Group5 used a multi-stage delivery chain in which a first-stage .NET downloader (delivered as putty.exe) retrieved and installed the second-stage NanoCore RAT (dropped as dwm.exe) onto the victim host. |
