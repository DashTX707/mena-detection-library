# OilAlpha — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **13** across **8** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | The group registers and operates a large set of lookalike dynamic-DNS domains themed around victim organizations and the string 'version' (e.g. carversion.ddns.net, nrcversion.ddns.net, ksrversion.ddns.net, unsversion.ddns.net) plus a dedicated credential-theft domain (kssnew.online, registered ~January 2023). |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | OilAlpha operationalizes widely distributed commodity remote access trojans rather than bespoke malware: SpyNote/SpyMax (and SpyC23) Android RATs for mobile targets, and njRAT (Bladabindi) Windows RAT samples observed communicating with C2 infrastructure associated with the group, indicating parallel desktop operations. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | OilAlpha engages targets directly over encrypted messengers (WhatsApp), frequently from Saudi Arabian phone numbers, and uses URL link shorteners to deliver links that lead to malicious Android APK files disguised as legitimate humanitarian, UN/UNICEF, or government applications. 'Cold-calling'/direct messaging on chat platforms is a common engagement method. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | The victim is induced to install and run a spoofed Android application (observed file names: 'Cash Incentives.apk' / arabic 'المساعدات النقدية.apk', 'NRC Business.apk', and a CARE-branded app). During execution the app prompts the user in Arabic to enable an Accessibility service labelled 'Google Services', granting the RAT elevated control. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | OilAlpha's Android apps impersonate the branding, icons, names and Arabic-language login portals of legitimate and trusted organizations — UNICEF, the United Nations, the World Food Programme, the Norwegian Refugee Council, CARE International, and the King Salman Humanitarian Aid and Relief Centre — to lower target suspicion during social engineering. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Web Portal Capture | [T1056.003](https://attack.mitre.org/techniques/T1056/003/) | The malicious apps redirect the infected device's browser to a fake web portal hosted on kssnew.online that spoofs the login pages of NRC, CARE International (kssnew.online/care/index.php) and the King Salman Humanitarian Aid and Relief Centre. Victims are prompted to enter their username and password, which the portal harvests before any 'registration' fallback — enabling account takeover of the affected organizations. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Video Capture | [T1125](https://attack.mitre.org/techniques/T1125/) | SpyNote/SpyMax samples request access to the device camera among their excessive permissions, enabling covert video/image capture from the compromised phone for surveillance. |
| Audio Capture | [T1123](https://attack.mitre.org/techniques/T1123/) | The RATs request microphone/audio permissions on the infected Android device, allowing the operator to record ambient audio and calls as part of the espionage/surveillance mission. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | SpyNote/SpyMax requests invasive permissions to SMS, contacts, WiFi state, and external storage read/write, harvesting messages, contact lists and stored files from the compromised device for exfiltration to the operator. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Dynamic Resolution | [T1568](https://attack.mitre.org/techniques/T1568/) | OilAlpha almost exclusively uses dynamic DNS for command-and-control, spread across providers ddns.net, sytes.net, dynns.com and serveftp.com. Sandbox analysis showed samples resolving DDNS C2 (e.g. ho1hm2.ddns.net -> 206.189.98.34; NRC Business.apk C2 resolving to 141.255.145.221), a consistent, attributable tradecraft trait. |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | OilAlpha Android RAT samples beacon to their dynamic-DNS C2 servers over uncommon high TCP ports — the 'Cash Incentives' sample contacted ho1hm2.ddns.net on port 44414, and the 'NRC Business' sample was configured to reach ho1hm2.ddns.net and ho2hm1.ddns.net over port 44449. |
| Application Layer Protocol | [T1071](https://attack.mitre.org/techniques/T1071/) | Installed SpyNote/SpyMax Android RATs establish an application-layer command-and-control channel back to the operator's dynamic-DNS servers to receive commands and stream collected data from the compromised handset. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Collected device data (SMS, contacts, media, captured audio/video and harvested credentials) is exfiltrated back to OilAlpha operators over the same RAT command-and-control channel to the dynamic-DNS C2 servers. |
