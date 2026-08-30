# Bahamut — ATT&CK Technique Mapping

> Attribution: Iran-nexus — low confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **41** across **11** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Gather Victim Identity Information | [T1589](https://attack.mitre.org/techniques/T1589/) | Bahamut researches specific high-value individuals (government officials, diplomats, activists, journalists, military and business figures) and develops bespoke phishing content tailored to each target, indicating detailed pre-attack collection of victim identity/contact information. |
| Gather Victim Org Information | [T1591](https://attack.mitre.org/techniques/T1591/) | The group mimics specific government-agency login portals and organizational webmail, implying reconnaissance of victim organizations' branding, portals and staff to build convincing lures. |
| Phishing for Information: Spearphishing Link | [T1598.003](https://attack.mitre.org/techniques/T1598/003/) | Bahamut operates a highly tuned credential-harvesting system: fake login pages mimicking government agencies, private email and trusted applications, sometimes with bespoke per-target content and embedded logic to detect victim click patterns and validate real targets before harvesting credentials. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | The group registers large numbers of single-use, look-alike domains — impersonating login portals, news outlets, and app/VPN vendors (e.g. thesecurevpn[.]com mimicking SecureVPN) — and rotates infrastructure weekly or even daily to frustrate tracking. |
| Acquire Infrastructure: Web Services | [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | Bahamut fronts C2 and distribution infrastructure behind third-party web services (e.g. Cloudflare) and stands up a sprawling network of fake news websites to lend legitimacy to lures and personas. |
| Establish Accounts | [T1585](https://attack.mitre.org/techniques/T1585/) | The group builds and maintains elaborate fake personas — journalists, activists, and organizations — with fabricated online histories to approach and social-engineer targets and to author their fake-news ecosystem. |
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | Bahamut operates numerous fake social-media accounts to amplify fake-news content, build persona credibility, and initiate contact with targets ahead of phishing or spyware delivery. |
| Establish Accounts: Email Accounts | [T1585.002](https://attack.mitre.org/techniques/T1585/002/) | The group provisions attacker-controlled email accounts to send spearphishing lures and to back the identities of its fake personas. |
| Compromise Accounts: Social Media Accounts | [T1586.001](https://attack.mitre.org/techniques/T1586/001/) | Consistent with its account-takeover-centric tradecraft, Bahamut repurposes compromised accounts (obtained via credential phishing) to further its espionage and disinformation objectives and to reach additional targets from trusted identities. |
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Bahamut develops custom malware in-house across platforms — hundreds of custom Windows samples, bespoke iOS App Store apps, and Android spyware families (Bahamut spyware, CoverIm/CoverLM) built by repackaging legitimate apps with espionage code. |
| Obtain Capabilities: Exploits | [T1588.005](https://attack.mitre.org/techniques/T1588/005/) | BlackBerry assessed Bahamut had access to an in-house zero-day exploit developer and used zero-day exploits in operations, an unusually advanced capability for a hack-for-hire group. |
| Obtain Capabilities: Vulnerabilities | [T1588.006](https://attack.mitre.org/techniques/T1588/006/) | The group researches and stockpiles vulnerabilities (feeding its in-house exploit development) to enable targeted compromise. |
| Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | Bahamut stages trojanized apps on attacker-controlled distribution sites (e.g. thesecurevpn[.]com serving trojanized SoftVPN/OpenVPN builds) and, historically, smuggled malicious iOS/Android apps into official app stores for download by targets. |
| Stage Capabilities: Install Digital Certificate | [T1608.003](https://attack.mitre.org/techniques/T1608/003/) | The SafeChat/CoverIm spyware uses a Let's Encrypt TLS certificate on its C2 endpoint to present an encrypted, trusted-looking channel for exfiltration. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Primary initial-access vector: targeted spearphishing emails and messages carrying links to credential-harvesting pages or trojanized-app downloads, with lures bespoke to each victim. |
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Bahamut has delivered malicious document/attachment lures to targets to drop custom Windows malware, consistent with its hundreds of Windows samples and use of document-based social engineering. |
| Phishing: Spearphishing via Service | [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | In the SafeChat/CoverIm campaign, the malicious 'SafeChat' Android app was delivered to targets directly over WhatsApp via spear-messaging (a third-party messaging service rather than email). |
| Drive-by Compromise | [T1189](https://attack.mitre.org/techniques/T1189/) | Bahamut lures targets to its fake-news and fake-vendor websites (and app-store listings) where trojanized apps and malicious content are served, using the fabricated ecosystem to give downloads a veneer of legitimacy. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Compromise depends on the target clicking attacker links — to credential-harvesting portals or to attacker-hosted app downloads (e.g. thesecurevpn[.]com). |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | The target must install the trojanized app (SecureVPN/SoftVPN/OpenVPN, SafeChat) or open the malicious Windows document/attachment for the payload to run; the Android apps then repeatedly prompt the user to grant Accessibility and battery-exemption permissions. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Per MITRE ATT&CK's Windshift/Bahamut (G0112) profile, the group has used Visual Basic (macro) execution in its document-lure delivery of Windows payloads. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | On Windows, the Windshift/Bahamut cluster (G0112) establishes persistence via Registry Run keys / Startup folder. On Android, the spyware achieves the equivalent by registering for the BOOT_COMPLETED broadcast to auto-start at device boot (mapped here to the nearest Enterprise autostart technique). |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | Bahamut's entire delivery model is masquerade-based: fake VPN/chat apps posing as legitimate privacy tools, fake-news sites and personas posing as real journalists/outlets, and login portals impersonating real government and email services. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | The trojanized apps reuse the exact names, icons and package identities of real software — 'SecureVPN', trojanized SoftVPN/OpenVPN (packages com.secure.vpn, com.openvpn.secure), and 'SafeChat' — so victims believe they are installing genuine privacy apps. |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | The group employs anti-forensic and anti-analysis techniques (per BlackBerry) and the mobile payloads use encryption of stolen data (RSA/ECB/OAEP) to obstruct reverse-engineering and content recovery. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | By abusing Android Accessibility Services, the spyware captures on-screen activity and keystrokes, including text entered into secure messaging apps (Signal, WhatsApp, Telegram, Viber, Facebook Messenger, WeChat, imo, Conion), effectively defeating end-to-end encryption at the input layer. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Software Discovery | [T1518](https://attack.mitre.org/techniques/T1518/) | The Android spyware enumerates the list of installed applications on the device to identify which messaging/target apps are present and to tailor collection. |
| Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | Consistent with its AV-evasion and anti-forensic tradecraft on Windows, the Windshift/Bahamut cluster (G0112) checks for security software present on the host before proceeding. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | The spyware collects device identifiers and system information — IMEI, device ID, IP address, SIM serial number, and device accounts — for fingerprinting and C2 registration. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | The malware harvests device accounts and owner information to identify the victim and support targeting. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | Per the Windshift/Bahamut (G0112) profile, the group enumerates running processes on compromised hosts as part of environment assessment. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | Through Accessibility Services the malware captures the content displayed on screen (including messages rendered by target chat apps), a screen-scraping form of collection. |
| Audio Capture | [T1123](https://attack.mitre.org/techniques/T1123/) | The Bahamut Android spyware records phone calls, exfiltrating recorded call audio to the C2 server. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | The spyware harvests locally stored data — SMS messages, call logs, contacts, GPS/location data, device accounts and files from external storage — and stages it in a local database prior to exfiltration. |
| Automated Collection | [T1119](https://attack.mitre.org/techniques/T1119/) | Collection is automated: exfiltrated data is continuously gathered and written to a local SQLite/database before being batched and sent to the C2, requiring no per-item operator interaction. |
| Archive Collected Data | [T1560](https://attack.mitre.org/techniques/T1560/) | Before exfiltration the SafeChat/CoverIm spyware encrypts collected data using RSA/ECB/OAEPPadding, packaging it in an encrypted form that also hampers analyst recovery of stolen content. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | The Android spyware communicates with its C2 over HTTPS web protocols (SecureVPN campaign C2 ft8hua063okwfdcu21pw[.]de; SafeChat C2 laborer-posted[.]nl), using a Ktor (Kotlin) HTTP client. |
| Encrypted Channel: Asymmetric Cryptography | [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | The SafeChat/CoverIm C2 channel is protected with a Let's Encrypt TLS certificate and the exfiltrated payload is additionally encrypted with RSA (OAEP padding), layering asymmetric cryptography over the transport. |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | SafeChat/CoverIm beacons to its C2 (laborer-posted[.]nl) over non-standard TCP port 2053 rather than the usual 443. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | The trojanized VPN apps require an operator-supplied activation key that, once validated by the C2, unlocks/delivers the spyware functionality — the server gating and enabling of malicious capability post-install (per the Windshift/Bahamut G0112 ingress-transfer behavior). |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Collected data (messages, SMS, call logs, contacts, location, recorded calls, device info) is exfiltrated from the local database to the C2 over the same HTTPS channel used for command-and-control. |
