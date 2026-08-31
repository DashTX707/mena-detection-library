# Domestic Kitten — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **28** across **10** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Stage Capabilities: SEO Poisoning | [T1608.006](https://attack.mitre.org/techniques/T1608/006/) | The FurBall ESET campaign staged the malicious APK on a copycat website (downloadmaghaleh.com) impersonating a legitimate Persian scientific-paper translation service, and other campaigns hosted payloads on an Iranian blog and a fake mobile app-store, luring victims searching for the legitimate services/apps. |
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | Rampant Kitten created fake Telegram 'service' accounts that message targets with fake warnings about 'improper use' of Telegram to lure them to credential-phishing pages. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Domestic Kitten delivers FurBall APKs to targets via SMS messages containing download links, links posted on Iranian blog sites, and links shared in Telegram channels. Rampant Kitten additionally served Telegram-credential phishing pages via links pushed from fake Telegram 'service' accounts warning victims about 'improper use' of Telegram. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Infection requires the victim to sideload and install a malicious APK presented behind a fake Google Play download button; the decoys impersonate security, news, religious, poetry, restaurant, VPN and translation apps to induce installation. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Boot or Logon Autostart Execution | [T1547](https://attack.mitre.org/techniques/T1547/) | FurBall registers a broadcast receiver for the Android BOOT_COMPLETED intent so the spyware relaunches automatically every time the device is powered on, maintaining persistent surveillance. |
| Compromise Host Software Binary | [T1554](https://attack.mitre.org/techniques/T1554/) | The TelB and TelAndExt variants hijack Telegram Desktop's update mechanism by replacing/modifying the legitimate Updater.exe binary, so the stealer is executed under cover of Telegram's own auto-update flow. |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | The HookInjEx variant establishes persistence via a RunOnce registry key, typically named 'SunJavaHtml' or 'DevNicJava', to relaunch its loader at logon. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | FurBall is repackaged inside, or made to imitate, legitimate applications — a fake VIPRE Mobile Security app, the ISIS 'Amaq' news app, an 'Islamic Caliphate' app, a repackaged 'Exotic Flowers' game from Google Play, an Android app-store (MyKet mimic, ir.mservices.market), and a Mohsen Restaurant app — so the surveillanceware appears to be trusted software. The Rampant Kitten Android backdoor displays a fake 'Google protect is enabled' notification to mask microphone recording. |
| Process Injection: Dynamic-link Library Injection | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | The HookInjEx variant maps its DLL into explorer.exe and subclasses the Windows Start button (across multiple UI languages) to hook and run within a trusted process. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Multi-Factor Authentication Interception | [T1111](https://attack.mitre.org/techniques/T1111/) | The Rampant Kitten Android backdoor intercepts incoming SMS messages and forwards any message whose body begins with 'G-' (Google two-factor authentication codes) to an attacker-controlled phone number, defeating SMS-based 2FA on victim Google accounts. |
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | The Python info-stealer and HookInjEx variants steal saved credentials from web browsers including Chrome, Firefox, Edge and Opera. |
| Credentials from Password Stores: Password Managers | [T1555.005](https://attack.mitre.org/techniques/T1555/005/) | The TelB variant steals KeePass password-manager databases (.kdbx files) from the victim host, targeting the master credential store. |
| Input Capture: Web Portal Capture | [T1056.003](https://attack.mitre.org/techniques/T1056/003/) | The Rampant Kitten Android backdoor phishes Google account credentials by presenting a Google login through a WebView with a JavascriptInterface bridge that captures the entered username and password; separately, Telegram phishing pages harvest Telegram credentials. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | FurBall collects device identifiers, device type, OS version, and a unique device ID to fingerprint each infected phone for the operators. |
| Software Discovery | [T1518](https://attack.mitre.org/techniques/T1518/) | FurBall enumerates the list of installed applications on the infected device and reports it to the C2, aiding targeting and follow-on tasking. |
| Peripheral Device Discovery | [T1120](https://attack.mitre.org/techniques/T1120/) | The HookInjEx Windows variant enumerates removable/USB drives on the host to identify additional data sources for collection. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Audio Capture | [T1123](https://attack.mitre.org/techniques/T1123/) | FurBall records ambient/surroundings audio via the device microphone and records phone calls; the Rampant Kitten Android backdoor records ~30 seconds of surroundings audio, and the HookInjEx Windows stealer records ~60 seconds of audio from the host. |
| Video Capture | [T1125](https://attack.mitre.org/techniques/T1125/) | FurBall can be tasked by its C2 to capture photos and record video from the device camera and upload them to the command-and-control server. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | The HookInjEx Windows variant captures screenshots of the victim's desktop for exfiltration. |
| Clipboard Data | [T1115](https://attack.mitre.org/techniques/T1115/) | FurBall monitors and exfiltrates clipboard text content on the mobile device; the HookInjEx Windows variant likewise steals clipboard data. |
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | The HookInjEx Windows variant hooks input to keylog the victim, capturing typed keystrokes across applications. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | FurBall steals SMS messages, call logs, contacts, media files (photos/videos), and files from external storage; the Windows infostealers steal documents by extension (.txt, .csv, .kdbx, .xls, .xlsx, .ppt, .pptx) and Telegram Desktop data files from the local system. |
| Automated Collection | [T1119](https://attack.mitre.org/techniques/T1119/) | FurBall automatically harvests a broad set of device data on a schedule/command — device identifiers, notification text, running processes, device accounts, location, and installed-app inventory — using a command protocol delimited by '===' with arguments separated by '~~~'; the C2-tasking loop drives repeated automated collection. |
| Archive Collected Data | [T1560](https://attack.mitre.org/techniques/T1560/) | The Python info-stealer encrypts collected data with AES via pyAesCrypt using a hard-coded password before exfiltration; the Rampant Kitten Android backdoor likewise AES-encrypts data prior to FTPS upload. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | FurBall communicates with its C2 over HTTP, beaconing roughly every 10 seconds to request commands, using obfuscated server URI paths (backend PHP script names are periodically changed). The Rampant Kitten Android backdoor uses HTTP to alarabiye.net for C2 and pulls configuration/commands from gradleservice.info; the TelB Windows variant uses SOAP over HTTP. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | FurBall retrieves configuration and command updates from its C2 (a capability the operators added on top of the original KidLogger code) and downloads server-side URI/PHP changes, allowing the operators to re-point and re-task infected devices after deployment. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | FurBall uploads captured surveillance data (SMS, call recordings, media, location, photos/video) back to its C2 over the same HTTP channel used for tasking. |
| Exfiltration Over Alternative Protocol | [T1048](https://attack.mitre.org/techniques/T1048/) | The TelAndExt and Python Windows stealers exfiltrate stolen data over FTP, and the Rampant Kitten Android backdoor uploads data over FTPS using hard-coded credentials, using a protocol distinct from the HTTP command channel. |
