# UNC3890 — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **32** across **9** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | UNC3890 developed proprietary/custom malware, including the SUGARUSH first-stage backdoor and multiple versions of the SUGARDUMP browser-credential stealer (early local-file version 2021, SMTP-exfil version late 2021/early 2022, HTTP-exfil version April 2022). Farsi-language development artifacts (.NET project name 'yaal', AES password containing 'KHODA') were embedded in SUGARDUMP. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | UNC3890 obtained and operationalized publicly available offensive tooling: the Metasploit framework, Unicorn (PowerShell downgrade/shellcode injection generator), and the open-source NorthStar C2 framework. |
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | UNC3890 registered typosquatting and brand-spoofing domains used for watering-hole/fake-login and lure infrastructure — e.g., lirikedin[.]com (punycode xn--lirkedin-vkb[.]com, fake LinkedIn), rnfacebook[.]com (fake Facebook), office365update[.]live (fake Office 365), pfizerpoll[.]com, celebritylife[.]news, fileupload[.]shop, naturaldolls[.]store and xxx-doll[.]com (robotic-dolls lure), and aspiremovecentraldays[.]net. |
| Establish Accounts: Email Accounts | [T1585.002](https://attack.mitre.org/techniques/T1585/002/) | UNC3890 established free webmail accounts (Yandex, Yahoo, Gmail, ProtonMail) under the persona 'john.macperson' / 'john.macperson2021' used as SUGARDUMP SMTP exfiltration senders and recipients. |
| Stage Capabilities: Drive-by Target | [T1608.004](https://attack.mitre.org/techniques/T1608/004/) | UNC3890 compromised/embedded malicious content in the legitimate login page of an Israeli shipping company to stage a watering hole, and stood up fake login pages spoofing Office 365, LinkedIn, Facebook and Pfizer on actor-controlled hosting (e.g., 128.199.6.246, 185.170.215.170) to capture visitor data and credentials. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Drive-by Compromise | [T1189](https://attack.mitre.org/techniques/T1189/) | UNC3890 used a strategic web compromise / watering hole: malicious content hosted on the legitimate login page of an Israeli shipping company reported visitor data back to an actor C2 (128.199.6.246) and could redirect victims to fake login pages, targeting visitors from Israeli shipping/maritime and related sectors. |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | UNC3890 delivered elaborate email social-engineering lures containing links to actor-controlled content — fake job offers (e.g., a fraudulent NexisLexis/Nexus offer), fake AI/robotics 'robotic dolls' commercials, and links to a fake Israeli dating-service login and other spoofed login pages — to deliver malware and harvest credentials. |
| Trusted Relationship | [T1199](https://attack.mitre.org/techniques/T1199/) | By compromising the legitimate login page of an Israeli shipping company to host the watering hole, UNC3890 abused a trusted third-party web property to reach and gather data on visitors from partner/sector organizations. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | UNC3890 relied on victims clicking links in social-engineering emails (fake job offers, fake commercials, fake dating-service/login pages) to reach credential-capture pages and malware-hosting infrastructure. |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | UNC3890 lured victims into executing malicious files: a fake VLC installer '3-Video-VLC.exe' that dropped/ran 'CrashReporter.exe' (SUGARDUMP SMTP variant) while displaying a 'RealDo1080.mp4' robotic-dolls video, and a malicious Excel/.xls macro document (fake NexisLexis job offer) that dropped the SUGARDUMP HTTP variant executed via RunDLL. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | UNC3890 used PowerShell downloaders and a PowerShell TCP reverse shell, and used the Unicorn tool to generate PowerShell-based shellcode-injection / downgrade payloads. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | The SUGARUSH backdoor establishes a reverse TCP shell to its hardcoded C2 and executes CMD (Windows command shell) commands received from the operator. |
| System Services: Service Execution | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | SUGARUSH executes as/through a Windows service ('Service1'), using the service control manager to launch the backdoor payload. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | SUGARUSH creates a Windows service named 'Service1' (establishing 'Logs'/'ServiceLog' folders) to persist and run its reverse-shell backdoor. |
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | The SUGARDUMP SMTP variant copies itself to %AppData%\Microsoft\Internet Explorer\TabRoaming\CrashReporter.exe and creates a logon-triggered scheduled task for persistence — named 'MicrosoftInternetExplorerCrashRepoeterTaskMachineUA' on Windows 7 or 'MicrosoftEdgeCrashRepoeterTaskMachineUA' on other Windows versions (note the misspelling 'Repoeter'). |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| System Binary Proxy Execution: Rundll32 | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | The SUGARDUMP HTTP variant (April 2022) was dropped by a malicious Excel macro and its PE payload was executed via RunDLL (rundll32.exe) to proxy execution of the credential-stealer. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | SUGARDUMP masquerades as benign Windows/utility software — dropped as 'CrashReporter.exe' staged under %AppData%\Microsoft\Internet Explorer\TabRoaming\, delivered by a fake '3-Video-VLC.exe' installer, exfil files named to look like system artifacts ('CrashLog.txt', %TEMP%\DebugLogWindowsDefender.txt), and scheduled tasks named to mimic Microsoft/IE/Edge crash-reporter tasks. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | SUGARDUMP writes its collected credentials to disk in obfuscated/encrypted form prior to exfil — the HTTP variant stores AES-CBC-encrypted then Base64-encoded data in %TEMP%\DebugLogWindowsDefender.txt, and the SMTP variant stages Base64-encoded credentials as CrashLog.txt. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | SUGARDUMP harvests saved credentials from web browsers — Chrome (%AppData%\Google\Chrome\User Data), Opera (%AppData%\Opera Software\Opera Stable), Edge Chromium (%AppData%\Microsoft\Edge\User Data) and Firefox (%AppData%\Mozilla\Firefox\Profiles). |
| Steal Web Session Cookie | [T1539](https://attack.mitre.org/techniques/T1539/) | In addition to saved passwords, the SUGARDUMP SMTP variant harvests browser cookies (along with browser version, browsing history and bookmarks) from targeted browser profiles. |
| Input Capture: Web Portal Capture | [T1056.003](https://attack.mitre.org/techniques/T1056/003/) | UNC3890 deployed fake login pages spoofing Office 365, LinkedIn, Facebook, Pfizer and an Israeli dating service (and the shipping-company watering hole) to capture credentials entered by victims into cloned web portals. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | SUGARDUMP gathers host/environment context (Windows version — branching persistence between Windows 7 and later versions — and browser versions installed) to tailor its persistence and collection. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | UNC3890 used PowerShell downloaders and staged malware/tools on actor-controlled hosting (e.g., 128.199.6.246 for malware/tools hosting and the watering hole; 161.35.123.176 for SUGARUSH C2 and malicious-domain hosting) to transfer follow-on payloads to victims. |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | SUGARUSH beacons its reverse TCP shell to its hardcoded C2 over the non-standard port 4585 (observed C2 161.35.123.176). |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | The SUGARDUMP HTTP variant communicates/exfiltrates over HTTP (port 80) to actor C2 144.202.123.248, and the watering hole reported visitor data over web protocols to actor infrastructure; NorthStar C2 (143.110.155.195) also uses web-based C2. |
| Remote Access Tools | [T1219](https://attack.mitre.org/techniques/T1219/) | UNC3890 operated the open-source NorthStar C2 framework (stager MD5 2fe42c52826787e24ea81c17303484f9; C2 server 143.110.155.195) for remote command-and-control of compromised hosts. |
| Data Encoding: Standard Encoding | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | SUGARDUMP Base64-encodes harvested credential data before exfiltration — the SMTP variant sends Base64-encoded credentials in a 'CrashLog.txt' attachment (subject 'VLC Player'), and the HTTP variant Base64-encodes the AES-encrypted output. |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | The SUGARDUMP HTTP variant encrypts exfiltration data with AES-CBC before Base64-encoding and sending over HTTP; the AES key is the SHA256 of the hardcoded password '1qazXSW@3edc123456be name KHODA 110 !!)1qazXSW@3edc' (the string 'KHODA' being Farsi for 'God'). |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | UNC3890 employed tunneling within its C2 tradecraft (reported by Mandiant among the cluster's C2 techniques) to relay backdoor traffic through actor infrastructure and obscure the true source of connections. |
| Web Service: Bidirectional Communication | [T1102.002](https://attack.mitre.org/techniques/T1102/002/) | UNC3890 abused legitimate webmail services (Gmail/Yahoo/Yandex via SMTP) as a bidirectional relay/dead-drop for SUGARDUMP credential exfiltration, blending malicious traffic with normal mail-provider connections. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over Alternative Protocol | [T1048](https://attack.mitre.org/techniques/T1048/) | The SUGARDUMP SMTP variant exfiltrates harvested browser credentials over SMTP (port 587) to legitimate webmail providers (smtp.yandex.com, smtp.mail.yahoo.com), sending Base64-encoded data as a 'CrashLog.txt' attachment with subject 'VLC Player' from/to actor personas (john.macperson2021@yandex.com, @yahoo.com, @gmail.com, john.macperson@protonmail.com). NOTE: the webmail service domains (yandex/yahoo/gmail/protonmail) are legitimate and are intentionally NOT listed in the domains IOC array — the detectable behavior is the exfil-to-webmail pattern captured here. |
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | The SUGARDUMP HTTP variant exfiltrates AES-encrypted, Base64-encoded browser credentials over its HTTP C2 channel to actor server 144.202.123.248:80, writing staging data to %TEMP%\DebugLogWindowsDefender.txt. |
