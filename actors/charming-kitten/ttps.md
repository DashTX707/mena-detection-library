# Charming Kitten (APT35 / Magic Hound, G0059) — ATT&CK Technique Mapping

> Attribution: Iran-nexus (IRGC) — high confidence. MITRE ID: G0059.
> Enriched from MITRE ATT&CK G0059 + Google/Mandiant APT42 reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **84** across **14** tactics. Identity/email-centric tradecraft (credential phishing, impersonation personas, cloud/webmail abuse).

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Phishing for Information: Spearphishing Link | [T1598.003](https://attack.mitre.org/techniques/T1598/003/) | Charming Kitten's signature vector: spear-phishing emails carrying links (often via typo-squatted domains posing as news articles, conference invitations or cloud-hosted documents, sometimes behind the n9[.]cl shortener) that redirect targets to cloned login portals (Gmail, Google Meet, Google Drive, Microsoft 365, SharePoint, LinkedIn, Yahoo, Hotmail, YouTube, DUO) to elicit credentials and MFA tokens. Lures are highly tailored to each victim (journalists, activists, academics). |
| Gather Victim Identity Information: Email Addresses | [T1589.002](https://attack.mitre.org/techniques/T1589/002/) | The actor collects target email addresses (of journalists, activists, academics, NGO and government personnel) to seed tailored spear-phishing and credential-harvesting campaigns. |
| Gather Victim Identity Information: Credentials | [T1589.001](https://attack.mitre.org/techniques/T1589/001/) | Charming Kitten's operations are fundamentally oriented around obtaining victim credentials, harvested through fake login pages and social-engineering correspondence, then reused for account and cloud access. |
| Gather Victim Identity Information | [T1589](https://attack.mitre.org/techniques/T1589/) | Broadly, the actor profiles targets' identities — names, roles, affiliations and relationships — to build convincing personas and select spoofed institutions/individuals for lures (e.g. spoofing Harvard T.H. Chan School, 'Daniel Serwer', 'David Webb', 'Jamileh Nedai'). |
| Gather Victim Org Information: Determine Physical Locations | [T1591.001](https://attack.mitre.org/techniques/T1591/001/) | Charming Kitten gathers organizational information about targets to inform targeting and lure content per the G0059 mapping. |
| Gather Victim Network Information: IP Addresses | [T1590.005](https://attack.mitre.org/techniques/T1590/005/) | The actor gathers victim network/IP information, including via tracking pixels/web beacons embedded in phishing content that profile recipient IP addresses. |
| Gather Victim Host Information: Software | [T1592.002](https://attack.mitre.org/techniques/T1592/002/) | The actor gathers information about victim host software/defensive products (e.g. presence of Windows Defender influences the TAMECAT execution path) to tailor payload delivery. |
| Active Scanning: Vulnerability Scanning | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Charming Kitten conducts active scanning for vulnerabilities on internet-facing targets per the G0059 mapping, supporting exploitation of public-facing applications. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | A hallmark of the actor: cultivating fake social-media personas (e.g. the 'Mona Louri' Twitter account posing as a human-rights activist/researcher) to build rapport and credibility with targets before delivering credential-harvesting links or malware. Descends from the historical NEWSCASTER persona network. |
| Establish Accounts: Email Accounts | [T1585.002](https://attack.mitre.org/techniques/T1585/002/) | The actor registers email accounts under fabricated personas (journalists, event organizers, activists) used for trust-building correspondence and to send spear-phishing lures; also registers attacker mailboxes such as <victim_org>@outlook.com used as exfiltration destinations. |
| Compromise Accounts: Email Accounts | [T1586.002](https://attack.mitre.org/techniques/T1586/002/) | The actor leverages compromised legitimate email accounts (harvested credentials) to lend authenticity to correspondence and to hijack existing trust relationships when phishing further targets. |
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | The actor registers large numbers of typo-squatted / lookalike domains on TLDs such as .top, .online, .site, .live and .buzz — often several hyphen-separated words (e.g. panel-live-check[.]online, review[.]modification-check[.]online, drive-file-share[.]site) — to host credential-harvesting pages, redirects and malware staging. |
| Acquire Infrastructure: Web Services | [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | The actor abuses legitimate web/cloud services for infrastructure: glitch.me subdomains (prism-west-candy[.]glitch[.]me, accurate-sprout-porpoise[.]glitch[.]me) as NICECURL/TAMECAT C2, s3[.]tebi[.]io object storage for payload hosting, Dropbox/Google Drive for decoy documents, and Cloudflare-fronted domains — to blend malicious traffic into trusted destinations. |
| Compromise Infrastructure: Domains | [T1584.001](https://attack.mitre.org/techniques/T1584/001/) | The actor compromises and repurposes existing domains/infrastructure for redirects and hosting of credential-harvesting content per the G0059 mapping. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | The actor obtains and uses open-source/legitimate tooling, e.g. PowerHuntShares (Invoke-HuntSMBShares) for SMB share enumeration and 7-Zip for archiving, living off open-source and built-in utilities to reduce custom-malware exposure during cloud operations. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Primary initial-access vector: spear-phishing emails with malicious links leading to credential-harvesting pages or malware droppers (e.g. LNK/macro-document delivery of NICECURL/TAMECAT), frequently after extended trust-building correspondence posing as journalists or conference organizers. |
| Phishing: Spearphishing via Service | [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | The actor initiates contact and delivers lures through social-media/messaging services using fake personas (e.g. LinkedIn/Twitter personas, fake Google Meet invitations), leveraging non-email channels to build rapport before phishing. |
| Drive-by Compromise | [T1189](https://attack.mitre.org/techniques/T1189/) | Charming Kitten uses malicious/compromised web content and redirect chains that can compromise or harvest from visitors per the G0059 mapping, complementing its link-based phishing. |
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | The actor exploits vulnerabilities in internet-facing applications (historically including ProxyShell/Log4j-class and VPN/appliance flaws in Phosphorus/Mint Sandstorm operations) to gain initial access per the G0059 mapping. |
| Valid Accounts: Cloud Accounts | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | After harvesting credentials and defeating MFA, APT42 logs into victims' Microsoft 365 / cloud environments as legitimate users to explore, enumerate and exfiltrate data — the core of its cloud operations against U.S./U.K. legal and NGO targets. This is a well-sourced addition beyond the G0059 sub-technique list (verified present in this ATT&CK dataset), directly documented by Mandiant. |
| Valid Accounts: Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | The actor reuses harvested/valid domain credentials to access on-premises and hybrid systems (e.g. Citrix + RDP) and move through victim networks per the G0059 mapping and Mandiant cloud-operations reporting. |
| Valid Accounts: Default Accounts | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | The actor leverages default/valid accounts as mapped in G0059 to obtain and retain access. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Multi-Factor Authentication Request Generation | [T1621](https://attack.mitre.org/techniques/T1621/) | To bypass MFA on accounts for which it holds valid credentials, APT42 sends repeated MFA push notifications to victims upon login attempts ('MFA fatigue' / push bombing), which Mandiant observed succeeding after cloned-page token capture failed. Well-sourced addition beyond the G0059 list (verified present in this dataset), directly documented by Mandiant. |
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | On compromised hosts the actor dumps credentials from LSASS memory to obtain additional accounts per the G0059 mapping. |
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | The actor uses keylogging to capture credentials and other input per the G0059 mapping. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Use Alternate Authentication Material: Web Session Cookie | [T1550.004](https://attack.mitre.org/techniques/T1550/004/) | APT42 captured MFA tokens / session material via cloned login pages and abused the KMSI (Keep-Me-Signed-In) feature to avoid re-authentication, effectively using authenticated session material to maintain access without re-verifying MFA. Well-sourced addition beyond the G0059 list (verified present in this dataset). |
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | APT42 logged into a victim's Citrix application and used Windows RDP for hands-on-keyboard access to explore, enumerate and stage data for exfiltration. |
| Lateral Tool Transfer | [T1570](https://attack.mitre.org/techniques/T1570/) | The actor transfers tools between systems within the victim environment to extend operations per the G0059 mapping. |

## Defense Impairment

| Technique | ID | Notes |
|---|---|---|
| Modify Authentication Process: Multi-Factor Authentication | [T1556.006](https://attack.mitre.org/techniques/T1556/006/) | APT42 abused Microsoft's app-password feature — which generates single-use passwords that do not require MFA — to establish continuous MFA-free access to compromised M365 accounts. ATT&CK cites the Mandiant APT42 report directly for this technique. Verified present in this dataset. |
| Impair Defenses: Disable or Modify Tools | [T1685](https://attack.mitre.org/techniques/T1685/) | The actor disables or works around security tooling; TAMECAT branches its behavior on the presence of Windows Defender (using conhost+Wget when Defender is running) to evade defensive controls, and Phosphorus/Mint Sandstorm operations have tampered with defenses per the G0059 mapping. |
| Impair Defenses: Disable or Modify Windows Event Log | [T1685.001](https://attack.mitre.org/techniques/T1685/001/) | The actor disables or modifies Windows event logging to reduce host visibility during operations per the G0059 mapping (remapped ID per this dataset's convention). |
| Impair Defenses: Windows Host Firewall | [T1686.003](https://attack.mitre.org/techniques/T1686/003/) | The actor modifies the Windows host firewall (e.g. netsh advfirewall / Set-NetFirewallProfile / rule changes) to enable remote access and C2 traffic per the G0059 mapping. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Victims are induced to click links leading to credential-harvesting pages or malware download URLs (e.g. drive-file-share[.]site/OneDrive-Form.pdf.lnk), a required user action in the actor's link-centric campaigns. |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Victims are lured into opening malicious files: LNK droppers disguised as PDFs (onedrive-form.pdf.lnk) and macro-enabled Office documents that drop TAMECAT, each paired with a decoy document spoofing a real institution or individual (e.g. Harvard T.H. Chan interview feedback form). |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell is central: TAMECAT is a PowerShell toehold that executes arbitrary PowerShell or C# content and carries an AES-encrypted payload decrypted at runtime; TAMECAT uses conhost to run a Wget-based PowerShell download when Windows Defender is present; and cloud operators ran Set-ExecutionPolicy, Import-Module and Invoke-HuntSMBShares. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | NICECURL is a VBScript backdoor (e.g. kuzen.vbs) that reverses the string 'llehS.tpircsW' to instantiate WScript.Shell, base64-decodes operator commands, and uses curl to communicate; the YARA rule keys on these VBScript artifacts. Office macro lures (VBA) also drop TAMECAT. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | NICECURL launches 'cmd /C start /MIN curl ...' to fetch commands, and TAMECAT uses cmd.exe to execute a curl download in the non-Defender path — cmd.exe is used to spawn curl-based C2 fetches. |
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) | The actor uses WMI for execution and discovery on compromised hosts per the G0059 mapping. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | The actor creates scheduled tasks for execution/persistence of its implants per the G0059 mapping. |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | The actor establishes persistence via Registry Run keys / Startup folder entries per the G0059 mapping. |
| Create Account: Local Account | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | The actor creates local accounts to maintain access to compromised systems per the G0059 mapping. |
| Account Manipulation: Additional Email Delegate Permissions | [T1098.002](https://attack.mitre.org/techniques/T1098/002/) | Consistent with FireEye's APT35 reporting, the actor grants additional mailbox delegate permissions (e.g. Add-MailboxPermission) to retain persistent access to targeted mailboxes in Exchange/Office 365. |
| Account Manipulation: Additional Local or Domain Groups | [T1098.007](https://attack.mitre.org/techniques/T1098/007/) | The actor adds controlled accounts to local/domain groups (e.g. administrators, Remote Desktop Users) to maintain and elevate access per the G0059 mapping. |
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | The actor deploys web shells on compromised internet-facing servers for persistence and remote command execution per the G0059 mapping. |

## Stealth

| Technique | ID | Notes |
|---|---|---|
| Hide Artifacts: Email Hiding Rules | [T1564.008](https://attack.mitre.org/techniques/T1564/008/) | Consistent with FireEye's APT35 2018 findings and the actor's mailbox-centric tradecraft, Charming Kitten creates inbox/forwarding rules in compromised mailboxes to hide security alerts and conceal its access and email theft. Well-aligned addition emphasizing the actor's identity/email signature (verified present in this dataset). |
| Masquerading: Match Legitimate Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | The actor disguises malicious files and infrastructure as legitimate: LNK named onedrive-form.pdf.lnk to look like a PDF, domains masquerading as Google/OneDrive/Drive services, and an attacker OneDrive/mailbox masquerading as the victim organization (<victim_org>@outlook.com). |
| Masquerading: Masquerade Task or Service | [T1036.004](https://attack.mitre.org/techniques/T1036/004/) | The actor names scheduled tasks/services to resemble legitimate ones to blend persistence into normal system activity per the G0059 mapping. |
| Masquerading: Masquerade Account Name | [T1036.010](https://attack.mitre.org/techniques/T1036/010/) | The actor names attacker-created accounts/personas to approximate legitimate ones (e.g. mailbox/OneDrive naming echoing the victim organization) to make them appear benign. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Payloads are stored encrypted/encoded: TAMECAT is delivered as an obfuscated, AES-encrypted backdoor inside nconf.txt (AES key kNz0CXiP0wEQnhZXYbvraigXvRVYHk1B, unique key value T2r0y1M1e1n1o0w1) decrypted by a companion PowerShell; NICECURL base64-decodes operator commands; TAMECAT expects Base64-encoded C2 data. |
| Obfuscated Files or Information: Command Obfuscation | [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | NICECURL obfuscates its logic (e.g. StrReverse of 'llehS.tpircsW' to build 'WScript.Shell', base64-decoded commands), and TAMECAT wraps its logic in layered obfuscation, to impede signature analysis. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | At runtime the implants reverse their own encoding: TAMECAT's loader AES-decrypts the embedded backdoor and its C2 parameters; NICECURL base64-decodes commands before execution. |
| Hide Artifacts: Hidden Window | [T1564.003](https://attack.mitre.org/techniques/T1564/003/) | NICECURL launches its curl C2 fetch with 'cmd /C start /MIN' to run minimized/hidden, concealing the command window from the user. |
| Modify Registry | [T1112](https://attack.mitre.org/techniques/T1112/) | The actor modifies the registry to support persistence/configuration of its implants per the G0059 mapping. |
| System Binary Proxy Execution: Rundll32 | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | The actor proxies execution through rundll32.exe to run malicious code under a trusted system binary per the G0059 mapping. |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | NICECURL's 'kill' command removes artifacts and ends execution (it includes DeleteFile/CopyFile helpers), and operators delete tooling/artifacts to cover tracks per the G0059 mapping. |
| Indicator Removal: Clear Command History | [T1070.003](https://attack.mitre.org/techniques/T1070/003/) | The actor clears command history to hinder investigation per the G0059 mapping. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Account Discovery: Email Account | [T1087.003](https://attack.mitre.org/techniques/T1087/003/) | In compromised cloud/email environments the actor enumerates mailboxes/email accounts to identify further targets and data of interest per the G0059 mapping. |
| Domain Trust Discovery | [T1482](https://attack.mitre.org/techniques/T1482/) | The actor enumerates domain trust relationships to plan lateral movement per the G0059 mapping. |
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | The actor scans internal hosts/services (including SMB share hunting via Invoke-HuntSMBShares) to map the environment and locate data per the G0059 mapping and Mandiant cloud-operations reporting. |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) | The actor enumerates remote systems on the network to identify lateral-movement targets per the G0059 mapping. |
| System Network Connections Discovery | [T1049](https://attack.mitre.org/techniques/T1049/) | The actor enumerates active network connections on compromised hosts per the G0059 mapping. |
| System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | The actor enumerates network configuration on compromised hosts per the G0059 mapping. |
| System Network Configuration Discovery: Internet Connection Discovery | [T1016.001](https://attack.mitre.org/techniques/T1016/001/) | The actor checks for internet connectivity from compromised hosts (e.g. to confirm C2 reachability) per the G0059 mapping. |
| System Network Configuration Discovery: Wi-Fi Discovery | [T1016.002](https://attack.mitre.org/techniques/T1016/002/) | Consistent with Check Point's CharmPower reporting, the actor enumerates Wi-Fi network names/passwords (e.g. via netsh wlan / wlanAPI) on compromised hosts per the G0059 mapping. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | The actor identifies the current/owner user on compromised hosts per the G0059 mapping. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | The actor enumerates running processes (e.g. to check for Windows Defender/security tooling, as TAMECAT does to select its execution path) per the G0059 mapping. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | NICECURL gathers system information (the YARA rule references a GetSystemCaption function retrieving the OS caption) and the actor profiles host details per the G0059 mapping. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | During cloud/host operations the actor explores and enumerates files and directories to locate and stage data of interest (e.g. files pertaining to Iran's foreign affairs / the Persian Gulf) per the Mandiant report and G0059 mapping. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | The actor collects files of strategic interest from compromised local systems and cloud stores (OneDrive documents, files pertaining to Iran's foreign affairs / Persian Gulf region) per the Mandiant report and G0059 mapping. |
| Email Collection | [T1114](https://attack.mitre.org/techniques/T1114/) | The actor collects victim email — Outlook emails from the M365 environment were exfiltrated — a core objective of its identity-centric espionage per the Mandiant report and G0059 mapping. |
| Email Collection: Local Email Collection | [T1114.001](https://attack.mitre.org/techniques/T1114/001/) | The actor collects email data from local Outlook stores/caches on compromised hosts per the G0059 mapping. |
| Email Collection: Remote Email Collection | [T1114.002](https://attack.mitre.org/techniques/T1114/002/) | The actor collects email remotely from Exchange/O365 (Outlook Web / EWS) using valid or delegated access, exfiltrating mailbox contents from cloud environments per the Mandiant report and G0059 mapping. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | The actor captures screenshots from compromised hosts per the G0059 mapping. |
| Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | APT42 staged data for exfiltration in password-protected 7-Zip archives before moving it out of the M365/host environment. |

## Command And Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | NICECURL communicates over HTTPS (via curl with --ssl-no-revoke) and TAMECAT over HTTP (expecting Base64-encoded data), using standard web protocols for C2 to blend with normal web traffic. |
| Application Layer Protocol | [T1071](https://attack.mitre.org/techniques/T1071/) | The actor uses standard application-layer protocols for C2 per the G0059 mapping, consistent with the HTTP/HTTPS channels used by NICECURL and TAMECAT. |
| Web Service: Bidirectional Communication | [T1102.002](https://attack.mitre.org/techniques/T1102/002/) | The actor uses legitimate web services for bidirectional C2 and staging: NICECURL/TAMECAT C2 on glitch.me subdomains (prism-west-candy[.]glitch[.]me, accurate-sprout-porpoise[.]glitch[.]me) and payloads on s3[.]tebi[.]io, hiding C2 in traffic to trusted providers. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | The backdoors download additional components: NICECURL's 'Module' command downloads and executes additional files (incl. a datamining module); TAMECAT downloads nconf.txt and a decrypt helper; LNK/curl chains pull payloads from drive-file-share[.]site and s3[.]tebi[.]io. |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | The actor uses non-standard ports for C2 communications per the G0059 mapping. |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | The actor tunnels traffic to conceal C2/lateral movement per the G0059 mapping. |
| Encrypted Channel | [T1573](https://attack.mitre.org/techniques/T1573/) | C2 is encrypted: NICECURL over HTTPS/TLS; TAMECAT AES-encrypts POST content with key kNz0CXiP0wEQnhZXYbvraigXvRVYHk1B and a random 16-char IV sent in a 'Content-DPR' header, layering symmetric crypto over its web channel. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | The actor proxies/anonymizes its access through ExpressVPN exit nodes, Cloudflare-fronted domains and ephemeral VPS servers to obscure the true source of cloud logins and C2. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) | APT42 exfiltrated OneDrive documents and Outlook email to an attacker-controlled OneDrive account masquerading as the victim organization (<victim_org>@outlook.com), using a legitimate cloud storage service as the exfiltration channel to blend with normal cloud traffic. |

## Impact

| Technique | ID | Notes |
|---|---|---|
| Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | Beyond espionage, Phosphorus/Mint Sandstorm sub-operations of this actor have deployed encryption/ransomware (e.g. BitLocker-based) for disruptive/extortion impact per the G0059 mapping. |
