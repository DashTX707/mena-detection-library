# Cotton Sandstorm (G1009) — ATT&CK Technique Mapping

> Attribution: Iran-nexus — high confidence. MITRE ID: G1009.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **30** across **10** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Search Open Technical Databases | [T1596](https://attack.mitre.org/techniques/T1596/) | ASA uses open technical-database services to find internet-exposed targets: Shodan (shodan[.]io) to identify infrastructure hosting IP cameras and other devices, and ip2location[.]com for network geolocation, when conducting reconnaissance and enumeration against organizations. |
| Gather Victim Identity Information | [T1589](https://attack.mitre.org/techniques/T1589/) | When targeting individuals, ASA profiles identities using people-search, reverse-image and username-check services — knowem[.]com, facecheck[.]id, ancestry[.]com, socialcatfish[.]com, peekyou[.]com, familysearch[.]org — to build dossiers on targets such as Israeli fighter pilots and UAV operators. |
| Gather Victim Identity Information: Email Addresses | [T1589.002](https://attack.mitre.org/techniques/T1589/002/) | ASA harvests target email addresses associated with particular domains using services such as snov[.]io, email-format[.]com and hunter[.]io to seed messaging, phishing and account-targeting. |
| Gather Victim Identity Information: Employee Names | [T1589.003](https://attack.mitre.org/techniques/T1589/003/) | ASA researches potential victims and their roles on social media including Instagram and LinkedIn, and used a Python script to correlate Instagram location data with OpenStreetMap to identify individuals of interest (e.g. Israeli military personnel). |
| Gather Victim Org Information: Determine Physical Locations | [T1591.001](https://attack.mitre.org/techniques/T1591/001/) | ASA searches for physical-location information on Israeli military bases and the Israeli Air Force flight academy, using mapping resources such as Wikimapia[.]org and correlating Instagram geolocation with OpenStreetMap. |
| Gather Victim Network Information: Domain Properties | [T1590.001](https://attack.mitre.org/techniques/T1590/001/) | ASA uses subdomainfinder.c99[.]nl to enumerate subdomains and domain properties of target organizations during reconnaissance. |
| Active Scanning: Scanning IP Blocks | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) | ASA uses the Masscan application to scan IP blocks, including enumerating internet-facing hosts running Real Time Streaming Protocol on TCP/554 across Israel, Gaza and Iran to locate accessible IP cameras. |
| Active Scanning: Vulnerability Scanning | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | ASA runs vulnerability scans against target infrastructure using Acunetix and Burp Suite to identify exploitable web-application flaws prior to exploitation. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Access | [T1650](https://attack.mitre.org/techniques/T1650/) | ASA acquires access to previously-leaked datasets containing account credentials from online resources such as ghostproject[.]fr, reusing them against targets and to enrich victim profiling. |
| Acquire Infrastructure | [T1583](https://attack.mitre.org/techniques/T1583/) | ASA acquires operational infrastructure through commercial VPN providers (Private Internet Access, Windscribe, ExpressVPN, Urban VPN, NordVPN) for anonymization, and procures operational servers via its own fictitious cover-hosting resellers 'Server-Speed' (server-speed[.]com) and 'VPS-Agent' (vps-agent[.]net), themselves upstreamed from BAcloud (Lithuania) and Stark Industries/PQ Hosting (UK/Moldova). |
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | ASA registers persona and operational domains for influence and hosting operations, including cybercourt[.]io, zeusistalking[.]io/net/com, rgud-group[.]net/com, pro-today[.]org, onlinelive[.]info, cyberflood[.]io, Contact-hstg[.]com and il-cert[.]net (used for RAT C2). |
| Acquire Infrastructure: Web Services | [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | ASA stands up and abuses web/cloud services — including its own cover-hosting reseller storefronts (VPS-Agent, Server-Speed) and generative-AI SaaS (Remini, Voicemod, Murf AI, Appy Pie) — to provision servers and produce influence content while providing plausible deniability that malicious infrastructure came from a legitimate provider. |
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | A hallmark of the actor: creating fictitious cover personas and sock-puppet/cover-hacktivist social-media presences — 'Cyber Court' (Telegram @cybercourt_io), 'Cyber Flood', 'For-Humanity', 'Regiment GUD', 'Zeus is Talking', 'Anzu Team', 'Makhlab al-Nasr', 'NET Hunter', 'Emirate Students Movement' — to amplify influence messaging and manufacture apparent grassroots hacktivism. |
| Establish Accounts: Email Accounts | [T1585.002](https://attack.mitre.org/techniques/T1585/002/) | ASA establishes email/messaging accounts under fabricated personas to send intimidation messages (e.g. Contact-HSTG SMS to hostage families) and to operate its cover-hosting reseller businesses (e.g. Info@Vps-Agent[.]Net). |
| Develop Capabilities: Exploits | [T1587.004](https://attack.mitre.org/techniques/T1587/004/) | ASA weaponized an exploit for CVE-2023-38831 (WinRAR) for use in its operations, per the advisory's Resource Development mapping. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | ASA obtains and operates commercially/openly available tooling — Masscan, Acunetix, Burp Suite and SQLMap for scanning and exploitation, and hash-cracking and OSINT services — living off widely-available tools to reduce custom-malware exposure. |
| Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | ASA stages its WezRat payload on actor-controlled web infrastructure (onlinelive[.]info, with C2 fetch/report paths /wez/insert.php and /wez/api.php) so the trojanized 'Google Chrome Installer.msi' can retrieve and beacon to it post-execution. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | ASA exploits internet-facing applications and content-management systems to gain access, notably using SQLMap for SQL-injection against target infrastructure, and seeking mass-compromise opportunities against shared hosting providers or a common CMS used by a sector. Public-facing exploitation also underpinned access to the compromised French dynamic-display provider and IPTV/streaming services. |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | ASA leverages unauthorized/valid access to third-party services for influence delivery — e.g. accessing a US IPTV streaming service to inject 'For-Humanity' messaging, accessing internet-facing IP-camera streams, and accessing the compromised French dynamic-display provider to push montages. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | ASA induces victims to run a trojanized 'Google Chrome Installer.msi' that masquerades as a legitimate Chrome security-patch installer; the altered MSI installs Chrome but then executes the embedded, heavily-obfuscated 'bd.exe' (WezRat) RAT. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | The WezRat 'bd.exe' RAT is heavily obfuscated and requires a runtime de-obfuscation key passed on the command line (observed value '8765') to decode its embedded configuration, including the C2 web-server address, impeding static analysis. |
| Masquerading: Match Legitimate Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | ASA disguises malicious artifacts and personas as legitimate: the RAT dropper is named 'Google Chrome Installer.msi' and performs a real Chrome install to appear benign; the C2 domain il-cert[.]net (connect.il-cert[.]net) mimics a security/CERT resource; and the 'Regiment GUD' persona impersonates the real French far-right group 'GUD'. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | ASA accesses victim infrastructure via automated password-guessing attempts against exposed accounts and services. |
| Brute Force: Password Cracking | [T1110.002](https://attack.mitre.org/techniques/T1110/002/) | ASA cracks obtained password hashes offline using online resources such as crackstation[.]net, hashes[.]com and md5hashing[.]net. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | Upon execution, the WezRat RAT collects basic system information about the infected computer to report to its C2, per the advisory's description of the 'bd' program's behavior. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | The WezRat RAT beacons over HTTP web protocols to its C2, checking in for tasking and returning collected data — observed communicating to http://onlinelive[.]info/wez/insert.php and http://onlinelive[.]info/wez/api.php (and C2 host connect.il-cert[.]net), with the C2 host address decoded from the obfuscated config at runtime. It can persist by being added to the Windows Startup directory. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | The trojanized MSI retrieves and executes the WezRat payload, and the RAT can pull additional instructions/content from its C2 web server — transferring tooling into the victim environment after initial execution. |
| Remote Access Tools | [T1219](https://attack.mitre.org/techniques/T1219/) | ASA deploys the WezRat remote access trojan (mapped to T1219 in the advisory's C2 table) which collects basic system information, checks in to a specified web server when run from the command line, and awaits interactive tasking — providing hands-off-keyboard remote control of infected hosts. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) | Central to the actor's hack-and-leak model: after stealing data ASA exfiltrates and publishes it (and harvested IP-camera content) via actor-controlled web services and servers, making stolen material available to 'clients' and leaking it to inflict reputational/psychological damage. |

## Impact

| Technique | ID | Notes |
|---|---|---|
| Defacement: External Defacement | [T1491.002](https://attack.mitre.org/techniques/T1491/002/) | As part of its cyber-enabled influence operations, ASA defaces and hijacks externally-visible surfaces to display crafted propaganda — e.g. injecting Israel-Hamas-war messaging into a compromised US IPTV stream ('For-Humanity'), pushing anti-Israel photo montages via a compromised French dynamic-display provider during the 2024 Olympics, and website defacements against Israeli targets. |
