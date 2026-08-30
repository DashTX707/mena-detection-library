# Sea Turtle — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium-high confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **33** across **11** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Gather Victim Network Information: DNS | [T1590.002](https://attack.mitre.org/techniques/T1590/002/) | Actors map the DNS architecture of targets and their upstream registrars/registries/DNS providers to identify which third-party DNS operator to compromise in order to hijack resolution for the ultimate victim. |
| Gather Victim Org Information | [T1591](https://attack.mitre.org/techniques/T1591/) | Actors select deliberate victims aligned to Turkish state interest (Kurdish/PKK-affiliated organizations, Cypriot/Greek and MENA government and telecom), indicating targeted organizational research rather than opportunistic scanning. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: DNS Server | [T1583.002](https://attack.mitre.org/techniques/T1583/002/) | Actors stood up actor-controlled nameservers (ns1/ns2.intersecdns.com and ns1/ns2.lcjcomputing.com, resolving to 95.179.150.101) to serve falsified DNS responses to victim queries after hijacking records. |
| Acquire Infrastructure: Virtual Private Server | [T1583.003](https://attack.mitre.org/techniques/T1583/003/) | Actors rented a large set of VPS instances (26 documented MitM IPs across multiple hosting providers and regions) to host man-in-the-middle nodes that impersonate legitimate victim services. |
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Actors register domains used for nameserver and C2 infrastructure (e.g. intersecdns.com, lcjcomputing.com, boord.info, systemctl.network) to blend with legitimate DNS/service naming. |
| Obtain Capabilities: Digital Certificates | [T1588.004](https://attack.mitre.org/techniques/T1588/004/) | Actors obtained CA-signed X.509 certificates (Let's Encrypt, Comodo/Sectigo) — and used self-signed certs — for victim domains so the MitM node presents a trusted certificate and avoids browser TLS warnings during credential interception. |
| Stage Capabilities: Install Digital Certificate | [T1608.003](https://attack.mitre.org/techniques/T1608/003/) | Actors install the obtained/forged certificates on the MitM VPS nodes so that intercepted TLS sessions to spoofed login portals appear valid to victims. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Actors obtain and operationalize public tooling — a modified Socat for tunnelling, the Adminer web DB tool, and SnappyTCP (based on a since-removed public GitHub project). |
| Compromise Infrastructure: DNS Server | [T1584.002](https://attack.mitre.org/techniques/T1584/002/) | Signature tradecraft: rather than attacking the ultimate victim directly, actors compromise third-party DNS registrars, ccTLD registries and DNS providers, then alter the victim's NS and A records at the compromised operator to redirect resolution to actor-controlled MitM nodes. TTL is frequently lowered to as little as 1 second to limit caching and allow rapid record reversion. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Primary initial-access vector against intermediary providers and victims: exploitation of known CVEs on internet-facing systems — Cisco ASA directory traversal (CVE-2018-0296), Cisco IOS/switch and ISR RCEs (CVE-2017-3881, CVE-2017-6736), Apache Tomcat RCE (CVE-2017-12617), Drupalgeddon2 (CVE-2018-7600), phpMyAdmin PHP injection (CVE-2009-1151) and Shellshock (CVE-2014-6271). Consistent with reporting on Citrix/NetScaler and webmail/VPN RCE exploitation. |
| External Remote Services | [T1133](https://attack.mitre.org/techniques/T1133/) | Actors abuse internet-facing remote services for access, including SSH logons originating from commercial VPN providers and reuse of hosting/cPanel access to reach victim webservers. |
| Trusted Relationship | [T1199](https://attack.mitre.org/techniques/T1199/) | By compromising DNS providers, registrars, registries and IT/telecom service providers, actors abuse the trust those intermediaries hold to reach downstream ultimate victims (supply-chain / trusted-relationship access). |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | Actors use valid credentials — including a compromised-but-legitimate cPanel hosting account (2023 case) and credentials harvested via DNS-hijack MitM interception — to authenticate to victim systems. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Exploitation for Client Execution | [T1203](https://attack.mitre.org/techniques/T1203/) | Actors leverage exploitation of vulnerable server/appliance software (the CVEs above) to achieve code execution on internet-facing intermediary and victim systems. |
| Command and Scripting Interpreter: Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Actors execute commands via the Unix/Bash shell on compromised Linux/Unix webservers to deploy SnappyTCP, run Socat, stage tools and copy/collect data. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Actors deploy the custom SnappyTCP reverse-shell webshell (MITRE S1163) into web-accessible directories on Linux/Unix victim servers for persistence and basic C2. Two variants exist: one uses OpenSSL to create a TLS-secured channel, the other sends requests in cleartext. On start it reads a config file with a C2 domain and port and issues an HTTP GET for the URI 'sy.php'; it acts on the response only if the server returns header 'X-Auth-43245-S-20' and the body is of sufficient size and does not begin with '@'. |
| Valid Accounts: Local Accounts | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Actors reuse compromised local accounts (e.g. the hijacked cPanel hosting account) to maintain access to victim webservers across sessions. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Hide Artifacts: Ignore Process Interrupts | [T1564.011](https://attack.mitre.org/techniques/T1564/011/) | Actors launch SnappyTCP with NoHup so the reverse shell keeps running after the initiating SSH/web session closes, detaching it from session hang-up signals. |
| Obfuscated Files or Information: Compile After Delivery | [T1027.004](https://attack.mitre.org/techniques/T1027/004/) | SnappyTCP is delivered/handled as source and compiled on the victim host (the OpenSSL-linked and cleartext variants are built locally), reducing static-detection surface for the delivered payload. |

## Impair Defenses

| Technique | ID | Notes |
|---|---|---|
| Clear Linux or Mac System Logs | [T1685.006](https://attack.mitre.org/techniques/T1685/006/) | Following SSH sessions, actors overwrite/clear Linux system logs under /var/log as an anti-forensic measure to remove evidence of their activity. |
| Prevent Command History Logging | [T1690](https://attack.mitre.org/techniques/T1690/) | Actors unset/clear the Bash command-history file and the MySQL history file to prevent their commands from being recorded during interactive sessions. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Adversary-in-the-Middle | [T1557](https://attack.mitre.org/techniques/T1557/) | Signature credential-access behavior: after DNS records are hijacked, victim traffic is transparently proxied through actor-controlled MitM nodes presenting valid TLS certificates. The nodes impersonate VPN concentrators, webmail and other login portals to capture submitted usernames and passwords before relaying traffic onward. |
| Modify Authentication Process | [T1556](https://attack.mitre.org/techniques/T1556/) | Actors interpose spoofed login portals (served from MitM nodes) into the authentication flow of legitimate victim services, harvesting credentials as users authenticate to what appears to be the genuine portal. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data from Information Repositories: Databases | [T1213.006](https://attack.mitre.org/techniques/T1213/006/) | Actors install the Adminer web-based database management tool in public web directories to browse and extract data from victim MySQL/other databases. |
| Email Collection: Local Email Collection | [T1114.001](https://attack.mitre.org/techniques/T1114/001/) | Actors collect victim e-mail archives from the compromised mail/web host — a primary espionage objective — copying the mailbox archive for staging and retrieval. |
| Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Actors use tar to compress collected e-mail archives prior to exfiltration. |
| Data Staged: Remote Data Staging | [T1074.002](https://attack.mitre.org/techniques/T1074/002/) | Actors copy the tar'd e-mail archive into the public web directory of the compromised website so it is directly reachable from the internet for later retrieval. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Actors collect files and data of interest from the local compromised system in support of espionage objectives. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | SnappyTCP communicates over HTTP: on startup it issues an HTTP GET for URI 'sy.php' to its configured C2 and keys off the response header 'X-Auth-43245-S-20'; channels are established to C2 domains over port 443. |
| Encrypted Channel: Asymmetric Cryptography | [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | One SnappyTCP variant uses OpenSSL to wrap its C2 channel in TLS, encrypting the reverse-shell traffic (over port 443) to blend with normal HTTPS and defeat inspection. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | Actors use a modified Socat (retrieved from actor infrastructure at 193.34.167.245/c00n/socat) to relay/tunnel connections and proxy C2, obscuring the true source of traffic. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) | Actors exfiltrate the staged e-mail archive by downloading it directly over HTTP/HTTPS from the internet-accessible public web directory of the compromised host (web-accessible file retrieval). |
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Actors can also move collected data out over the SnappyTCP/Socat C2 channel established to their infrastructure. |
