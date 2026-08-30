# Cavern Manticore — ATT&CK Technique Mapping

> Attribution: Iran-nexus — high-medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **34** across **13** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Active Scanning: Vulnerability Scanning | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Actors conduct internet-wide scanning to identify servers vulnerable to the CVEs they weaponize (Log4Shell on Horizon, ProxyShell on Exchange, Fortinet), consistent with early-adopter opportunistic targeting. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Actors obtain and operationalize publicly available tools — Fast Reverse Proxy (FRPC), Plink, Ngrok, Procdump, Impacket wmiexec, DiskCryptor, and SoftPerfect Network Scanner. |
| Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | Actors stage payloads and tooling on a GitHub account (protections20) and on actor-controlled masquerading domains (service-management.tk payload/hosting server) for retrieval by compromised hosts. |
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Actors register and operate C2/payload domains that masquerade as legitimate services (e.g. microsoft-updateserver.cf, service-management.tk, onedriver-srv.ml, symantecserver.co, msupdate.us, gupdate.us). |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Primary initial-access vector: rapid exploitation of newly disclosed high-severity vulnerabilities in internet-facing applications — Log4Shell (CVE-2021-44228 / CVE-2021-45046) against VMware Horizon (Tomcat ws_TomcatService.exe), Microsoft Exchange ProxyShell (CVE-2021-34473/34523/31207) and ProxyLogon (CVE-2021-26855/26857/26858/27065), and Fortinet FortiOS (CVE-2018-13379, CVE-2020-12812, CVE-2019-5591). |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Actors run malicious PowerShell from exploited services (Tomcat/Exchange) to download payloads (System.Net.WebClient), execute reverse shells, harvest credentials, install root certificates, and drive discovery. PowerShell is a core LOLBin throughout the intrusion. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Actors execute .bat scripts (wininet.bat, nvContainerRecovery.bat, setup.bat) and cmd.exe commands for discovery, encryption setup, and lateral execution (e.g. cmd.exe /Q /c quser via Impacket). |
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) | Actors use WMI for discovery (wmic computersystem get domain) and remote execution via Impacket wmiexec (cmd.exe /Q /c quser 1> \\127.0.0.1\ADMIN$\... 2>&1). |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Actors drop ASPX web shells on compromised Exchange/IIS servers following ProxyShell exploitation, using a distinctive naming pattern aspx_[a-z]{13}.aspx (e.g. aspx_okqmeibjplh.aspx) to maintain access. |
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Actors create scheduled tasks for persistence, loading XML task definitions and executing .bat/reverse-proxy payloads. Observed task XMLs include SynchronizeTimeZone.xml and Wininet.xml (with matching Wininet.bat). |
| Create Account: Local Account | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Actors create local accounts for persistence and RDP access via net user /add — observed account names include DefaultAccount (password P@ssw0rd1234) and MSSQL (password _AS_@1394); Secureworks also observed a DefaultUser account. |
| Account Manipulation | [T1098](https://attack.mitre.org/techniques/T1098/) | Actors add their newly created backdoor users to privileged/administrator groups to retain elevated access. |
| Valid Accounts: Default Accounts | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Actors repurpose/rename the built-in DefaultAccount and use created DefaultUser/DefaultAccount identities to blend malicious logons with legitimate-looking default accounts. |
| External Remote Services | [T1133](https://attack.mitre.org/techniques/T1133/) | Actors enable and abuse RDP (adding firewall rule netsh advfirewall firewall add rule name="Terminal Server" dir=in action=allow protocol=TCP localport=3389 and enabling Terminal Server) to establish durable external remote access via their backdoor accounts. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Modify Registry | [T1112](https://attack.mitre.org/techniques/T1112/) | Actors modify the registry to enable plaintext credential capture and RDP: reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f, and modify HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server (and WinStations\RDP-Tcp) to enable RDP; ransom messaging added under HKLM\SOFTWARE\Policies. |
| Subvert Trust Controls: Install Root Certificate | [T1553.004](https://attack.mitre.org/techniques/T1553/004/) | Actors install a custom root certificate via PowerShell to facilitate trusted communications / evade inspection. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Actors rename tooling to legitimate-looking Windows binaries — the FRPC client is dropped as audio.exe, and reverse-proxy/payloads masquerade as dllhost.exe, task_update.exe, user.exe, and CacheTask. |
| System Binary Proxy Execution: Rundll32 | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Actors abuse rundll32.exe to proxy execution of comsvcs.dll's MiniDump function for LSASS credential theft. |

## Impair Defenses

| Technique | ID | Notes |
|---|---|---|
| Disable or Modify Tools | [T1685](https://attack.mitre.org/techniques/T1685/) | Actors disable Microsoft Defender Antivirus real-time protection (via PowerShell/registry) to allow their tools and encryption to run unimpeded. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Actors dump LSASS memory using the signed comsvcs.dll MiniDump function via rundll32 (output file name reversed to ssasl.dmp), and also use Procdump against LSASS. |
| OS Credential Dumping: Security Account Manager | [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Actors dump the SAM registry hive to extract local credential material (observed in TunnelVision Horizon intrusions). |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | Actors enumerate system/domain info using LOLBins — wmic computersystem get domain and related host queries early in the intrusion. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | Actors run whoami, net user, and quser to enumerate the current user and logged-on sessions. |
| Account Discovery: Domain Account | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Actors enumerate mail/domain recipients with PowerShell — e.g. Get-Recipient \| Select Name -ExpandProperty EmailAddresses -first 1 \| Select SmtpAddress \| ft -hidetableheaders — to map accounts on compromised Exchange. |
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Actors scan internal subnets for RDP (port 3389) prior to lateral movement, and use SoftPerfect Network Scanner (netscan / netscan_portable_v621.zip, netscanold.exe) to enumerate hosts and services. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Actors move laterally and deploy tooling (e.g. dropping DiskCryptor on workstations) over interactive RDP sessions using the DefaultAccount/DefaultUser backdoor identities. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Actors stage tooling/collected data in archives (pxy.zip, pxy.rar, 23.zip, netscan_portable_v621.zip) on compromised hosts. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | Actors tunnel C2 and RDP out of victim networks using Fast Reverse Proxy Client (FRPC, dropped as audio.exe), Plink, and Ngrok. FRPC deployment is a signature Cluster B behavior. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | The Fast Reverse Proxy provides a reverse-proxy relay allowing the actors to reach internal services (RDP) from actor-controlled infrastructure, obscuring the true source of connections. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Actors download tooling and payloads to victim hosts via PowerShell (System.Net.WebClient) from actor-controlled domains and a GitHub account (protections20); observed staged archives include pxy.zip, pxy.rar, 23.zip, rsf.exe, and netscan_portable_v621.zip. |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Backdoors and reverse shells communicate over HTTP(S) to actor C2 domains (e.g. microsoft-updateserver.cf as C2, service-management.tk as payload server). |

## Impact

| Technique | ID | Notes |
|---|---|---|
| Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | Signature impact behavior: full-disk-encryption extortion using native BitLocker on servers (enabled via PowerShell / setup.bat, rendering hosts inoperable) and open-source DiskCryptor on workstations (dropped over RDP and launched to encrypt the entire drive). Ransom notes reference low demands (~USD 8,000). |
| Inhibit System Recovery | [T1490](https://attack.mitre.org/techniques/T1490/) | By enabling BitLocker/DiskCryptor full-disk encryption and withholding the recovery/decryption keys, actors render hosts inoperable and block normal recovery until ransom is paid. |
| Financial Theft | [T1657](https://attack.mitre.org/techniques/T1657/) | Actors extort victims for payment (ransom demands around USD 8,000) in exchange for decryption keys after BitLocker/DiskCryptor encryption; ransom messaging is planted (including under HKLM\SOFTWARE\Policies). |
