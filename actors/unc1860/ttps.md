# UNC1860 — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **30** across **12** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | UNC1860 maintains an unusually large, purpose-built library of custom passive implants, loaders, controllers and drivers — TEMPLEDOOR, TEMPLEPLAY, TEMPLELOCK, TEMPLEDROP, OATBOAT, TOFULOAD, TOFUDRV, VIROGREEN, STAYSHANTE, BASEWALK, SASHEYAWAY, FACEFACE, SPARKLOAD, OBFUSLAY, CRYPTOSLAY and TUNNELBOI — reflecting deep, in-house development including kernel-component reverse engineering. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | TEMPLEDROP repurposes a legitimate signed Iranian antivirus product's Windows filesystem filter driver ('Sheed AV') as its own defensive tooling — obtaining and weaponizing a trusted third-party driver to protect deployed malware files from modification or removal. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | UNC1860 opportunistically exploits vulnerable internet-facing servers to gain initial access. The VIROGREEN framework specifically exploits Microsoft SharePoint via CVE-2019-0604, then deploys the STAYSHANTE webshell and BASEWALK backdoor to establish a foothold. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Native API | [T1106](https://attack.mitre.org/techniques/T1106/) | Multiple UNC1860 components (TEMPLELOCK, TOFULOAD, TOFUDRV) drive functionality through undocumented I/O control (IOCTL) commands issued via native Windows APIs (e.g. DeviceIoControl against HTTP.sys and driver devices), executing capability directly through the OS/kernel interface rather than higher-level tooling. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | The TEMPLEPLAY controller instructs TEMPLEDOOR to execute operator commands via cmd.exe on the compromised host, giving GUI-driven interactive command execution on servers. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | STAYSHANTE (disguised as legitimate Windows server files) and BASEWALK are deployed on compromised internet-facing servers as webshells/backdoors under the VIROGREEN framework, providing persistent operator access and staging of follow-on passive implants. |
| Server Software Component: IIS Components | [T1505.004](https://attack.mitre.org/techniques/T1505/004/) | UNC1860's passive main-stage implants (TEMPLEDOOR, TOFULOAD) install as HTTP request handlers on compromised internet-facing IIS/HTTP servers, listening for inbound operator traffic on the server's existing web bindings rather than opening new outbound channels. |
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | UNC1860's drivers and implants are installed as system services/drivers to survive reboot on compromised servers, including registration of the kernel drivers TOFUDRV / TEMPLEDROP (repurposed AV filter driver) as loaded system components. |

## Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Exploitation for Privilege Escalation | [T1068](https://attack.mitre.org/techniques/T1068/) | UNC1860 leverages Windows OS and kernel-component exploitation, loading malicious/repurposed drivers (TOFUDRV, TEMPLEDROP) to obtain kernel-mode, local-system-level execution on compromised servers — reflecting deep reverse-engineering of Windows kernel internals. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Obfuscated Files or Information: Software Packing | [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | The OBFUSLAY utility obfuscates UNC1860 payloads, and passive implants delivered via SASHEYAWAY are packed/obfuscated to keep detection rates low against static AV signatures. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | CRYPTOSLAY encrypts UNC1860 payloads at rest so that on-disk artifacts (loader stages, implant payloads carried by SASHEYAWAY/OATBOAT) are stored encrypted/encoded and only decrypted in memory at runtime. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | At runtime UNC1860 loaders reverse their own encoding — OATBOAT and the SASHEYAWAY dropper decode/decrypt embedded shellcode payloads (CRYPTOSLAY/OBFUSLAY-protected) before executing them in memory. |
| Reflective Code Loading | [T1620](https://attack.mitre.org/techniques/T1620/) | OATBOAT is a loader that executes shellcode payloads directly in memory, and SASHEYAWAY enables execution of passive backdoors (FACEFACE, SPARKLOAD) with low detection by loading them reflectively rather than dropping executables to disk. |
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) | OATBOAT-delivered shellcode and the kernel-mode drivers (TOFUDRV / WINTAPIX-overlap) inject and execute payloads within privileged host processes, running the passive backdoor logic inside legitimate processes rather than as standalone executables. |
| Rootkit | [T1014](https://attack.mitre.org/techniques/T1014/) | UNC1860 operates from kernel mode using malicious Windows drivers — TOFUDRV (overlapping the WINTAPIX driver family) — and the repurposed Sheed AV filter driver (TEMPLEDROP), demonstrating deep kernel-component reverse-engineering knowledge and providing stealthy, high-privilege execution and file-hiding/anti-tamper. |
| Exploitation for Defense Evasion | [T1211](https://attack.mitre.org/techniques/T1211/) | TEMPLEDROP repurposes a legitimate signed Iranian AV filesystem filter driver to run in kernel mode and protect UNC1860's deployed files from modification or deletion — abusing a trusted driver to shield malware from AV/EDR and analyst remediation. |
| Masquerading: Match Legitimate Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | STAYSHANTE is disguised as legitimate Windows server files, and TEMPLEDROP masquerades as / repurposes a legitimate signed antivirus driver — blending UNC1860 artifacts into expected system components by name and location. |

## Impair Defenses

| Technique | ID | Notes |
|---|---|---|
| Impair Defenses: Disable or Modify Windows Event Log | [T1685.001](https://attack.mitre.org/techniques/T1685/001/) | TEMPLELOCK is a .NET defense-evasion utility that terminates and later restarts the Windows Event Log service (via undocumented IOCTL commands), suppressing event logging while UNC1860 operates and then resuming it to reduce forensic traces. |
| Impair Defenses | [T1685](https://attack.mitre.org/techniques/T1685/) | Beyond event-log tampering, UNC1860's tooling as a whole degrades host defenses: TEMPLEDROP uses a kernel driver to protect malware files from AV/EDR removal, and passive-implant design plus custom crypto/obfuscation are engineered to keep detection rates low — a defense-impairment posture spanning the toolset. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | The VIROGREEN framework includes vulnerability-scanning functionality used to identify exploitable (SharePoint/CVE-2019-0604) services on reachable hosts prior to exploitation and implant deployment. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | TUNNELBOI manages RDP connections into and across the victim environment, enabling lateral movement to additional hosts and providing reliable interactive remote access that UNC1860 hands off to other Iranian operators. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Via TEMPLEPLAY's file-download capability, UNC1860 collects files of interest from the local filesystem of compromised servers for retrieval by operators. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Traffic Signaling | [T1205](https://attack.mitre.org/techniques/T1205/) | UNC1860's signature tradecraft: passive implants (TEMPLEDOOR, TOFULOAD, TOFUDRV, FACEFACE, SPARKLOAD) do NOT initiate outbound connections; they sit dormant and act on inbound operator commands arriving from volatile/varied source infrastructure, intercepted via undocumented HTTP.sys IOCTLs before the request reaches the normal application/logging layer. This trigger-on-inbound-traffic design defeats egress-based network detection. |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | The passive implants communicate over HTTP(S) on the compromised server's existing web listener, receiving operator commands and returning results in HTTP responses. TEMPLEDOOR/TOFULOAD interact directly with the HTTP.sys kernel stack via undocumented IOCTLs to grab requests below IIS, so the C2 blends into normal web traffic and bypasses IIS request logging. |
| Non-Application Layer Protocol | [T1095](https://attack.mitre.org/techniques/T1095/) | TOFULOAD and the TOFUDRV kernel driver receive commands via undocumented I/O control (IOCTL) commands issued to a driver device rather than a standard application protocol, providing a covert command path that user-mode network monitoring does not observe. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | The TEMPLEPLAY controller supports establishing HTTP proxy connections through TEMPLEDOOR to bypass network boundaries, letting operators route traffic to otherwise unreachable internal hosts via the compromised server. |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | TUNNELBOI is a network controller that manages RDP connections and remote-host access, tunnelling remote-access traffic through the compromised environment to reach internal hosts and support access hand-off to downstream actors. |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | In addition to HTTPS transport, UNC1860 protects payloads and C2 content with custom encryption via the CRYPTOSLAY utility (paired with OBFUSLAY obfuscation), adding a symmetric-crypto layer inside the web channel to defeat content inspection. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | The TEMPLEPLAY controller supports uploading and downloading files through TEMPLEDOOR, allowing UNC1860 to stage additional tooling and payloads onto compromised servers over the passive C2 channel. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | TEMPLEPLAY retrieves collected files from TEMPLEDOOR back to operators over the same inbound HTTP(S) passive C2 channel, exfiltrating data through the implant's response traffic. |
