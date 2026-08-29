# Scarred Manticore (Storm-0861) — ATT&CK Technique Mapping

> Attribution: Iran-nexus (MOIS) — high confidence. No official MITRE ATT&CK Group ID (Storm-0861 / DEV-0861).
> Enriched from the tracker seed + Check Point LIONTAIL reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **28** across **9** tactics. Server-side / memory-resident tradecraft (LIONTAIL passive HTTP.sys implant, web shells).

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Scarred Manticore develops and iteratively refines a custom, in-house toolset over several years: the LIONTAIL passive loader/backdoor and its web-shell and named-pipe variants, the LIONHEAD web forwarder, the FOXSHELL web-shell family (evolved from an open-source Tunna base into custom XORO/Bsae64/compiled versions), and the SDD .NET passive backdoor. Check Point ties these together (and to WINTAPIX) through shared obfuscation, a shared XOR-with-first-byte string-encryption scheme, shared backdoor command types, and shared heartbeat strings — indicating a common developer/build framework. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | The actor adopts and customizes open-source offensive tooling: the Tunna HTTP-tunnelling web shell (used as the FOXSHELL lineage's origin, customized to 'Tunna v1.1g' with added XOR encryption) and the Donut shellcode-generation project (used by the WINTAPIX driver to produce position-independent shellcode that loads .NET assemblies from memory). |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Scarred Manticore gains initial access by exploiting Internet-facing Windows servers. The May 2021 attack on the Albanian government began with exploitation of an Internet-facing Microsoft SharePoint server, on which the actor deployed the compiled FOXSHELL web shell (ClientBin.aspx) to proxy external connections and enable lateral movement. The actor's toolset is broadly oriented around compromised Internet-facing IIS/Exchange/SharePoint servers. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Hijack Execution Flow: DLL Search Order Hijacking | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | When installed as a DLL, LIONTAIL abuses 'phantom' DLL hijacking: the implant is dropped to C:\Windows\System32 as wlanapi.dll or wlbsctrl.dll — DLL names that do not exist by default on Windows Server installations. wlbsctrl.dll is loaded at the start of the 'IKE and AuthIP IPsec Keying Modules' service; wlanapi.dll is loaded when the actor enables the 'Extensible Authentication Protocol' (Eaphost) service, or directly by processes such as Explorer.exe. LIONHEAD is installed the same way. |
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | To trigger loading of its phantom hijack DLLs at boot, the actor enables specific Windows services that are disabled by default and that depend on the target DLL — e.g. running 'sc.exe config Eaphost start=auto' followed by 'sc.exe start Eaphost' to have the Extensible Authentication Protocol service load the malicious wlanapi.dll, and relying on the IKE and AuthIP IPsec Keying Modules service to load wlbsctrl.dll. LIONTAIL and LIONHEAD are also described as installed as services. |
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Scarred Manticore's core persistence on compromised servers is a lineage of web shells: a customized Tunna v1.1g tunnelling shell; the FOXSHELL family (XORO, Bsae64, and compiled App_Web_*.dll versions listening on relative path ~/1.aspx, e.g. ClientBin.aspx used against the Albanian government); a heavily-obfuscated Xsl Exec Shell (XML/XSL transform) variant; the LIONTAIL .NET web shell; and web shells previously attributed indirectly to OilRig. All retain class/method obfuscation and XOR-with-first-byte string encryption. |
| Server Software Component: IIS Components | [T1505.004](https://attack.mitre.org/techniques/T1505/004/) | The SDD standalone .NET passive backdoor (masquerading as System.Drawing.Design.dll) uses the IIS ServerManager class (System.Web.Administration) to enumerate the sites and bindings configured on the IIS server and programmatically build the set of URL prefixes it will listen on via HttpListener — installing itself as an IIS-server-resident .NET component to observe/handle HTTP requests. The WINTAPIX driver's final payload uses the same IIS ServerManager mechanism (which is why it only targets IIS servers). |

## Stealth

| Technique | ID | Notes |
|---|---|---|
| Masquerading: Match Legitimate Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | The actor disguises implants as legitimate software/system components: standalone LIONTAIL executables are disguised as 'Cyvera Console', a component of Palo Alto Cortex XDR; the SDD backdoor masquerades as the legitimate .NET library System.Drawing.Design.dll; and phantom hijack DLLs use trusted system DLL names (wlanapi.dll, wlbsctrl.dll) placed in System32. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Payloads and configurations are stored encoded/encrypted at rest: LIONTAIL one-byte-XOR-decrypts its configuration structure at runtime; received payloads are base64-decoded then XOR-decrypted; FOXSHELL embeds its encryption module (XORO.dll / Base64.dll) as a base64-encoded .NET DLL inside the web-shell body; the WINTAPIX driver carries an encrypted .NET payload. |
| Obfuscated Files or Information: Software Packing | [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | The .NET web shells and backdoors retain heavy class-, method- and string-level obfuscation, and the final WINTAPIX .NET payload is additionally obfuscated with a commercial obfuscator on top of the familiar class/method/string obfuscation. URL prefixes and paths are chosen to mimic legitimate services so malware communication blends into normal server traffic. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | At runtime the implants reverse their own encoding: LIONTAIL base64-decodes then XOR-decrypts each received C2 payload before executing it in memory and one-byte-XOR-decrypts its configuration; FOXSHELL base64-decodes and loads its embedded encryption DLL and decrypts request/response Packages; the SDD backdoor base64+XOR-decodes POST-body commands (and base64-decodes the 'Vet' parameter value) before executing them. |
| Reflective Code Loading | [T1620](https://attack.mitre.org/techniques/T1620/) | The framework runs payloads directly in memory rather than from disk: LIONTAIL creates a new thread and executes received shellcode in-memory (payload TYPE=1 runs another shellcode; nested shellcodes culminate in a fingerprinting payload), the compiled FOXSHELL loads an App_Web_*.dll via System.Reflection.Assembly.Load and invokes ProcessRequest, and WINTAPIX injects Donut-generated position-independent shellcode that loads and executes an encrypted .NET assembly from memory. |
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) | The WINTAPIX kernel-mode driver enumerates user-mode processes to find one running with local-system privileges and injects an embedded Donut-generated shellcode into it; that shellcode then loads and executes the encrypted .NET payload (combining SDD-backdoor and FOXSHELL functionality). LIONTAIL likewise runs received shellcode in a newly created thread in its host process. |
| Rootkit | [T1014](https://attack.mitre.org/techniques/T1014/) | WINTAPIX is a kernel-mode driver (Fortinet-named; tracked by Check Point via version SRVNET2) used to operate from the kernel — enumerating user-mode processes and injecting shellcode into a system-privileged process from kernel level, providing stealthy, high-privilege execution consistent with rootkit-enabling functionality. |
| Impair Defenses: Disable or Modify Windows Event Log | [T1685.001](https://attack.mitre.org/techniques/T1685/001/) | FOXSHELL version 1.7 (the variant carried in the WINTAPIX driver payload) includes an Event Log bypass implemented via the known technique of suspending the EventLog Service's threads, preventing Windows event logging while the implant operates. |

## Command And Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | LIONTAIL's primary variant is a PASSIVE backdoor: instead of beaconing out, it listens for inbound attacker HTTP(S) requests on registered URL prefixes and executes received shellcode, returning results in the HTTP response. Critically, it does NOT use IIS or the HTTP Server API — it interacts directly with the low-level HTTP.sys kernel driver via undocumented IOCTLs (UlCreateServerSessionIoctl, UlCreateUrlGroupIoctl, UlAddUrlToUrlGroupIoctl, UlReceiveHttpRequestIoctl, UlSendHttpResponseIoctl), specifically to avoid the IIS/HTTP-API layers that security tools monitor. URL prefixes mimic legitimate services (http://+:80/Temporary_Listen_Addresses/, https://+:443/autodiscover/autodiscovers/, /ews/exchanges/, /ews/ews/). The SDD backdoor similarly uses the .NET HttpListener class as an HTTP-request-handling C2 listener supporting command execution and file upload/download. |
| Non-Application Layer Protocol | [T1095](https://attack.mitre.org/techniques/T1095/) | A named-pipe variant of LIONTAIL, intended for internal servers with no access to the public web, receives its shellcode payloads over a named pipe instead of HTTP. It creates a named pipe (observed as \\.\pipe\test-pipe) using a security descriptor string 'D:(A;;FA;;;WD)' that grants File All Access to Everyone, and uses standard kernel32.dll APIs (CreateNamedPipe, ReadFile/WriteFile). The encryption scheme and in-memory shellcode payload structure are identical to the HTTP version. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | FOXSHELL (originating from the open-source Tunna framework) is a web-shell proxy that lets the actor connect from outside to any service on the compromised host — including services blocked at the firewall — because all external communication is tunnelled through the web shell over HTTP. The IP/port of the target service is supplied in a configuration ('Config'/'RDPconfig' PackageType), and Tunna/FOXSHELL is frequently used to proxy RDP connections into the victim environment. |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | FOXSHELL tunnels arbitrary TCP service traffic over its HTTP web-shell channel: it opens a new socket to a remote machine specified in its configuration and relays 'Data'-type packages between that socket and the HTTP channel, encapsulating firewall-blocked internal service traffic (notably RDP) inside HTTP requests/responses. |
| Proxy: External Proxy | [T1090.002](https://attack.mitre.org/techniques/T1090/002/) | The LIONHEAD web forwarder, deployed on compromised Exchange servers and installed via the same phantom DLL hijacking technique as LIONTAIL, registers listen_urls (e.g. https://+:443/<redacted>/) and, for each request, copies the content type, cookie, and body and forwards them to a configured forward_server/forward_path/forward_port (localhost:444 /ews/exchange.asmx). It returns the EWS response to the original requester — acting as an external-facing proxy that bypasses restrictions on external EWS connections and conceals that the true consumer of the Exchange Web Services data is external. |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | Across the toolset, C2 request/response bodies are protected with a custom symmetric scheme rather than relying on TLS alone: LIONTAIL base64-decodes the request then XORs the whole payload with the first byte of the data; responses are XOR-encoded with a randomly chosen key byte that is prepended to the result before base64 encoding. The web shells (Tunna v1.1g, FOXSHELL XORO/Bsae64, SDD backdoor) use the same XOR-with-first-byte(s) scheme (with AES additionally in compiled FOXSHELL), sometimes via embedded encryption DLLs (XORO.dll, Base64.dll). |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | The SDD backdoor supports 'Upload' (writes an operator-supplied file to a specified path on the infected system) and 'Rundll' (loads an operator-delivered additional .NET assembly and runs it), and LIONTAIL receives arbitrary shellcode/payloads from the operators — allowing staging of further tooling onto compromised servers. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Email Collection: Remote Email Collection | [T1114.002](https://attack.mitre.org/techniques/T1114/002/) | Scarred Manticore's LIONHEAD forwarder is deployed on Exchange servers to reach Exchange Web Services (EWS) endpoints, used to bypass external-EWS restrictions and conceal external consumption of mailbox data — enabling email exfiltration. The DEV-0861 cluster (assessed to align with Scarred Manticore) was publicly exposed for email exfiltration from multiple Middle Eastern organizations (Kuwait, Saudi Arabia, Turkey, UAE, Jordan). |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | The WINTAPIX kernel driver enumerates the system's user-mode processes in order to identify a suitable target process running with local-system privileges into which it can inject its Donut shellcode. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | A LIONTAIL fingerprinting payload (delivered as a nested shellcode) profiles the host: Computer Name (GetComputerNameW), Domain Name (GetEnvironmentVariableA), 64-bit flag and processor count (GetNativeSystemInfo), physical RAM (GetPhysicallyInstalledSystemMemory), and data read from the CurrentVersion, SecureBoot\State and System\Bios registry keys — returning the values plus per-API last-error codes to the operators. |
| Software Discovery | [T1518](https://attack.mitre.org/techniques/T1518/) | The SDD backdoor uses the .NET ServerManager (IIS) class to extract the list of sites and bindings hosted by the IIS server, in order to build a matching HashSet of URL prefixes to listen on — enumerating installed server-application configuration to blend its listener into legitimate sites. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | The SDD backdoor executes operator commands via the Windows command shell: on a POST request carrying a 'Vet' parameter it base64-decodes the value and runs it with 'cmd /c', and its 'Command' capability executes a process with a specified argument. cmd.exe execution is also among the backdoor's core command set. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | The SDD backdoor's 'Download' command sends a specified file from the infected system back to the operators over the same encrypted HTTP C2 channel; more broadly, Scarred Manticore/DEV-0861 leveraged its server access to systematically exfiltrate data — including email exfiltration via EWS/LIONHEAD — from victims across the Middle East over months. |
