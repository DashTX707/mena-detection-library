# Hunt: UNC1860 passive HTTP.sys/IIS inbound listener — TEMPLEDOOR/TOFULOAD triggered by inbound operator traffic with NO matching outbound beacon

- **Hypothesis:** If a UNC1860 passive main-stage implant (TEMPLEDOOR, TOFULOAD, TOFUDRV) is resident on one of our internet-facing IIS/HTTP servers, then — because it *never beacons out* and instead sits dormant until an inbound operator request arrives — the evidence is not an egress connection but three stacked host-state anomalies: (a) an HTTP.sys URL reservation / registered UrlGroup owned by a non-IIS, non-service-account process with no matching IIS site binding, (b) a driver or user-mode process consuming *undocumented* HTTP.sys IOCTLs via `DeviceIoControl` to grab requests below the IIS/HTTP-API logging layer, and (c) an inbound-triggered child process (`w3wp.exe`/`System`/an implant host spawning `cmd.exe` or touching the filesystem) that has **no corresponding outbound C2 connection** in flow data. A single one of these is thin; the finding is the inbound-triggered execution *stacked on* an unexplained listener with the beacon conspicuously absent.
- **ATT&CK:**
  - T1205 — Traffic Signaling (command-and-control) — the defining tradecraft: implants act on inbound operator traffic arriving from volatile source infrastructure, intercepted via undocumented HTTP.sys IOCTLs before the request reaches the normal application/logging layer; no outbound beacon exists to catch
  - T1071.001 — Application Layer Protocol: Web Protocols (command-and-control) — C2 rides the server's existing 80/443 web listener, receiving commands and returning results in HTTP responses, bypassing IIS request logging
  - T1095 — Non-Application Layer Protocol (command-and-control) — TOFULOAD/TOFUDRV receive commands via undocumented IOCTLs issued to a driver device rather than a standard application protocol, a covert path user-mode network monitoring does not observe
  - T1106 — Native API (execution) — capability is driven directly through `DeviceIoControl` against HTTP.sys / a custom driver device (undocumented IOCTLs) rather than higher-level tooling

- **Actor procedure:** UNC1860's signature design. Passive implants do not initiate outbound connections; they install as HTTP request handlers on the compromised server's existing web bindings and interact directly with the HTTP.sys kernel stack via undocumented IOCTLs (issued through `DeviceIoControl`) to receive inbound operator traffic *below* IIS — so the C2 blends into normal web traffic and leaves no IIS log entry and no `W3SVC` event. TOFULOAD and the TOFUDRV kernel driver take commands via IOCTLs to a driver device, a channel with essentially no standard network telemetry. The operator (TEMPLEPLAY controller) reaches TEMPLEDOOR over this inbound-only channel; source infrastructure is volatile and varied by design, so there is no durable IP/domain to block.
- **Why a hunt, not a rule:** this is *the* reason a conventional SIEM/network rule is blind — there is no outbound beacon, no egress connection, no domain/IP IOC (UNC1860 publishes none, by design), and by driving HTTP.sys below the HTTP Server API the implant leaves no IIS request log. Ports 80/443 on a server are expected, so a network rule sees nothing anomalous. The durable, hard-to-change observable (Summiting Level 4–5: technique-core — abandoning HTTP.sys URL registration / IOCTL interception means abandoning the passive-listener design itself) is the *state + relational anomaly*: a URL ACL / UrlGroup no legitimate IIS site or service explains, owned by an unexpected process, that fires child execution on inbound traffic while holding zero outbound sockets. Separating that from legitimate self-hosted WCF/HttpListener apps requires per-server baselining of which processes are *supposed* to hold reservations — analyst correlation, not a threshold. The absence-of-beacon correlation is inherently judgement-heavy → hunt.

## Data sources required

- Host-collected `netsh http show urlacl` and `netsh http show servicestate` output (or the `HTTP\Parameters\UrlAclInfo` registry / Http.sys config store) — periodic per-server snapshots diffed against a golden baseline; `servicestate` maps registered UrlGroups → owning PIDs
- Sysmon EID 1 (process create) + parent lineage — `w3wp.exe` / `System` / implant host spawning `cmd.exe`, and the inbound-triggered execution timestamp
- Network flow / connection telemetry (Zeek conn, EDR network events, firewall) to establish the **negative**: no outbound connection from the server process around the execution event
- EDR loaded-module / handle telemetry to attribute a URL reservation or `HTTP.sys` `\Device\Http\ReqQueue` handle to an owning process; DeviceIoControl / IOCTL instrumentation where available

## Query starting point

Platform: `netsh / PowerShell host procedure` (no SIEM query fits the HTTP.sys state — collect it, then diff), then correlate in Sentinel/Splunk

```
# Run per server (scheduled), ship output to the SIEM as a field-extracted event:
netsh http show urlacl        > urlacl_%COMPUTERNAME%.txt
netsh http show servicestate  > svcstate_%COMPUTERNAME%.txt   # registered URL groups + owning PIDs

# PowerShell: flag reservations owned by a process that is NOT w3wp.exe / a known service,
# with no matching IIS site binding
Import-Module WebAdministration
$iisPrefixes = (Get-WebBinding | ForEach-Object { $_.bindingInformation })
(netsh http show servicestate) -join "`n" -split '(?=Server session ID)' |
  Where-Object { $_ -notmatch 'w3wp|inetinfo|Microsoft\.' } |
  ForEach-Object { [pscustomobject]@{ Host=$env:COMPUTERNAME; Group=$_ } }
```

```kusto
// Sentinel: inbound-triggered execution off a web/System parent with NO outbound beacon
let webexec = DeviceProcessEvents
  | where InitiatingProcessFileName in~ ("w3wp.exe","System","svchost.exe")
  | where FileName in~ ("cmd.exe","powershell.exe","net.exe","whoami.exe")
  | project DeviceName, execTime = TimeGenerated, InitiatingProcessFileName, ProcessCommandLine;
let egress = DeviceNetworkEvents
  | where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
  | project DeviceName, connTime = TimeGenerated, RemoteIP, InitiatingProcessFileName;
webexec
| join kind=leftouter egress on DeviceName
| where isempty(connTime) or abs(datetime_diff('minute', execTime, connTime)) > 30
| summarize execs=count(), sampleCmd=any(ProcessCommandLine) by DeviceName, InitiatingProcessFileName
// server process executing children but not making outbound public connections = inbound-only pattern
```

Attribute each suspect reservation to its owning process (`servicestate` PID); an owning process holding an `HTTP.sys` request-queue handle while consuming IOCTLs but never opening an outbound socket is the core signal. Confirm the IOCTL path with a memory-forensics handle scan (Volatility `handles`/`devicetree`) on the owning/driver process.

## Triage guidance

- **Likely malicious:** a URL reservation / UrlGroup owned by a standalone EXE or a service DLL (not `w3wp.exe`/`inetinfo.exe`) with no matching IIS site binding; a driver or process issuing undocumented `DeviceIoControl` calls against HTTP.sys; a web/System process spawning `cmd.exe`/recon tooling on an inbound-request cadence while holding **zero** outbound public connections; any of these on an internet-facing SharePoint/IIS/telecom server in the targeted MENA sectors.
- **Likely benign / expected:** legitimate self-hosted WCF/.NET services and management agents that own `Temporary_Listen_Addresses` or app-specific prefixes; real IIS worker processes with matching site bindings; health-probe/monitoring agents that spawn short-lived children. Baseline which processes legitimately hold reservations per server class and suppress; a reservation with a matching IIS binding and a signed owning process clears.
- **Pivot next:** attribute the owning process, then pivot to the kernel driver / in-memory loader (HUNT-04), the driver provenance and file-protection (HUNT-03), the proxy/RDP-tunnel egress paths (HUNT-02), and the masquerade check on the owning image (HUNT-05); dump the owning process memory and YARA-scan for the shared OBFUSLAY/CRYPTOSLAY constants (HUNT-06). Cross-reference the detection lane for STAYSHANTE/BASEWALK webshells (T1505.003) and `w3wp.exe`→`cmd.exe` (T1059.003). A confirmed passive listener on a live server is an active access-broker intrusion feeding downstream Iranian operators — escalate to incident-response-coordinator. Once the per-server reservation baseline exists, an owned-by-unexpected-process reservation with no IIS binding is repeatable and precise — hand to detection-engineering as a candidate rule (Summiting Level 4).

## References

- https://thehackernews.com/2024/09/iranian-apt-unc1860-linked-to-mois.html
- https://securityaffairs.com/168656/apt/unc1860-provides-iran-linked-apts-access-middle-east.html
- https://attack.mitre.org/techniques/T1205/
- https://attack.mitre.org/techniques/T1071/001/
- https://attack.mitre.org/techniques/T1095/
- https://attack.mitre.org/techniques/T1106/
