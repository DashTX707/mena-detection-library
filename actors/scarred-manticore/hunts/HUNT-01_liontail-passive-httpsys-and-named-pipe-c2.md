# Hunt: Scarred Manticore LIONTAIL passive C2 — unexpected HTTP.sys URL reservations, Exchange-mimicking prefixes, and Everyone-DACL named pipes on servers

- **Hypothesis:** If LIONTAIL is resident on one of our Internet-facing or internal Windows servers, then — because it is a *passive* listener that never beacons out — the evidence is not on the wire but in the host's HTTP.sys registration state and named-pipe namespace: we should find a URL reservation / registered UrlGroup owned by a non-IIS, non-service-account process for a prefix that mimics a legitimate service (`http://+:80/Temporary_Listen_Addresses/`, `https://+:443/autodiscover/autodiscovers/`, `/ews/exchanges/`, `/ews/ews/`) with no corresponding IIS site or WCF app behind it, OR (on internal servers with no web access) a named pipe such as `\\.\pipe\test-pipe` created with the permissive security descriptor `D:(A;;FA;;;WD)` (File-All-Access to Everyone) by a process that is not a known IPC application.
- **ATT&CK:**
  - T1071.001 — Application Layer Protocol: Web Protocols (command-and-control) — LIONTAIL PE variant and SDD backdoor drive HTTP.sys directly via undocumented IOCTLs / HttpListener, registering Exchange/Autodiscover-mimicking prefixes to receive inbound shellcode instead of beaconing
  - T1095 — Non-Application Layer Protocol (command-and-control) — the LIONTAIL named-pipe variant receives shellcode over `\\.\pipe\test-pipe` on internal servers with no web path, using an Everyone-File-All-Access DACL
- **Actor procedure:** The primary LIONTAIL variant is a passive shellcode loader that listens for attacker HTTP(S) requests by interacting with the low-level HTTP.sys kernel driver via undocumented IOCTLs (`UlCreateServerSessionIoctl`, `UlCreateUrlGroupIoctl`, `UlAddUrlToUrlGroupIoctl`, `UlReceiveHttpRequestIoctl`, `UlSendHttpResponseIoctl`) — deliberately bypassing IIS and the HTTP Server API to avoid the layers security tools monitor. It registers URL prefixes that mimic legitimate services (WCF `Temporary_Listen_Addresses`, Autodiscover, EWS). The SDD backdoor achieves the same via the .NET `HttpListener` class, building its prefix set from IIS site bindings. For internal servers with no public web access, a named-pipe LIONTAIL variant receives the same encrypted shellcode over `\\.\pipe\test-pipe` (security descriptor `D:(A;;FA;;;WD)`), using `CreateNamedPipe`/`ReadFile`/`WriteFile`. Both variants execute received shellcode in a new in-memory thread and return results in the response — no outbound C2.
- **Why a hunt, not a rule:** This is *the* defining evasion for this actor and the reason a normal SIEM alert cannot see it. By driving HTTP.sys below the HTTP Server API, LIONTAIL leaves no IIS log entry, no `W3SVC` event, and no outbound connection to beacon on — the three things most host/network detections key on. Ports 80/443/444 on a server are expected, so a network rule is blind; there is no domain/IP IOC to block (the actor publishes none, by design). The durable, hard-to-change observable (Summiting Level 4–5: this is technique-core — abandoning HTTP.sys URL registration means abandoning the passive-listener design) is the *state anomaly*: a URL ACL / UrlGroup that no legitimate IIS site or service explains, owned by an unexpected process. Distinguishing that from legitimate self-hosted WCF/HttpListener apps requires per-server baselining of which processes are *supposed* to hold URL reservations — analyst correlation, not a threshold. A single odd pipe or reservation is thin; the finding is a mimicking-prefix reservation OR Everyone-DACL pipe **stacked on** an unexplained owning process (correlate with HUNT-03 loader and HUNT-05 masquerade).

## Data sources required

- Host-collected `netsh http show urlacl` and `netsh http show servicestate` output (or the `HTTP\Parameters\UrlAclInfo` registry / `Http.sys` config store) — periodic per-server snapshots, diffed against a golden baseline
- Sysmon EID 17 (pipe created) / EID 18 (pipe connected) with the pipe name and creating `Image` — for the named-pipe variant
- EDR loaded-module / handle telemetry to attribute a URL reservation or `HTTP.sys` handle to an owning process (map PID → process holding the `\Device\Http\ReqQueue` handle)
- IIS site/binding inventory and service inventory (to know which prefixes are legitimately explained)

## Query starting point

Platform: `netsh / PowerShell host procedure` (no SIEM query fits the HTTP.sys state — collect it, then diff)

```
# Run per server (scheduled), ship output to the SIEM as a field-extracted event:
netsh http show urlacl        > urlacl_%COMPUTERNAME%.txt
netsh http show servicestate  > svcstate_%COMPUTERNAME%.txt   # lists registered URL groups + owning process IDs

# PowerShell: flag reservations that mimic services but have no matching IIS binding / known WCF app
$known = @('Temporary_Listen_Addresses')   # WCF default is legit-but-abused — treat as SUSPECT on non-WCF hosts
$susp  = 'autodiscover/autodiscovers|/ews/exchanges|/ews/ews|autodiscovers|exchanges'
(netsh http show urlacl) -join "`n" -split '(?=Reserved URL)' |
  Where-Object { $_ -match $susp -or $_ -match 'Temporary_Listen_Addresses' } |
  ForEach-Object { [pscustomobject]@{ Host=$env:COMPUTERNAME; Reservation=$_ } }
```

```
# Named-pipe variant — Sysmon (Splunk SPL)
index=endpoint source=*Sysmon* (EventCode=17 OR EventCode=18)
| eval pipe=lower(PipeName), img=lower(Image)
| eval suspect_pipe=if(match(pipe,"(?i)\\\\?test-pipe$") OR match(pipe,"^\\\\?[a-z0-9]{6,}$"),1,0)
| where suspect_pipe=1
       AND NOT match(img,"(?i)\\\\(sql|mssql|spool|chrome|msoffice|svchost)\\b")
| stats values(pipe) as pipes values(img) as procs min(_time) as first by host
```

Attribute each suspect reservation/pipe to its owning process (`servicestate` PID or Sysmon `Image`); the DACL `D:(A;;FA;;;WD)` on the pipe requires an EDR/handle query or memory inspection (Sysmon does not emit the security descriptor) — pull it with `accesschk \pipe\<name>` or a memory-forensics handle scan.

## Triage guidance

- **Likely malicious:** a URL reservation / UrlGroup for `/autodiscover/autodiscovers/`, `/ews/exchanges/`, `/ews/ews/`, or `Temporary_Listen_Addresses` on a host with no matching IIS site binding or self-hosted WCF app, owned by a standalone EXE / a service DLL rather than `w3wp.exe`/`Microsoft.Exchange.*`; a `\\.\pipe\test-pipe` (or short random-name pipe) with an Everyone-File-All-Access DACL created by an unexpected process on an internal server; either one on the same host as a phantom `wlanapi.dll`/`wlbsctrl.dll` load or a `Cyvera Console` masquerade.
- **Likely benign / expected:** legitimate self-hosted WCF/.NET services and management agents that own `Temporary_Listen_Addresses` or app-specific prefixes; genuine Exchange owning real `/ews/exchange.asmx` and `/autodiscover/autodiscover.xml` (note the *singular, real* paths vs the actor's doubled `/autodiscovers/`, `/exchanges/`, `/ews/ews/`); SQL/print-spooler/browser IPC pipes. Baseline which processes legitimately hold reservations per server class and suppress them.
- **Pivot next:** attribute the owning process, then pivot to the in-memory loader and kernel driver (HUNT-03), the phantom-DLL persistence and service enablement (detection lane), and the masquerade check on the owning image (HUNT-05); if on an Exchange host, pivot to the LIONHEAD EWS relay (HUNT-02). Dump the owning process memory and YARA-scan for the shared XOR/heartbeat constants (HUNT-04, HUNT-07). A confirmed passive listener on a live server is an active espionage intrusion — escalate to incident-response-coordinator. The *doubled Exchange-prefix* pattern and the `test-pipe`+Everyone-DACL pair are repeatable and precise once baselined — hand those to detection-engineering as candidate rules (Summiting Level 4).

## References

- https://research.checkpoint.com/2023/from-albania-to-the-middle-east-the-scarred-manticore-is-listening/
- https://attack.mitre.org/techniques/T1071/001/
- https://attack.mitre.org/techniques/T1095/
