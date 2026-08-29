# Hunt: Charming Kitten web-service C2 & staging (glitch.me / tebi.io)

- **Hypothesis:** If a NICECURL or TAMECAT implant is beaconing in our environment, then in proxy/DNS/EDR-network telemetry we should observe host processes making outbound HTTP(S) connections to legitimate-but-atypical web services — `*.glitch.me` subdomains and `s3.tebi.io` object storage — originating from script hosts (wscript/cscript/powershell/cmd/curl/conhost) rather than browsers, at machine-like intervals.
- **ATT&CK:**
  - T1583.006 — Acquire Infrastructure: Web Services (resource-development)
  - T1102.002 — Web Service: Bidirectional Communication (command-and-control)

- **Actor procedure:** APT42 hides C2 in traffic to trusted providers. NICECURL and TAMECAT use `glitch.me` subdomains as bidirectional C2 (`prism-west-candy[.]glitch[.]me`, `accurate-sprout-porpoise[.]glitch[.]me`) and `s3[.]tebi[.]io` object storage for payload hosting/staging; decoys are pulled from Dropbox/Google Drive and infrastructure is Cloudflare-fronted. NICECURL fetches via `curl` over HTTPS; TAMECAT downloads `nconf.txt` + a decrypt helper over HTTP. The three-random-word glitch subdomain pattern (adjective-noun-noun) is a recognizable naming tell.
- **Why a hunt, not a rule:** glitch.me and tebi.io are legitimate developer/object-storage services with real business use — blanket-blocking or alerting on them is untenable in most orgs, so a naive rule is all false positives or gets disabled. The malicious signal is *contextual*: which **process** initiated the connection, whether the destination is normal **for that host**, and machine-like **beacon timing** — a stacked-anomaly judgement (never-before-seen destination + unexpected process→network relationship + regular timing) that needs per-environment baselining. That's a hunt. A specific confirmed glitch subdomain can be handed to detection-engineering as a short-lived block, but the behavioral pattern stays a hunt.

## Data sources required

- Web proxy / SWG logs (URL, host header, user-agent, bytes, timing)
- DNS resolver logs (queries for `*.glitch.me`, `s3.tebi.io`, tebi.io)
- EDR / Sysmon EID 3 network events with process context (process→destination correlation)
- TLS/SNI metadata (JA3/SNI where available)

## Query starting point

Platform: `KQL / Microsoft Sentinel` — outbound to CK web-service C2 that did NOT come from a browser, plus beacon-regularity check

```kusto
let c2svc = dynamic(["glitch.me","tebi.io"]);
DeviceNetworkEvents
| where RemoteUrl has_any (c2svc) or RemoteDnsQuery has_any (c2svc)
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe")
| where InitiatingProcessFileName in~
        ("wscript.exe","cscript.exe","powershell.exe","pwsh.exe","cmd.exe","curl.exe","conhost.exe","mshta.exe","rundll32.exe")
| extend sub = tostring(split(RemoteUrl,"/")[2])
| summarize hits=count(), conns=make_set(RemoteUrl,20), first=min(TimeGenerated), last=max(TimeGenerated)
        by DeviceName, InitiatingProcessFileName, sub
// beacon-regularity: low stddev of inter-arrival gaps on the same host+dest = machine timing
| join kind=inner (
    DeviceNetworkEvents
    | where RemoteUrl has_any (c2svc)
    | order by DeviceName, TimeGenerated asc
    | serialize gap = datetime_diff('second', TimeGenerated, prev(TimeGenerated))
    | summarize beacons=count(), stdev=stdev(gap), avg=avg(gap) by DeviceName
    | where beacons>=6 and stdev < avg*0.25
  ) on DeviceName
| sort by hits desc
```

## Triage guidance

- **Likely malicious:** wscript/cscript/powershell/cmd/curl/conhost (never a browser) connecting to a three-random-word `*.glitch.me` subdomain or `s3.tebi.io`; regular machine-like beacon intervals; small periodic requests punctuated by a larger download (module/`nconf.txt`); the host has no developer/dev-ops role justifying glitch/tebi use.
- **Likely benign / expected:** developers/dev-ops hosts using glitch.me or tebi.io from a browser or dev CLI; CI runners; legitimate apps embedding these services. Baseline which hosts legitimately touch these domains and suppress them.
- **Pivot next:** on a flagged host pull the initiating script (NICECURL `kuzen.vbs` / TAMECAT `nconf.txt`) and its parent chain (LNK/macro → HUNT-05/06), decode C2 config, and check the encrypted-channel tell (`Content-DPR` header — HUNT-05). This is a live-implant indicator → escalate to IR. Confirmed C2 FQDNs → detection-engineering for short-lived perimeter blocks (pivots, not durable detection).

## References

- https://cloud.google.com/blog/topics/threat-intelligence/untangling-iran-apt42-operations
- https://attack.mitre.org/groups/G0059
