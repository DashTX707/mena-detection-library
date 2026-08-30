# Hunt: UNC1549 (TA455) — encrypted C2 beaconing that hides inside legitimate Azure

- **Hypothesis:** If UNC1549 has a MINIBIKE/MINIBUS/TWOSTROKE/LIGHTRAIL implant on our estate, then the on-victim tell is *not* a bad reputation hit — the C2 rides `*.azurewebsites.net` / `*.cloudapp.azure.com`, TLS-terminates like any benign cloud service, and every payload is a unique hash — but a **narrow, endpoint-originated TLS/443 session that beacons with machine-like regularity to an Azure host our organisation has never legitimately used, dressed up with an IT/health-service-sounding name** (`vm-tools-svc`, `vmware-health-ms`, `active-internal-logs`, `mso-intranet-logs`). The finding is the *stack*: never-before-seen Azure destination + low-jitter periodicity + a masquerading service-like hostname + (ideally) the requesting process being a side-loaded binary from a VMware/Citrix dir. Any one alone is noise; the stack on one host is the hunt.
- **ATT&CK:**
  - T1583.006 — Acquire Infrastructure: Web Services (resource-development) — actor provisions Azure App Service web apps and Azure VMs across eastus/westus3/northeurope/uaenorth/qatarcentral to host C2; this hunt finds the *use* of that acquired infra from inside our network.
  - T1573 — Encrypted Channel (command-and-control) — TWOSTROKE uses SSL/TCP-443, LIGHTRAIL uses Azure WebSocket over HTTPS/443; content is opaque so we hunt TLS metadata (JA3/JA3S), periodicity and destination-reputation rather than payload.
  - T1071.001 — Application Layer Protocol: Web Protocols (command-and-control) — corroborating context: LIGHTRAIL hardcoded `/news` path + fixed Chrome/Edge UA, POLLBLEND `POST {"username":"<computer_name>"}` to `/register/` (detection-lane, cited here for the pivot).
- **Actor procedure:** UNC1549's signature is blending malicious traffic into trusted cloud. Backdoors beacon over HTTPS to Azure App Service (`*.azurewebsites.net`) and Azure VMs (`*.cloudapp.azure.com`). Hostnames deliberately imitate benign IT/cloud/telemetry services. LIGHTRAIL (modified Lastenzug Socks4a, MAX_CONNECTIONS raised to 5000) is side-loaded via `VGAuthCLI.exe` loading a malicious `VGAuth.dll`. GHOSTLINE (go-yamux) and POLLBLEND relay through Azure. Certs are legitimate-signed, hashes are per-sample unique — so reputation/hash signatures fail by design.
- **Why a hunt, not a rule:** You cannot alert on "traffic to Azure over 443" — that is most of the modern enterprise's egress. The malicious signal only emerges from correlating several weak anomalies (rarity of the specific tenant/host, beacon regularity, name-masquerade, side-loaded requesting process) and weighing them with analyst judgement plus the curated actor-domain list. That fusion is hunt work. If a durable relational observable falls out — e.g. a specific side-loaded process consistently originating low-jitter 443 sessions to a first-seen Azure host — hand *that* scoped analytic to detection-engineering; do not try to alert on "beaconing to Azure."

## Data sources required

- Proxy / TLS-metadata / Zeek `ssl.log` + `conn.log`: SNI/JA3/JA3S, bytes-per-connection, connection timing to `*.azurewebsites.net` and `*.cloudapp.azure.com`.
- Passive DNS / DNS resolver logs: first-seen timestamps per Azure FQDN (never-before-seen scoring).
- EDR network+process join (DeviceNetworkEvents / DeviceProcessEvents): the initiating process and its image path (VMware/Citrix/Fortinet/NVIDIA dirs) for the C2 session.
- Curated actor-domain watchlist from this pack's IOC appendix (the 60+ Azure FQDNs).

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — score beacon regularity + destination rarity + name-masquerade on the same host

```kusto
let actorC2 = dynamic(["vm-tools-svc","vmware-health-ms","active-internal-log","active-intranet-logs",
    "mso-internal-log","mso-intranet-logs","vcphone-ms","snare-core","infrasync-ac","nxlog-win"]);
let lookback = 14d;
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where RemoteUrl has_any ("azurewebsites.net","cloudapp.azure.com") or RemotePort == 443
| extend host = tostring(split(RemoteUrl,"/")[0])
// (1) name-masquerade: service/health/log-sounding Azure hostnames
| extend masquerade = iff(host has_any (actorC2) or host matches regex @"(?i)(vm|vmware|health|internal|intranet|tools|svc|nxlog|status|check)", 1, 0)
| summarize hits=count(), conns=make_list(TimeGenerated,500),
            firstSeen=min(TimeGenerated), procs=make_set(InitiatingProcessFolderPath,8)
        by DeviceName, host, masquerade
// (2) never-before-seen: destination first observed inside the window
| where firstSeen > ago(lookback) - 1d or masquerade == 1
// (3) beacon regularity: low coefficient-of-variation of inter-arrival gaps => machine cadence
| mv-expand ts=conns to typeof(datetime)
| order by DeviceName, host, ts asc
| serialize | extend gap = datetime_diff('second', ts, prev(ts))
| summarize beaconCV = stdev(gap)/avg(gap), samples=count(),
            masquerade=max(masquerade), procs=take_any(procs) by DeviceName, host
| where samples >= 8 and beaconCV < 0.25          // tight, machine-like cadence
| where masquerade == 1 or procs has_any ("VMware","Citrix","Fortinet","NVIDIA")
| order by beaconCV asc
```

## Triage guidance

- **Likely malicious:** a host with tight beacon cadence (low CV) to a first-seen Azure FQDN whose name imitates an IT/telemetry service, where the initiating process is a signed binary loading from a VMware/Citrix path (cross-ref detection-pack T1574.001); any destination matching the pack's actor-Azure IOC list; a fixed `Chrome/42.0.2311.135 ... Edge/12.10136` UA or requests to `/news` or `/register/`.
- **Likely benign / expected:** legitimate SaaS and monitoring agents (Datadog, Azure Monitor, Splunk UF, backup) beacon regularly to Azure too — baseline your sanctioned agents and their hostnames first; auto-update and telemetry pings from Microsoft products; CDN/App-Service apps your business actually owns. Regular cadence alone is not malicious — it is the *combination* with rarity + masquerade + side-load provenance that matters.
- **Pivot next:** on a hit, pull the initiating process' module loads (Sysmon EID 7) to confirm/deny DLL side-load; sweep the full actor-Azure FQDN watchlist across all hosts for lateral spread; feed the confirmed FQDN/JA3 pair to HUNT-02 (exfil) and to detection-engineering as a scoped analytic. If side-load + DCSync/screenshot artefacts co-occur, escalate to incident-response-coordinator — this is a live implant.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/analysis-of-unc1549-ttps-targeting-aerospace-defense
- https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-unc1549-targets-israel-middle-east
- https://attack.mitre.org/techniques/T1583/006/
- https://attack.mitre.org/techniques/T1573/
- https://attack.mitre.org/techniques/T1071/001/
