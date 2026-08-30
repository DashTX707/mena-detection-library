# Hunt: Cavern Manticore — adversary domain infrastructure acquisition & resolution

- **Hypothesis:** If Cavern Manticore is operating (or staging to operate) against us, then their masquerading C2/payload **domains** — registered off-victim and therefore invisible on our endpoints at registration time — will eventually surface in our resolver and proxy telemetry as *outbound lookups/connections from internal hosts to update-service-impersonating domains on abuse-prone TLDs*. Their naming grammar is consistent: legitimate-service impersonation (`microsoft-updateserver`, `onedriver-srv`, `symantecserver`, `msupdate`, `gupdate`, `winstore`) on cheap/free TLDs (`.cf`, `.ml`, `.tk`, `.us`, `.co`, `.top`, `.eu`). The finding is an internal host resolving/beaconing to a domain matching both the known IOC set *and* this registration pattern — especially a newly-registered look-alike not previously seen in our environment.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — the actor registers update-impersonating domains off-victim; the hunt catches them when they resolve on our side and tracks new look-alikes matching the grammar.
  - T1071.001 — Application Layer Protocol: Web Protocols (command-and-control) — cross-referenced: the acquired domains are reached over HTTP(S) C2; a resolution followed by a beacon is the escalation.
  - T1583 — Acquire Infrastructure (resource-development) — parent context: the IP/ASN hosting these domains (the pack IOC IP set) is the reusable infrastructure to pivot on.

- **Actor procedure:** The actor registers and operates C2/payload domains that masquerade as legitimate software-update and cloud services. Confirmed IOC domains: `microsoft-updateserver.cf` (C2), `service-management.tk` (payload host), `onedriver-srv.ml`, `google.onedriver-srv.ml`, `symantecserver.co`, `msupdate.us`, `gupdate.us`, `newdesk.top`, `aptmirror.eu`, `winstore.us`, `my-logford.ml`, `tcp443.org`. These resolve to the actor's VPS IP set (e.g. `51.89.x.x` OVH blocks, `148.251.71.182`, `162.55.137.20`). Backdoors/reverse shells beacon to these over HTTP(S), and PowerShell download cradles pull staged payloads from them (see HUNT-04).
- **Why a hunt, not a rule:** The static IOC domains *should* be blocklisted outright — that's a rule, and it belongs to the detection pack / TI blocklist, not here (blocklisting a known-bad domain is QA of an existing indicator, not hunting). The hunt's value is in the *durable, evadable-only-by-abandoning-the-grammar* pattern: the actor rotates domains constantly (Level-1 IOCs expire), so hunting the *registration behavior* — newly-observed, low-reputation, update-service-impersonating look-alikes on abuse TLDs resolving from inside — catches the *next* domain before it's on any blocklist. That newly-registered-domain + naming-grammar + internal-resolution correlation, weighed against benign software-update traffic, is judgement work. If a specific look-alike is confirmed actor-owned, hand it to detection-engineering/TI to blocklist; the hunt keeps finding the ones that aren't listed yet.

## Data sources required

- DNS resolver logs (internal recursive resolver / Defender for Endpoint `DeviceNetworkEvents` / Umbrella) — query name, querying host, response IP, first-seen
- Web proxy / TLS-inspection or SNI logs — outbound HTTP(S) destinations, JA3/JA3S, requesting process
- Domain-reputation / newly-registered-domain (NRD) enrichment + WHOIS creation date + TLD
- Threat-intel: the pack IOC domain and IP/ASN set as a watchlist

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — catch internal resolutions to IOC domains and to unseen look-alikes matching the registration grammar

```kusto
let iocDomains = dynamic(["newdesk.top","onedriver-srv.ml","symantecserver.co",
    "microsoft-updateserver.cf","msupdate.us","service-management.tk","aptmirror.eu",
    "winstore.us","my-logford.ml","gupdate.us","tcp443.org","google.onedriver-srv.ml"]);
let iocIps = dynamic(["107.173.231.114","198.12.65.175","148.251.71.182","162.55.137.20",
    "51.89.169.198","142.44.251.77","51.89.135.142","51.89.190.128","51.89.178.210",
    "142.44.135.86","182.54.217.2"]);
let abuseTlds = dynamic([".cf",".ml",".tk",".top",".us",".co",".eu"]);
let updateLures = dynamic(["update","msupdate","gupdate","onedriver","symantec","winstore",
    "microsoft-update","service-management","aptmirror","logford","srv"]);
DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| where isnotempty(RemoteUrl) or isnotempty(RemoteIP)
| extend host = tostring(parse_url(RemoteUrl).Host)
| extend hitIoc   = iff(host in (iocDomains) or RemoteIP in (iocIps), true, false)
| extend grammarHit = iff(host has_any (updateLures) and host has_any (abuseTlds), true, false)
| where hitIoc or grammarHit
| summarize conns = count(), hosts = make_set(host, 10), ips = make_set(RemoteIP, 10),
            firstSeen = min(TimeGenerated), procs = make_set(InitiatingProcessFileName, 10)
         by DeviceName, hitIoc, grammarHit
// prioritise: direct IOC hits, or grammar look-alikes first seen recently (candidate new domain),
// especially those reached by powershell.exe / non-browser processes
| order by hitIoc desc, firstSeen desc
```

## Triage guidance

- **Likely malicious:** any internal host resolving/connecting to a pack IOC domain or IP; a *newly-observed* update-impersonating look-alike on an abuse TLD (`*-update*.cf`, `*srv*.ml`) reached by `powershell.exe` or a masquerading binary rather than a browser/updater; a domain whose WHOIS creation date is within days/weeks and that resolves to an OVH/Hetzner VPS in the actor's ASN range; beaconing periodicity (regular-interval callbacks) to the look-alike.
- **Likely benign / expected:** legitimate vendor update domains (`update.microsoft.com`, `*.windowsupdate.com`, real Symantec/Broadcom, real OneDrive) — the grammar filter deliberately targets *impersonations on abuse TLDs*, so allowlist genuine vendor FQDNs; some businesses legitimately use `.co`/`.us`/`.eu` domains, so TLD alone is not guilt; NRD hits from marketing/CDN churn are common and need process/context to matter.
- **Pivot next:** confirm WHOIS/passive-DNS for any look-alike (creation date, registrar, co-hosted domains on the same VPS — this often unmasks the *next* set of actor domains before they're used). If a host is beaconing, pivot to that host's process lineage and the download-cradle hunt (HUNT-04, T1105/T1588.002/T1608.001) and treat as active C2 — escalate to IR. Feed any confirmed actor-owned domain/IP to detection-engineering/TI for blocklisting and to expand the watchlist.

## References

- https://www.secureworks.com/blog/cobalt-mirage-conducts-ransomware-operations-in-us
- https://www.sentinelone.com/labs/log4j2-in-the-wild-iranian-aligned-threat-actor-tunnelvision-actively-exploiting-vmware-horizon/
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1071/001/
