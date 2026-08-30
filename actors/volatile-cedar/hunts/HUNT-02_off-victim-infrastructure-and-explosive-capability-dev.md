# Hunt: Volatile Cedar — off-victim infrastructure & Explosive-RAT capability development

- **Hypothesis:** If Volatile Cedar is operating against us, then the *build-out* of their operation — the custom Explosive RAT codebase they alone use and the C2/updater domains they register — happens off-victim and cannot be seen on our endpoints; but its shadow lands on us in two observable ways. First, any host that ever resolves or connects to their known static updater C2 (`edortntexplore[.]info`) or the Explosive C2 IPs (68.65.122.109, 74.208.73.149, 191.101.5.183, 198.101.242.72, 169.50.13.61) is by definition already implanted. Second — the durable, actor-agnostic half — a *newly registered domain whose passive-DNS/registration fingerprint matches the group's tradecraft* (young domain, hosted on the same ASNs/registrars as prior Explosive C2, `.info`-style updater naming, resolving from inside our estate) is the reusable tell that survives IOC rotation. This is an intel-led infrastructure hunt: pivot from the actor's known build patterns to any internal host reaching adversary-shaped infrastructure.
- **ATT&CK:**
  - T1587.001 — Develop Capabilities: Malware (resource-development) — the custom Explosive RAT (v1–v4, main binary + separately-patched API DLL) that only this group uses; its on-victim shadow is the implant's host/network behavior
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — registration of hardcoded static updater C2 (`edortntexplore[.]info`) plus a DGA-generated domain pool for fallback

- **Actor procedure:** Volatile Cedar is the only known APT to use the Explosive RAT and has maintained it across four major versions since ~2012, deliberately splitting it into a main binary plus a separately-updatable API DLL so operators can patch capability and re-obfuscate to dodge heuristic AV. For control infrastructure they register hardcoded static updater C2 domains (Kaspersky documented `edortntexplore[.]info` receiving Explosive check-ins at `/micro/data/index.php?micro=4` on port 443) and stand up a pool of DGA-generated domains as dynamic fallback update servers — infrastructure Kaspersky ultimately sinkholed.
- **Why a hunt, not a rule:** Malware development and domain registration are off-victim resource-development acts with no endpoint telemetry — there is nothing on our hosts to alert on at the moment of the build. The known IOCs (the `.info` domain, the five IPs, the sample hashes) *can* be alerted on and should be handed to the detection lane, but they are Level-1 indicators the adversary rotates freely; the durable hunt value is in the *shape* of the infrastructure (young domain + shared hosting lineage + updater-style naming resolving from inside), which requires analyst correlation against passive-DNS and registration intel, not a static match.
- **Note for detection-engineering:** the five C2 IPs and `edortntexplore[.]info` are precise, low-volume, and repeatable — hand them to the detection lane as a blocklist/TI-match rule. This hunt owns only the *adversary-shaped-but-not-yet-known* infrastructure.

## Data sources required

- DNS resolver logs (internal → external query records, with resolving client)
- Proxy / firewall egress connection logs (destination IP, domain, port, bytes)
- Passive-DNS + domain-registration / newly-registered-domain (NRD) intel feed
- Threat-intel indicator table (the known Explosive C2 IPs/domain + sample hashes as a watchlist)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — join internal DNS/egress against both the known-IOC watchlist and a newly-registered-domain feed shaped like this actor's updater C2.

```kusto
let knownC2ip = dynamic(["68.65.122.109","74.208.73.149","191.101.5.183","198.101.242.72","169.50.13.61"]);
let knownC2dom = dynamic(["edortntexplore.info"]);
// (a) Any internal host touching known Explosive infrastructure = already implanted
let hardHits = union
    (DeviceNetworkEvents
        | where TimeGenerated > ago(30d)
        | where RemoteIP in (knownC2ip)
        | project TimeGenerated, DeviceName, Match=RemoteIP, Kind="known_ip"),
    (DnsEvents
        | where TimeGenerated > ago(30d)
        | where Name has_any (knownC2dom)
        | project TimeGenerated, DeviceName=Computer, Match=Name, Kind="known_domain");
// (b) Durable half: internal resolutions of young/updater-shaped domains (adversary tradecraft)
let shapedHits = DnsEvents
    | where TimeGenerated > ago(30d)
    | where Name matches regex @"(?i)(update|micro|explore|ntnt|rtnt).*\.(info|xyz|top|online)$"
    | join kind=inner (_GetWatchlist('newly_registered_domains')
                        | project Name=SearchKey, registered) on Name
    | where registered > ago(45d)                 // freshly registered, updater-style naming
    | project TimeGenerated, DeviceName=Computer, Match=Name, Kind="shaped_nrd";
union hardHits, shapedHits
| summarize hits=count(), firstSeen=min(TimeGenerated), lastSeen=max(TimeGenerated),
            samples=make_set(Match, 10) by DeviceName, Kind
| order by Kind asc, hits desc
```

## Triage guidance

- **Likely malicious:** any internal resolution of or connection to `edortntexplore[.]info` or the five Explosive C2 IPs — treat as confirmed implant, not a hunt lead; a young `.info`/updater-shaped domain, registered in the last ~45 days on the same registrar/ASN lineage as prior Explosive C2, resolved by a server host that has no business making external DNS lookups; the same destination correlating with the beacon-cadence hunt (HUNT-03) on the same host.
- **Likely benign / expected:** legitimate software-update domains (vendor CDNs, OS/patch updaters) that share "update" naming — allow-list known update infrastructure; NRD noise from marketing/tracking domains; a workstation resolving a freshly-registered but clearly commercial domain. The combination of *server host + updater-shaped young domain + shared hosting lineage* is what elevates it.
- **Pivot next:** on any hard IOC hit, escalate to incident-response-coordinator immediately and pivot to the implant/module hunt (detection pack T1129/T1574.001) and the C2-cadence hunt (HUNT-03) on that host. For a shaped-NRD lead, watch for beacon regularity and the Explosive URI pattern (`/micro/data/index.php?micro=`), and submit the domain to the passive-DNS tracker so future resolutions across the estate light up. Preserve any newly-observed C2 domain/IP as attribution intel and hand the confirmed indicators to detection-engineering.

## References

- https://securelist.com/sinkholing-volatile-cedar-dga-infrastructure/69421/
- https://blog.checkpoint.com/security/volatilecedar/
- https://www.clearskysec.com/wp-content/uploads/2021/01/Lebanese-Cedar-APT.pdf
- https://attack.mitre.org/techniques/T1587/001/
- https://attack.mitre.org/techniques/T1583/001/
