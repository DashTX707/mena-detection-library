# Hunt: Cavern Manticore — pre-intrusion mass vulnerability scanning of our internet-facing apps

- **Hypothesis:** If Cavern Manticore (DEV-0270 / Cobalt Mirage / TunnelVision) is preparing to hit us, then before any on-host foothold exists we will see *off-victim reconnaissance landing on our own edge*: bursts of inbound probes against the exact internet-facing products they weaponize — VMware Horizon/Tomcat (Log4Shell JNDI strings), Exchange (ProxyShell/ProxyLogon autodiscover/PowerShell endpoints), and Fortinet FortiOS SSL-VPN (CVE-2018-13379 path traversal) — arriving from hosting-provider/VPS ASNs and, tellingly, from IPs or blocks adjacent to their known infrastructure. The tell is not one 404 but a *narrow, version-probing scan pattern* on the vulnerable path that immediately precedes (or matches the timing of) a successful exploit attempt. This hunt correlates our own perimeter/WAF telemetry with external attack-surface exposure, because the wider internet scan itself is not something we can see on an endpoint.
- **ATT&CK:**
  - T1595.002 — Active Scanning: Vulnerability Scanning (reconnaissance) — internet-wide scanning for Log4Shell-vulnerable Horizon, ProxyShell-vulnerable Exchange, and FortiOS as it lands on our edge; the whole hunt is this technique observed from the victim side.
  - T1190 — Exploit Public-Facing Application (initial-access) — cross-referenced only: the scan is the precursor and the exploit is the payoff; a scan that transitions to exploitation on the same path/source is the escalation pivot.

- **Actor procedure:** All three vendor reports describe Cavern Manticore as an *early-adopter opportunistic* actor that scans the internet for freshly-disclosed high-severity CVEs and exploits them within days. Their confirmed weaponized surface: Log4Shell (CVE-2021-44228 / CVE-2021-45046) against VMware Horizon's `ws_TomcatService.exe`; Exchange ProxyShell (CVE-2021-34473/34523/31207) and ProxyLogon (CVE-2021-26855/26857/26858/27065); and Fortinet FortiOS (CVE-2018-13379, CVE-2020-12812, CVE-2019-5591). Scanning precedes the drop of ASPX web shells (`aspx_[a-z]{13}.aspx`) and PowerShell download cradles. They operate from VPS/hosting infrastructure (see the IOC IP set, e.g. `51.89.0.0`-range OVH blocks, `148.251.71.182`, `162.55.137.20`).
- **Why a hunt, not a rule:** Internet background-noise scanning is constant — every internet-facing appliance is probed thousands of times a day, so a standalone "someone scanned our Fortinet path" alert is pure noise and would be tuned off within a week. The finding only exists in *correlation and judgement*: a version-specific probe pattern on a product we actually expose, from an ASN/IP that ties to this actor's infrastructure or that then transitions into an exploit attempt on the same session. That fusion of perimeter logs + external exposure intel + actor-infra enrichment is hunt work. If a durable, precise transition emerges (e.g. "JNDI string in a Horizon request followed within 60s by a Tomcat child process" — a Level-4 behavioral chain), hand *that* to detection-engineering; do not try to alert on scanning volume itself.

## Data sources required

- Perimeter/WAF and reverse-proxy logs (Horizon/Tomcat access logs, Exchange IIS logs, FortiGate SSL-VPN logs) — inbound request URIs, user-agents, source IPs
- IDS/IPS signatures for Log4Shell JNDI, ProxyShell autodiscover/PowerShell, FortiOS path traversal
- External attack-surface management (ASM) / exposure feed naming which of our edge assets run vulnerable Horizon/Exchange/FortiOS versions
- Threat-intel enrichment: actor IP/ASN watchlist (the pack IOC IPs + their hosting neighbors), GreyNoise-style mass-scanner classification

## Query starting point

Platform: `KQL / Microsoft Sentinel` — surface version-probing bursts on the actor's weaponized paths from suspect ASNs against assets we actually expose

```kusto
let actorIps = dynamic(["107.173.231.114","198.12.65.175","148.251.71.182","162.55.137.20",
    "51.89.169.198","142.44.251.77","51.89.135.142","51.89.190.128","51.89.178.210",
    "142.44.135.86","182.54.217.2"]);
let vulnPaths = dynamic([
    "jndi:ldap", "jndi:rmi", "${jndi",                       // Log4Shell (Horizon/Tomcat)
    "/autodiscover/autodiscover.json", "/powershell",         // ProxyShell/ProxyLogon (Exchange)
    "/remote/fgt_lang", "/remote/login", "..%2f",             // FortiOS CVE-2018-13379 traversal
    "X-Rq-BId", "X-BEID"]);                                   // ProxyShell exploit headers
W3CIISLog, FortinetLog                                        // union your edge sources here
| where TimeGenerated > ago(30d)
| where RequestURI has_any (vulnPaths) or ClientHeaders has_any (vulnPaths)
| extend actorInfra = iff(cIP in (actorIps), "actor_ip", "other")
| summarize probes = count(), paths = make_set(RequestURI, 15),
            firstSeen = min(TimeGenerated), lastSeen = max(TimeGenerated),
            statusSet = make_set(scStatus, 10)
         by cIP, actorInfra, targetHost = sSitename
// prioritise: many distinct vuln paths from one source (scan), or any hit from actor infra,
// or a source whose probes flipped from 404 to 200/500 (probe -> exploit success)
| where probes >= 5 or actorInfra == "actor_ip" or statusSet has_any ("200","500")
| order by actorInfra asc, probes desc
```

## Triage guidance

- **Likely malicious:** a source IP from (or neighboring) the actor IOC blocks sending Log4Shell JNDI / ProxyShell / FortiOS-traversal probes at an asset we confirm runs the vulnerable version; a scan pattern that walks vulnerable paths then returns a `200`/`500` on the exploit path (probe → success); probing tightly scoped to only the products this actor weaponizes rather than a broad web-app fuzz.
- **Likely benign / expected:** commodity mass-scanners (Shodan, Censys, GreyNoise-classified benign) and security researchers constantly probe Log4Shell/ProxyShell paths — high volume from a well-known scanner ASN against an asset we've patched is background noise; internal vulnerability scanners (Tenable/Qualys) will fire every signature and must be allowlisted by source; a single JNDI string in a user-agent with no follow-on is likely automated internet spray, not targeted.
- **Pivot next:** if a probe transitioned to exploitation on an exposed asset, pivot immediately to that host's process lineage — `ws_TomcatService.exe`/`w3wp.exe` spawning powershell/cmd (detection pack T1190/T1505.003/T1059.001), ASPX web-shell writes matching `aspx_[a-z]{13}.aspx`, and outbound to actor C2 domains — and treat as a live intrusion (escalate to incident-response-coordinator). If it's scanning only, add the source IP/ASN to the actor watchlist and confirm the probed asset's patch state via ASM.

## References

- https://www.sentinelone.com/labs/log4j2-in-the-wild-iranian-aligned-threat-actor-tunnelvision-actively-exploiting-vmware-horizon/
- https://www.secureworks.com/blog/cobalt-mirage-conducts-ransomware-operations-in-us
- https://www.microsoft.com/en-us/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
- https://attack.mitre.org/techniques/T1595/002/
- https://attack.mitre.org/techniques/T1190/
