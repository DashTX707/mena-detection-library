# Hunt: Sea Turtle — off-victim actor infrastructure and tooling (nameservers, VPS, domains, tools)

- **Hypothesis:** Sea Turtle stands up a recognizable infrastructure kit before and during an operation, and traces of it appear at *our* perimeter and in external tracking data even though the infrastructure itself is off-victim. If the actor is building for or running an operation against us, then: (1) their nameserver domains and IPs (`ns1/ns2.intersecdns.com`, `ns1/ns2.lcjcomputing.com` → `95.179.150.101`) and DNS/service-blending registrations (`boord.info`, `systemctl.network`) appear in passive DNS near our zones or in newly-registered-domain feeds resembling our brand; (2) their rented MitM VPS IPs (the 26 Talos addresses plus `82.102.19.88`, `62.115.255.163`, `93.115.22.212`, `95.179.176.250`) and C2 hosts (`forward.boord.info`, `lo0.systemctl.network`, `193.34.167.245`) show up in our netflow/proxy/firewall egress; and (3) their tooling is fetched or run — e.g. a modified Socat retrieved from `http://193.34.167.245/c00n/socat`, or Adminer/SnappyTCP staged on a web host. This is an intel-driven infrastructure sweep: individual IOC hits are pivots, but a cluster tied to our estate is the finding.
- **ATT&CK:**
  - T1583.002 — Acquire Infrastructure: DNS Server (resource-development) — actor-operated nameservers serving falsified responses; hunt via passive-DNS/infrastructure tracking of `intersecdns.com` / `lcjcomputing.com` / `95.179.150.101`.
  - T1583.003 — Acquire Infrastructure: Virtual Private Server (resource-development) — rented MitM VPS set (26 documented IPs); hunt for those addresses in perimeter netflow and passive DNS.
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — registered nameserver/C2/blending domains (`boord.info`, `systemctl.network`); hunt via WHOIS + newly-registered-domain + CT feeds.
  - T1588.002 — Obtain Capabilities: Tool (resource-development) — modified Socat, Adminer, SnappyTCP obtained and staged; hunt for the tool-retrieval fetch and staged-tool artifacts as the on-victim landing of an off-victim acquisition.

- **Actor procedure:** Sea Turtle registers domains that blend with legitimate DNS/service naming and stands up dedicated nameservers (`intersecdns.com`, `lcjcomputing.com`) to serve falsified answers after a hijack. They rent a broad VPS fleet (26 MitM IPs across multiple providers/regions per Talos) to host the impersonation nodes, and additional hosts for C2 (`forward.boord.info`, `lo0.systemctl.network`). Tooling is public/off-the-shelf but operationalized: a *modified* Socat pulled from `193.34.167.245/c00n/socat` for tunnelling, Adminer staged in public web dirs for DB access, and SnappyTCP (from a since-removed GitHub project) compiled on-host. The infrastructure and tools are acquired off-victim; the observable moment for us is when they touch our perimeter or land on our hosts.
- **Why a hunt, not a rule:** Acquiring a VPS, registering a domain, or downloading a tool are off-endpoint acts with nothing for us to alert on directly. The IOC list *could* be dropped into blocklists — but static IPs/domains are Level-1 observables the actor rotates freely, so treating them as standing alerts yields stale coverage and false confidence. The hunt uses them as *pivots*: enrich each perimeter or passive-DNS hit with WHOIS/hosting/registration context, cluster related infrastructure (shared registrant, nameserver, ASN, TLS cert), and judge whether a cluster is oriented at us. That enrichment-and-clustering is analyst work. Durable, high-value observables that emerge (e.g. the modified-Socat retrieval URI path `/c00n/socat`, or SnappyTCP's on-host build) belong to the detection pack; this hunt feeds them, it does not replace them.
- **Note on scope:** the downstream *on-host* use of these tools (SnappyTCP webshell, socat relay, Adminer DB access) is covered by the detection lane (T1505.003, T1090, T1213.006) — this hunt covers the off-victim *acquisition/infrastructure* half and the perimeter traces that connect it to us.

## Data sources required

- Perimeter netflow / firewall / proxy egress logs (to match documented MitM + C2 IPs)
- Passive DNS + WHOIS + newly-registered-domain feeds (nameserver/domain infrastructure tracking)
- Certificate Transparency + hosting/ASN enrichment (infrastructure clustering)
- Web/proxy logs + host process telemetry for tool-retrieval fetches (`/c00n/socat`, Adminer, SnappyTCP source) as the on-victim landing point

## Query starting point

Platform: `Splunk SPL` — perimeter egress and tool-fetch sweep against the documented infrastructure set

```spl
(index=netflow OR index=proxy OR index=firewall)
| eval ioc_ip = coalesce(dest_ip, dest)
| search ioc_ip IN ("95.179.150.101","82.102.19.88","62.115.255.163","193.34.167.245",
                    "93.115.22.212","95.179.176.250","95.179.150.92")
         OR dest_host IN ("forward.boord.info","lo0.systemctl.network",
                          "ns1.intersecdns.com","ns2.intersecdns.com",
                          "ns1.lcjcomputing.com","ns2.lcjcomputing.com")
         OR url="*://193.34.167.245/c00n/socat*"                    /* modified-Socat retrieval */
| stats count values(url) as urls values(dest_host) as hosts
        min(_time) as first max(_time) as last by src_ip ioc_ip
| eval tool_fetch = if(match(mvjoin(urls," "), "c00n/socat"), 1, 0) /* pivot: on-host tool acquisition */
| table src_ip ioc_ip hosts urls tool_fetch first last count
| sort - tool_fetch - count
```

## Triage guidance

- **Likely malicious:** any internal host egressing to the documented C2/MitM IPs or `boord.info`/`systemctl.network` C2 hosts; a retrieval of `/c00n/socat` from `193.34.167.245`; our authoritative zone delegating to `intersecdns.com`/`lcjcomputing.com` (ties to HUNT-01); a freshly registered domain closely resembling our brand sharing a registrant/nameserver/ASN with known actor infrastructure.
- **Likely benign / expected:** these IPs sit in shared commercial-VPS ranges (Vultr, DigitalOcean, M247) that also host benign services — a single netflow hit to a reused IP may be unrelated; passive-DNS proximity is not causation; Socat and Adminer are legitimate admin/DBA tools in many environments. Enrich and cluster before flagging; a lone stale-IOC hit is a pivot, not a verdict.
- **Pivot next:** a perimeter hit that clusters with a DNS or cert anomaly (HUNT-01/02) or a tool-fetch landing on a web host indicates an operation touching us — escalate to incident-response-coordinator, pivot to the on-host detection lane (SnappyTCP T1505.003, socat T1090, Adminer T1213.006, anti-forensics), and pass any durable observable (the `/c00n/socat` URI, SnappyTCP build/`sy.php`) to detection-engineering. Refresh the IOC watchlists from the latest Talos/Hunt & Hackett appendices rather than trusting the static set.

## References

- https://blog.talosintelligence.com/seaturtle/
- https://www.huntandhackett.com/blog/turkish-espionage-campaigns
- https://attack.mitre.org/techniques/T1583/002/
- https://attack.mitre.org/techniques/T1583/003/
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1588/002/
