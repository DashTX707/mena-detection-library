# Hunt: HEXANE adversary infrastructure — lookalike domains, tunneling DNS servers & staged malware

- **Hypothesis:** If HEXANE has stood up infrastructure to target us, then across passive-DNS, certificate-transparency and registration telemetry we should be able to surface it *before* it is used — newly-registered domains that typosquat our brand or a staffing/recruitment firm (Siamesekitten pattern), authoritative name servers configured to answer the long, high-entropy subdomain queries DanBot uses for DNS tunneling, and malware staged on that infrastructure (spoofed careers site, open directories). The finding is a domain/NS that stacks several of these attributes — lookalike name + young registration + tunneling-capable NS + hosted payload — not any one attribute alone.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development)
  - T1583.002 — Acquire Infrastructure: DNS Server (resource-development)
  - T1608.001 — Stage Capabilities: Upload Malware (resource-development)

- **Actor procedure:** HEXANE registers domains — some spoofing legitimate brands, including a fake careers/recruitment website in the Siamesekitten campaign — and operates attacker-controlled authoritative DNS servers to carry DanBot's DNS-tunneling C2. It stages its droppers and implants (DanDrop → DanBot, Milan) on that infrastructure for delivery to lured targets.
- **Why a hunt, not a rule:** This is off-victim resource development — the registration, NS setup and payload upload happen on adversary infrastructure we do not instrument, so there is nothing on our endpoints to alert on until the infra is *used*. The external signals we can see (new domains, CT-log certs, passive DNS) have an internet-scale base rate; distinguishing a HEXANE lookalike from the thousands of benign new domains daily requires human judgement over brand-similarity, registrar/hosting patterns and NS behaviour. The output is an intel finding that seeds detection/blocklists — a hunt that *feeds* the DNS-tunneling and phishing detection lanes, not a rule itself.

## Data sources required

- Passive DNS + newly-registered-domain feed; certificate-transparency logs (brand/lookalike monitoring)
- WHOIS/registrar + hosting-ASN enrichment (registrant reuse, VPS clustering)
- Authoritative-NS behavioural data — resolvers that answer abnormally long/high-entropy subdomain labels (DNS-tunneling capable)
- URLscan / sandbox / open-directory crawling of suspect domains (hosted payloads)
- Our own outbound DNS & proxy logs (has anything internal already resolved/contacted the candidate infra?)

## Query starting point

Platform: `KQL / Microsoft Sentinel` — internal resolution of freshly-surfaced lookalike/tunneling infrastructure

```kusto
// Feed a watchlist of candidate HEXANE domains/NS (lookalike + young reg + tunneling NS) from external monitoring,
// then check whether any internal host has ALREADY resolved or contacted it.
let hexane_infra = _GetWatchlist("hexane_candidate_infra") | project Domain, Reason;
DnsEvents
| where TimeGenerated > ago(30d)
| extend sld = strcat(tostring(split(Name, ".")[-2]), ".", tostring(split(Name, ".")[-1]))
| join kind=inner (hexane_infra | extend sld = Domain) on sld
| summarize queries = count(), firstSeen = min(TimeGenerated),
           hosts = make_set(ClientIP, 20), labels = make_set(Name, 20) by sld, Reason
| order by firstSeen asc
// A resolution here means candidate infra is already live in our environment -> escalate.
// With no internal hit, output remains an external intel finding seeding the blocklist/DNS-tunneling detection.
```

## Triage guidance

- **Likely malicious:** a <30-day-old domain that typosquats our brand or a recruitment firm, whose authoritative NS answers long high-entropy subdomains (DanBot tunneling shape), serving a macro-laden Office doc or DanDrop-like payload from an open directory; registrant/hosting reuse overlapping known HEXANE infrastructure; any internal host already resolving it.
- **Likely benign / expected:** legitimate brand-adjacent domains (partners, campaigns, CDN vanity hosts) and short-TTL/geo NS setups are common; new domains alone are not malicious. Suppress sanctioned marketing/partner registrations and known-good NS providers.
- **Pivot next:** confirmed HEXANE infra → push domain/NS to DNS-sinkhole + proxy blocklist and hand to the DNS-tunneling detection lane (T1071.004) as a robust selector; pivot to HUNT-03 for the personas fronting the domain and HUNT-01 for who was targeted. Any internal resolution of live infra is a probable active intrusion → escalate to IR.

## References

- https://www.secureworks.com/research/lyceum-takes-center-stage-in-middle-east-campaign
- https://www.clearskysec.com/siamesekitten/
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1583/002/
- https://attack.mitre.org/techniques/T1608/001/
