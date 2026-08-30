# Hunt: CyberAv3ngers C2 domain infrastructure — passive-DNS & newly-registered-domain hunt

- **Hypothesis:** If CyberAv3ngers acquired attacker-controlled domains for IOCONTROL C2, then although the registration itself is off-victim, evidence of *use* should surface in our egress and resolution telemetry: any host — especially an OT/IoT device or its fronting gateway — resolving or connecting to the known C2 domain (`tylarion867mino.com` / `uuokhhfsdlk.tylarion867mino.com`) or to sibling infrastructure sharing its registration pattern (a random-looking sub-label under a nonsense second-level domain, registered shortly before an operation, resolving via DoH to hosting in the same ASN as `159.100.6.69`). Because the OT endpoints resolve C2 over Cloudflare DoH to evade the local resolver, the hunt must combine passive DNS, egress-boundary logs, and newly-registered-domain enrichment rather than relying on internal resolver logs alone.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development)

- **Actor procedure:** The actors registered `tylarion867mino.com` on 2023-11-23 (WHOIS) and used the subdomain `uuokhhfsdlk.tylarion867mino.com` as the IOCONTROL C2 hostname to manage compromised devices; before connecting, IOCONTROL resolved that hostname via Cloudflare DoH (returning C2 IP `159.100.6.69`) instead of the device's normal resolver, to evade DNS monitoring.
- **Why a hunt, not a rule:** The specific domain and IP are Level-1 IOCs — the actor rotates them cheaply, so a blocklist rule on `tylarion867mino.com` is stale the moment infrastructure changes and gives false comfort. Domain acquisition leaves no victim-side event, so the streaming-rule surface is thin. The hunt's durable value is *pattern-based enrichment and pivoting*: newly-registered / low-reputation domains with the actor's naming shape (random sub-label under a gibberish base), resolved via DoH from OT segments, pointing into shared hosting near known C2 — a registration/behaviour cluster judgement that is analyst work, not a signature. Confirmed live domains can be handed to threat-intel/blocking, but the *hunt* targets the reusable infrastructure pattern, not the single string.

## Query starting point

Platform: `Passive DNS + egress DNS/DoH logs (SOF-ELK / Elastic) — known C2 + newly-registered look-alike infra from OT segments`

```elasticsearch
# (a) direct: any internal resolution/connection to known C2 infra (pivot anchor)
(dns.question.name:("tylarion867mino.com" or "*.tylarion867mino.com")
   or destination.ip:"159.100.6.69")
| stats hits=count(), first=min(@timestamp) by source.ip, dns.question.name, destination.ip
# any hit from an OT/IoT segment is high-severity

# (b) pattern hunt: OT/gateway sources resolving NRD / low-rep domains via DoH,
#     with the actor's naming shape (random sub-label under a gibberish base)
source.ip in (OT_IOT_SEGMENT_CIDRS)
  and (destination.domain in (KNOWN_DOH_ENDPOINTS) or destination.ip:"1.1.1.1")
| lookup domain_age, domain_reputation, resolved_asn on dns.question.name
| where domain_age_days < 90                       # newly-registered-domain
    and shannon_entropy(second_level_label) > 3.5  # gibberish base domain
    and resolved_asn in (asn_of 159.100.6.69)      # shared-hosting pivot
| stats devices=dcount(source.ip) by dns.question.name, resolved_asn
```

## Data sources required

- Passive DNS (internal PDNS sensor + external PDNS/VirusTotal) for resolution history and sibling domains
- Egress DNS + DoH-egress logs at the boundary (OT segment → 1.1.1.1 / known DoH endpoints)
- WHOIS / newly-registered-domain feed + domain-reputation enrichment (age, registrar, gibberish scoring)
- ASN/hosting enrichment to cluster infrastructure near the known C2 IP
- Firewall/proxy connection logs from OT/IoT segments (source→external destination)

## Triage guidance

- **Likely malicious:** any host — especially an OT/IoT device or gateway — resolving or connecting to `tylarion867mino.com` / its subdomain or `159.100.6.69`; a newly-registered gibberish domain with a random sub-label resolved via DoH from an OT segment into hosting adjacent to known C2; the same look-alike domain queried by multiple OT devices (shared C2).
- **Likely benign / expected:** DoH to `1.1.1.1` can be legitimate on some modern devices/browsers, and newly-registered domains are often benign CDNs/SaaS — the finding is the *stack* (NRD + gibberish + DoH-from-OT + shared-ASN + OT source), not any single attribute. Whitelisted vendor-cloud domains and sanctioned DoH usage should be baselined out.
- **Pivot next:** a confirmed hit → pivot the source device into HUNT-01/02/03 (persistence, shell-exec, broker beacon) and extract sibling domains from passive DNS to expand the infrastructure cluster; feed confirmed live domains/IPs to threat-intel for blocking and to the detection pack (T1071.004 DoH egress). A resolution from a production OT device is an active compromise indicator → escalate to incident-response-coordinator.

## References

- https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a
- https://attack.mitre.org/techniques/T1583/001/
