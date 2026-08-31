# Hunt: OilAlpha DDNS infrastructure and commodity-RAT acquisition tracking

- **Hypothesis:** If OilAlpha stood up its "version"-themed dynamic-DNS infrastructure and armed it with commodity SpyNote/SpyMax/njRAT payloads, then passive-DNS / TI / proxy telemetry will show hosts in the org resolving or fetching from lookalike DDNS domains that stack anomalies — a masquerading brand token (`car`/`nrc`/`ksr`/`uns` + `version`), a DDNS-provider suffix (`ddns.net`/`sytes.net`/`dynns.com`/`serveftp.com`), and (where PCAP/JA3 exists) a commodity-RAT beacon fingerprint — rather than any single benign DDNS lookup.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development)
  - T1588.002 — Obtain Capabilities: Tool (resource-development)
- **Actor procedure:** OilAlpha registers large sets of lookalike DDNS domains themed around victim orgs plus the string "version" (e.g. `carversion.ddns.net`, `nrcversion.ddns.net`, `ksrversion.ddns.net`, `unsversion.ddns.net`, `*hid.sytes.net` variants) and a dedicated credential-theft domain `kssnew.online` (registered ~Jan 2023). It arms this infrastructure with widely available commodity RATs — SpyNote/SpyMax/SpyC23 for Android and njRAT (Bladabindi) for Windows — rather than bespoke malware, with C2 near-exclusively on Yemen PTC / DigitalOcean-style ranges.
- **Why a hunt, not a rule:** Domain registration and tool acquisition happen off-victim; DDNS hostnames rotate continuously and commodity RATs are shared across many unrelated actors, so a static domain/hash blocklist decays fast and generates cross-actor noise. The durable hunt is a *pattern* — the naming grammar (org-token + "version" on a free-DDNS provider) plus commodity-RAT beacon traits — surfaced by proactively sweeping resolver/proxy/TI data and infrastructure feeds, work that needs analyst pivoting (WHOIS, passive DNS, registrant/host overlap) rather than a fire-and-forget alert.

## Data sources required

- Recursive DNS / resolver logs (queried FQDN, resolved IP, first-seen)
- Web proxy / firewall egress logs (destination host, port, bytes)
- Threat-intel / passive-DNS / WHOIS enrichment for DDNS-provider and registrant pivoting
- Network IDS / PCAP with JA3 or commodity-RAT signatures (SpyNote/SpyMax/njRAT), where available

## Query starting point

Platform: `Splunk SPL`

```
index=dns OR index=proxy
| eval q=lower(coalesce(query,domain,url_domain))
| rex field=q "(?<sld>[a-z0-9\-]+)\.(?<provider>ddns\.net|sytes\.net|dynns\.com|serveftp\.com)$"
| where isnotnull(provider)
| eval brand_masq=if(match(sld,"(car|nrc|ksr|uns|version|hid|hm|rm)"),1,0)
| eval known_ioc=if(match(q,"(carversion|ho1hm2|ho2hm1|ksrversion|nrcversion|nrcversionhid|carversionhid|ksrversionhid|unsversion|unsversionhid|ufufw|midrmversion|golom|coldrmversion|reportss|hotrmversion|sh1177|euseus)"),1,0)
| stats count min(_time) as first_seen values(sld) as subdomains
        values(dest_ip) as resolved_ips dc(src_ip) as internal_hosts
        by q, provider, brand_masq, known_ioc
| eval score=known_ioc*2 + brand_masq
| where score>=1
| sort - score, - count
```

## Triage guidance

- **Likely malicious:** Resolution of any intel DDNS host (`*version.ddns.net`, `*hid.sytes.net`, `ufufw.dynns.com`, `reportss.serveftp.com`, `sh1177.ddns.net`) or `kssnew.online`; a newly-registered DDNS name combining an aid-org token with "version" on a free provider; resolved IP overlapping OilAlpha ranges (206.189.98.34, 176.123.21.4, 145.14.156.148, 141.255.144.8, 134.122.75.238, 141.255.145.221) or Yemen PTC space; a commodity SpyNote/SpyMax/njRAT beacon signature on the same host.
- **Likely benign / expected:** Legitimate personal/vendor use of dynamic DNS (home labs, IoT vendors, CCTV DVRs) with no org-brand token; well-known DDNS hosts already in the wiki baseline. A single DDNS lookup with no brand-masquerade token and no RAT beacon is thin — do not flag alone.
- **Pivot next:** For a matched host, pivot WHOIS/passive-DNS on the registrant and resolved IP to enumerate sibling domains; feed confirmed live C2 domains/IPs and any reproducible commodity-RAT JA3 back to detection-engineering (these are repeatable/precise — Summiting Level ~2 network observable) and to intel. On any host that both resolved the domain and ran a RAT beacon, escalate and run HUNT-03/HUNT-04.

## References

- https://assets.recordedfuture.com/insikt-report-pdfs/2024/cta-2024-0709.pdf
- https://www.recordedfuture.com/research/oilalpha-likely-pro-houthi-group-targeting-arabian-peninsula
- https://cyberscoop.com/oil-alpha-houthi-yemen/
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1588/002/
