# Hunt: Bahamut — single-use look-alike domains, CDN-fronting & certificate staging

- **Hypothesis:** If Bahamut is provisioning infrastructure against us, then because their signature is **single-use, weekly/daily-rotated, Cloudflare-fronted look-alike domains carrying fresh Let's Encrypt certificates**, we should be able to cluster near-real-time indicators *before* delivery lands: certificate-transparency issuance for Let's Encrypt certs on domains that are edit-distance-close to our brand or to trusted news/VPN/app vendors, resolving into Cloudflare ranges, registered within the last N days, and — the on-victim corroborator — first-seen DNS resolutions of those same young domains from inside our estate. A CT hit alone is intel; a CT hit for a look-alike that our resolvers then query within its first days of life is the finding.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — registration of large numbers of single-use look-alike domains impersonating login portals, news outlets and app/VPN vendors (e.g. thesecurevpn[.]com), rotated weekly/daily; hunt via newly-registered/brand-permutation feeds.
  - T1583.006 — Acquire Infrastructure: Web Services (resource-development) — C2/distribution fronted behind Cloudflare and a fake-news web-service network; hunt via infrastructure clustering and CDN-fronting analysis.
  - T1608.003 — Stage Capabilities: Install Digital Certificate (resource-development) — Let's Encrypt TLS certs installed on look-alike C2/distribution endpoints (SafeChat C2); hunt via certificate-transparency monitoring of look-alike domains.

- **Actor procedure:** BlackBerry documented Bahamut rotating single-use infrastructure weekly or even daily to frustrate tracking, standing up look-alike domains for portals, news outlets and app vendors. The mobile campaigns confirm the pattern: thesecurevpn[.]com mimicked the real SecureVPN brand to distribute trojanized SoftVPN/OpenVPN, C2 sat behind Cloudflare (104.21.10.79, 172.67.185.54 are shared Cloudflare ranges), and the SafeChat/CoverIm C2 (laborer-posted[.]nl) used a Let's Encrypt certificate to present a trusted-looking encrypted channel. The tradecraft is deliberately ephemeral — indicators expire fast, so hunting the *pattern of provisioning* (young age + brand proximity + CDN-fronting + fresh DV cert) beats chasing any single domain/IP.
- **Why a hunt, not a rule:** Every atomic indicator here is Level-1 on the Summiting pyramid — a specific domain or Cloudflare IP the actor discards within days — so an IOC blocklist is stale on arrival and Cloudflare IPs are shared across millions of benign sites (false-positive minefield). The durable signal is the *cluster* (brand-edit-distance + newly-registered + Let's Encrypt-on-CT + Cloudflare-resolving) correlated with a *first-seen internal resolution*, which requires human clustering judgement across CT, WHOIS-age, DNS and proxy telemetry — hunt work, not an alert. If a specific young look-alike is confirmed hostile and actively resolved internally, promote *that resolved domain* to the detection pack's DNS/proxy blocklist (T1071.001) and to an internal-first-resolution analytic; do not try to alert on "a Let's Encrypt cert was issued somewhere."

## Data sources required

- Certificate-transparency stream (e.g. crt.sh / Censys) filtered to Let's Encrypt issuance on brand-permutation domains of our org and of trusted news/VPN/app vendors.
- Passive DNS + WHOIS/registration-age enrichment (domain age, registrar, nameserver, resolving ASN — flag Cloudflare-fronted).
- Internal DNS resolver logs + web-proxy logs (first-seen resolution/connection of young look-alike domains from inside the estate).
- Brand-permutation / newly-registered-domain feed keyed to our brand and to the vendor brands Bahamut impersonates.

## Query starting point

Platform: `Splunk SPL (CT + WHOIS-age enrichment fused with internal DNS first-seen)`

```spl
`comment("(a) CT issuance: Let's Encrypt DV certs on brand-permutation look-alikes, last 7d")`
index=ct_logs issuer_ca="Let's Encrypt"
| eval brand_dist=min(levenshtein(domain,"ourbrand"), levenshtein(domain,"securevpn"), levenshtein(domain,"softvpn"))
| where brand_dist<=2
| lookup whois_age domain OUTPUT registered_days_ago resolving_asn
| where registered_days_ago<=14
| eval cdn_fronted=if(resolving_asn IN("AS13335"),"cloudflare","other")
| fields domain registered_days_ago resolving_asn cdn_fronted brand_dist
`comment("(b) join to internal first-seen resolutions of those same young domains")`
| join type=inner domain
    [ search index=dns earliest=-14d
      | stats earliest(_time) as first_internal_seen count as internal_queries
              values(src_ip) as querying_hosts by query
      | rename query as domain ]
| where internal_queries>0
| sort - registered_days_ago | table domain registered_days_ago cdn_fronted first_internal_seen internal_queries querying_hosts
```

## Triage guidance

- **Likely malicious:** a look-alike of *our* brand or of a VPN/news/app vendor, registered within days, carrying a fresh Let's Encrypt cert, Cloudflare-fronted, that one or more internal hosts have *just started* resolving; a cluster of such domains sharing a registrar/nameserver/creation-window (rotation signature).
- **Likely benign / expected:** legitimate services and CDNs use Let's Encrypt + Cloudflare ubiquitously — the cert issuer and CDN alone mean nothing; a young domain with no brand proximity and no internal resolution is background noise; your own marketing/regional domains and their CDN configs (baseline and allowlist them).
- **Pivot next:** if an internally-resolved young look-alike clusters as hostile, pivot to which users/hosts resolved it and why (link click → HUNT-04, portal → HUNT-01), push the domain to the C2/distribution blocklist (detection pack T1071.001/T1573.002/T1571), and preserve the CT/WHOIS cluster to pre-empt the next rotation. If internal hosts connected (not just resolved), treat as possible active delivery and escalate.

## References

- https://www.welivesecurity.com/2022/11/23/bahamut-cybermercenary-group-targets-android-users-fake-vpn-apps/
- https://www.cyfirma.com/research/apt-bahamut-targets-individuals-with-android-malware-using-spear-messaging/
- https://blogs.blackberry.com/en/2020/10/blackberry-uncovers-massive-hack-for-hire-group-targeting-governments-businesses-human-rights-groups-and-influential-individuals
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1583/006/
- https://attack.mitre.org/techniques/T1608/003/
