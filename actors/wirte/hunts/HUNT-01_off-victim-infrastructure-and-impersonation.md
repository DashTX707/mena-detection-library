# Hunt: WIRTE off-victim infrastructure & brand impersonation — themed Cloudflare-fronted domains, compromised-partner senders, staged archives and Havoc tooling

- **Hypothesis:** If WIRTE is preparing or running an operation against us, then before/around delivery we should be able to surface its off-victim footprint from *our own* telemetry: proxy/DNS resolutions and TLS SNI to newly-registered health/finance/regional-country-themed domains fronted by Cloudflare (e.g. `master-dental[.]com`, `king-pharmacy[.]com`, `saudiday[.]org`, `jordansons[.]com`, `egyptican[.]com`, `requestinspector[.]com`), inbound mail from a *trusted third-party partner mailbox* that suddenly fails DMARC/alignment or blasts atypical recipients (compromised-account abuse), archive/PDF downloads from those themed domains, and Havoc-default C2 behaviours (named-pipe patterns, sleep/beacon cadence) on the wire — clustered by lure theme and impersonated brand (INCD, ESET, Palestinian Authority).
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — themed Cloudflare-fronted C2/phishing domains
  - T1586.002 — Compromise Accounts: Email Accounts (resource-development) — Oct-2024 wiper sent from a compromised Israeli ESET-reseller mailbox
  - T1587.001 — Develop Capabilities: Malware (resource-development) — in-house Ferocious/LitePower/IronWind/SameCoin; shared XOR routine = code-overlap attribution pivot
  - T1588.002 — Obtain Capabilities: Tool (resource-development) — operationalised open-source Havoc Demon + donut
  - T1608.001 — Stage Capabilities: Upload Malware (resource-development) — RAR/ZIP/PDF + HTML-tag-embedded payloads staged on own domains, served only to the expected user agent
  - T1684.001 — Improper Impersonation: Impersonation (stealth) — INCD/ESET/Palestinian-Authority brand and authority impersonation
- **Actor procedure:** WIRTE registers themed domains on a consistent naming convention (health, finance, regional-country) fronted by Cloudflare to hide the real VPS IP, stages RAR/ZIP archives, lure PDFs and next-stage payloads embedded in HTML tags on those servers (returned only to requests carrying the expected hardcoded user agent, otherwise redirected to a legitimate news/health site), develops its loaders in-house (a unique XOR routine links IronWind's `propsys.dll` to the SameCoin wiper — same developer), and buys/operationalises Havoc + donut. Delivery leans on impersonation: SameCoin posed as an INCD security update (Feb 2024) and an ESET security notice sent from a genuinely compromised reseller mailbox (Oct 2024); espionage lures mimic Palestinian Authority themes.
- **Why a hunt, not a rule:** the resource-development itself is off-victim and invisible to us until it touches our environment, so this is retro-hunt and correlation, not an alert. IOCs (Level 1 — the specific domains/IPs) expire fast and are pivots, not the basis. The durable signal is the *pattern* stacked on one theme: never-before-seen themed domain + Cloudflare fronting + first-contact from a partner sender that just broke DMARC + a same-theme archive fetch. Newly-registered-domain and DMARC-fail both have large benign base rates alone; the find is their co-occurrence around one lure cluster, which needs per-environment baselining of normal partner mail and normal proxy destinations.

## Data sources required

- Proxy / web-gateway logs (URL, TLS SNI, server cert CN, referer, downloaded content-type) and DNS resolution logs
- Passive DNS / newly-registered-domain and threat-intel enrichment (domain age, Cloudflare ASN fronting, cert transparency CN pivots)
- Mail-gateway logs with DMARC/DKIM/SPF alignment results, sender domain, first-seen-sender, attachment/link metadata
- NDR / Zeek or EDR network telemetry for Havoc named-pipe and beacon-cadence characteristics

## Query starting point

Platform: `Splunk SPL`

```
index=proxy OR index=dns
| eval dom=lower(coalesce(ssl_server_name, query, dest_host))
| `enrich_domain_age(dom)`         /* age_days, registrar, front_asn from PDNS/TI */
| eval themed=if(match(dom,"(?i)(dental|pharmacy|health|bank|refugee|tour|nutrition|clinic|knee|economy)")
                 OR match(dom,"(?i)(saudi|jordan|egypt|lebanon|iraq|arabia)"),1,0)
| eval cf_front=if(match(front_asn,"(?i)cloudflare"),1,0)
| where (age_days < 60 AND (themed=1 OR cf_front=1))
        OR dom IN ("master-dental.com","requestinspector.com","theshortner.com",
                   "king-pharmacy.com","saudiday.org","jordansons.com","egyptican.com")
| stats count values(dom) as domains values(src_ip) as hosts
        values(http_content_type) as fetched min(_time) as first by dom
| sort first
```

Correlate hits against inbound mail: `index=mail | where dmarc_result="fail" OR (sender_is_known_partner=1 AND dkim_align="fail")` and against archive/PDF downloads (`http_content_type IN ("application/x-rar","application/zip","application/pdf")`) from the same themed domains.

## Triage guidance

- **Likely malicious:** first-contact resolution/fetch to a <60-day-old health/finance/country-themed domain behind Cloudflare; an archive or lure PDF pulled from such a domain; a trusted partner mailbox (e.g. a security-vendor reseller) that suddenly fails DMARC or mails an unusual recipient set with an EXE/ZIP; server cert CN pivoting to other themed domains (`firstohiobank[.]com`, `dentalmatrix[.]net`); Havoc-default named-pipe/beacon signatures on the wire.
- **Likely benign / expected:** legitimate new SaaS/marketing domains behind Cloudflare; genuine partner mail that passes alignment; security-vendor bulletins from the vendor's real infrastructure. Baseline your real partners' sending domains and your normal Cloudflare-hosted destinations and suppress them.
- **Pivot next:** if a themed-domain fetch or impersonating partner mail is confirmed, pivot forward to the delivery/click hunt (HUNT-02), to LOLBIN execution (HUNT-03) and web C2 (HUNT-08); pivot the domain via cert CN and Cloudflare-behind IP to the wider WIRTE cluster and hand confirmed live C2 domains to detection-engineering as blocklist entries (IOC pivots, not the hunt basis). A compromised partner mailbox actively mailing your users is an incident — escalate to incident-response-coordinator.

## References

- https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/
- https://securelist.com/wirtes-campaign-in-the-middle-east-living-off-the-land-since-at-least-2019/105044/
- https://attack.mitre.org/groups/G0090/
