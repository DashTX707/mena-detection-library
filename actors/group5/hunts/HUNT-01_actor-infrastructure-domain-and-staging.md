# Hunt: Group5 actor infrastructure — registered domains and staged malware

- **Hypothesis:** If Group5 stood up watering-hole/staging infrastructure to target Syrian opposition users, then passive-DNS and web-proxy telemetry from those users will show resolutions and HTTP(S) fetches to a newly-registered, thinly-hosted political-themed domain (the historical archetype being `assadcrimes[.]info` on Iran-based Hostnegar, shared IP `212.7.195.171`) that (a) impersonates a real opposition figure in its WHOIS registrant, and (b) serves a fake "Adobe Flash Player update" page whose click leads to an executable download — a never-before-seen domain with an unexpected-relationship between registrant identity and content.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development)
  - T1608.001 — Stage Capabilities: Upload Malware (resource-development)
- **Actor procedure:** Group5 registered `assadcrimes.info` (June 2015) under the *stolen identity* of Syrian opposition figure Noura Al-Ameer, hosted it on the Iran-based provider Hostnegar (shared IP `212.7.195.171`), seeded it with scraped Syrian-opposition and human-rights content as a lure, and staged malicious PPSX documents plus Windows/Android droppers behind a fake Adobe Flash Player update download page.
- **Why a hunt, not a rule:** The single historical domain/IP is aged and now sinkholed — an IOC block, not a hunt. The durable hunt is the *pattern of adversary infrastructure acquisition*: a freshly-registered political-lure domain, resolving to shared low-reputation hosting, with a registrant that impersonates a known target, serving fake-software-update executable downloads to a narrow victim set. That composite requires WHOIS/passive-DNS correlation and analyst judgement about identity abuse — it cannot be reduced to a reliable standing alert without high false positives on legitimate new political sites.

## Data sources required

- Passive DNS / resolver logs for the protected user population (first-seen timestamps, resolving IP, TTL)
- Web-proxy / HTTP(S) logs (URL path, referrer, content-type, downloaded file extension)
- WHOIS / domain-registration enrichment (registrant name, creation date, registrar, hosting ASN)
- Threat-intel enrichment on resolving IP / ASN reputation

## Query starting point

Platform: `Splunk SPL`

```
index=proxy sourcetype=*proxy* (uri_path="*flash*update*" OR uri_path="*adobe*flash*"
    OR uri_path="*/update*.exe" OR uri_path="*/download*.exe" OR uri_path="*.apk")
| eval fname=lower(mvindex(split(uri_path,"/"),-1))
| where match(fname,"\.(exe|apk|scr)$")
| lookup dns_first_seen domain AS site OUTPUT first_seen_epoch
| eval domain_age_days=round((now()-first_seen_epoch)/86400,0)
| where domain_age_days < 120
| stats count values(uri_path) as paths values(fname) as downloaded_files
        dc(src_ip) as victim_count values(dest_ip) as resolved_ips min(_time) as first_hit
        by site domain_age_days
| sort - count
```

## Triage guidance

- **Likely malicious:** A young domain (registered within months) serving `.exe`/`.apk` from a fake software-update page to a small cluster of civil-society/opposition users; WHOIS registrant that names a real activist/journalist (identity theft); hosting on low-reputation shared IPs in ASNs with no business nexus to the users; political/human-rights lure content on a site that otherwise has no history.
- **Likely benign / expected:** Legitimate CDN-served software updates from vendor-owned domains (verify registrant = the real vendor); established news/advocacy sites with long registration history; internal test hosts. Baseline the population's normal political-media browsing before flagging.
- **Pivot next:** If a staging domain is confirmed, pull every victim that fetched a payload and pivot to HUNT-02 (crypter/RAT capability on the downloaded file) and to the delivery detections (PPSX/CVE-2014-4114, masquerading droppers). If any victim executed a download, **escalate to incident-response**.

## References

- https://citizenlab.ca/2016/08/group5-syria/
- https://attack.mitre.org/groups/G0043/
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1608/001/
