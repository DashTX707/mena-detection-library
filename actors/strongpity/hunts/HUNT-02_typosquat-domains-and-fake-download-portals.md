# Hunt: StrongPity — typosquat delivery domains & fake download-portal staging

- **Hypothesis:** If StrongPity is standing up (or reusing) its watering-hole delivery infrastructure against our users, then off-victim it has **registered typosquat/lookalike domains** impersonating encryption/archiver/utility vendors and **hosted trojanized installers** on them — and on-victim the tell is a DNS/proxy resolution to a lookalike vendor domain (or a redirect out of a legitimate download aggregator such as `tamindir.com`) immediately followed by an installer download. The finding pairs an off-victim infrastructure discovery (a newly-registered `rarlab`/`winrar`/`truecrypt`-lookalike with an installer-hosting page and, ideally, a matching trojanized-installer hash) with any on-victim resolution to that domain. Either half alone is thin — a lookalike domain with no user touching it is intel backlog, a single odd DNS lookup is noise — the pair is the finding.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — typosquat registrations (`ralrab[.]com`, `winrar[.]it`, `winrar[.]be`, `true-crypt[.]com`) mimicking real vendors.
  - T1608.004 — Stage Capabilities: Drive-by Target (resource-development) — replica WinRAR/TrueCrypt download pages stood up as the watering hole.
  - T1608.001 — Stage Capabilities: Upload Malware (resource-development) — trojanized installers hosted on that staging infra; retro-hunt known hashes on download telemetry.

- **Actor procedure:** Kaspersky's 2016 reporting documented StrongPity redirecting encryption-software seekers to actor-controlled typosquats — `ralrab[.]com` (vs `rarlab.com`), `winrar[.]it`, `winrar[.]be`, and `true-crypt[.]com` (a replica of the TrueCrypt site), with victims also funneled from the legitimate `tamindir.com` download portal — that served trojanized WinRAR (`wrar531*.exe`, `winrar-x64-531*.exe`) and TrueCrypt (`TrueCrypt-Setup-7.1a.exe`, `TrueCrypt-7.2.exe`) builds. ESET's 2017 campaign added `downloading.internetdownloading[.]co` as a distribution host. The domains are chosen for maximum visual/typo proximity to the impersonated brand and for TLD ambiguity (`.it`/`.be` matching the targeted Italian/Belgian users).
- **Why a hunt, not a rule:** Domain registration and page-staging are entirely off-victim — there is no endpoint event to alert on until a user resolves the domain, and by then delivery may already be done. A standalone "resolved a lookalike domain" alert produces enormous false positives (brand-monitoring lookalikes, parked domains, legitimate regional vendor TLDs). The value is in *curating* candidate typosquats (CT-log + passive-DNS + registration-anomaly hunting around the impersonated vendors), retro-hunting the known trojanized-installer hashes across download telemetry, and then correlating a curated hit with an on-victim resolution/download — analyst fusion, not a rule. A concrete confirmed delivery domain is a Level-1/2 IOC: hand it to detection-engineering as a blocklist/watchlist entry, but do not build the hunt on it, since the actor rotates domains freely.

## Data sources required

- Certificate-Transparency log monitoring + passive DNS + a typosquat/brand-monitoring feed keyed to impersonated vendors (rarlab/winrar, truecrypt, ccleaner, videolan, opera, skype, 7-zip, winbox)
- Internal DNS resolution logs and web-proxy logs (client, queried domain, referer chain out of download aggregators like `tamindir.com`)
- EDR file-creation telemetry with SHA hashing (to retro-hunt the known trojanized-installer hashes from the pack)
- WHOIS/registration enrichment (registrar, creation date, registrant) for candidate lookalikes

## Query starting point

Platform: `Splunk SPL` — surface on-victim resolutions to curated lookalike vendor domains and pair with any installer download

```spl
index=dns OR index=proxy earliest=-30d
| eval domain=lower(coalesce(query, dest_host, url_domain))
``` ``` fuzzy vendor-lookalike match: brand token present but NOT the canonical vendor domain ```
| where (like(domain,"%rarlab%") OR like(domain,"%winrar%") OR like(domain,"%truecrypt%")
        OR like(domain,"%true-crypt%") OR like(domain,"%ccleaner%") OR like(domain,"%winbox%")
        OR like(domain,"%internetdownloading%") OR like(domain,"%ralrab%"))
        AND NOT cidrmatch("0.0.0.0/0", domain)
        AND domain!="rarlab.com" AND domain!="www.rarlab.com"
        AND domain!="videolan.org" AND domain!="7-zip.org"
| stats earliest(_time) as first_seen latest(_time) as last_seen values(domain) as domains
        count by src_ip, user
``` ``` join to any installer .exe that landed on the same host shortly after ```
| join type=left src_ip [ search index=edr sourcetype=file_create earliest=-30d
    file_name IN ("*winrar*.exe","*wrar*.exe","*truecrypt*.exe","*ccleaner*.exe","*vlc*.exe","*winbox*.exe")
    | eval known_bad=if(sha1 IN ("4ad3ecc01d3aa73b97f53e317e3441244cf60cbd","8b33b11991e1e94b7a1b03d6fb20541c012be0e3",
        "49c2bcae30a537454ad0b9344b38a04a0465a0b5","e17b5e71d26b2518871c73e8b1459e85fb922814"),"YES","no")
    | stats values(file_name) as dropped_installers values(known_bad) as hash_hit by src_ip ]
| sort - last_seen
```

## Triage guidance

- **Likely malicious:** an internal host resolving a *newly-registered* lookalike (`ralrab[.]com`, `winrar[.]it/.be`, `true-crypt[.]com`, or a fresh analogue) whose page hosts an installer, especially when a WinRAR/TrueCrypt/etc. `.exe` lands on that same host minutes later — and decisively if that binary's hash matches the pack's known trojanized-sample list. A referer chain that passes *through* a legitimate aggregator (`tamindir.com`) into the lookalike strengthens it.
- **Likely benign / expected:** legitimate regional vendor sites and resellers use ccTLDs (`.it`, `.be`) and brand tokens lawfully; security-vendor sandboxes, brand-protection scanners, and threat-intel crawlers in your own estate deliberately resolve lookalike domains — exclude known research/scanner hosts. Parked/for-sale typosquats with no hosted installer are intel to watch, not an on-victim finding.
- **Pivot next:** confirmed delivery domain → pivot on its hosting IP/ASN, TLS cert, and co-hosted domains to enumerate the wider staging cluster (feed HUNT-03), retro-hunt the served hash fleet-wide, and hand the confirmed domain/hash to detection-engineering for blocklisting. If a user executed the served installer, escalate onto the host-side kill chain (HUNT-05, detection-pack T1204.002).

## References

- https://securelist.com/on-the-strongpity-waterhole-attacks-targeting-italian-and-belgian-encryption-users/76147/
- https://www.welivesecurity.com/2017/12/08/strongpity-like-spyware-replaces-finfisher/
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1608/004/
- https://attack.mitre.org/techniques/T1608/001/
