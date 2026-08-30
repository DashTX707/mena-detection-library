# Hunt: SideWinder — look-alike government & port-authority domain infrastructure (off-victim)

- **Hypothesis:** If SideWinder is preparing or running a campaign against our estate, then *before* any endpoint is touched the adversary will stand up typosquatted / brand-impersonating domains echoing our own organisation, our ministry/government partners, or the regional port authorities we correspond with (Port of Alexandria, Djibouti port, Saudi MOFA), and those domains will surface as newly-registered look-alikes AND, shortly after, as the destination of a link in a lure email or as a resolved host in our DNS/proxy logs. Either signal alone is thin — a newly-registered look-alike domain is a dime a dozen, and a single odd DNS lookup is noise — but a *never-before-seen brand-impersonating domain that our users are actually resolving or being linked to* is the finding.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — SideWinder registers look-alike/typosquatted domains impersonating regional governments, ministries and port authorities to host lures and staging/C2 (mofa-gov-sa.direct888[.]net, depo-govpk[.]com, portdedjibouti[.]live, pncert[.]info).
  - T1598.003 — Phishing for Information: Spearphishing Link (reconnaissance) — pre-payload targeting messages carry links to these look-alike domains to profile/engage recipients before delivering the exploit chain; the mail-gateway URL is the on-our-side tell of an off-victim recon act.

- **Actor procedure:** SideWinder registers large volumes of look-alike domains that mimic real ministries, government CERTs and maritime/port authorities in the target region, then uses them for both the lure-hosting/recon phase and later staging/C2. Documented examples masquerade as the Saudi Ministry of Foreign Affairs (`mofa-gov-sa.direct888[.]net`), Pakistani government (`depo-govpk[.]com`), the Djibouti port (`portdedjibouti[.]live`) and a national CERT (`pncert[.]info`), alongside generic document/office-themed decoys (`document-viewer[.]info`, `ms-office.app`, `pmd-office.info`). The group rotates infrastructure aggressively — new variants/domains often appear within hours. Lure content is tailored to the recipient's sector (government, diplomatic, maritime, nuclear).
- **Why a hunt, not a rule:** Domain registration and the crafting of a targeting email happen off-victim on adversary/registrar infrastructure — there is nothing on our endpoints to alert on, and a blocklist of today's domains is stale within hours given SideWinder's <5-hour rotation. The durable work is *correlating* an external newly-registered-domain / brand-monitoring hit against our organisation and partner brands with an internal DNS/proxy/mail-gateway resolution of that same look-alike — human judgement about whether a string is a plausible impersonation of *our* trust relationships, not a static match. If a specific confirmed SideWinder domain pattern proves stable and precise (e.g. a registrant/nameserver cluster), hand that pivot to detection-engineering as a scoped TI-match analytic rather than alerting on "a new domain exists."

## Data sources required

- External brand-monitoring / newly-registered-domain (NRD) feed keyed to our org name, our ministry/government partners, and the regional port authorities we do business with (the off-victim half)
- Passive DNS / domain WHOIS enrichment (registrar, creation date, nameserver, hosting ASN) for clustering look-alikes to shared infrastructure
- Secure email gateway URL logs (inbound message links, sender, recipient, lure subject/theme)
- Internal recursive DNS resolver logs and web-proxy logs (which internal hosts resolved/visited the look-alike)

## Query starting point

Platform: `KQL / Microsoft Sentinel` — fuse an NRD/brand-monitoring watchlist of look-alike domains with internal DNS resolution and inbound mail links on the same domain

```kusto
// (a) Look-alike domains from brand-monitoring / NRD feed impersonating our org + partners + regional ports
let lookalikes = _GetWatchlist('sidewinder_lookalike_nrd')   // curated: NRDs fuzzy-matching our brands/ministries/ports
    | project LookalikeDomain = tolower(Domain), CreatedDate, Registrar, Nameserver;
// (b) Internal hosts that actually resolved one of those look-alikes
let dnsHits = DnsEvents
    | where TimeGenerated > ago(14d)
    | extend q = tolower(Name)
    | join kind=inner (lookalikes) on $left.q == $right.LookalikeDomain
    | summarize resolvers = make_set(ClientIP, 20), firstSeen = min(TimeGenerated), hits = count()
             by LookalikeDomain, CreatedDate, Registrar;
// (c) Inbound mail carrying a link to the same look-alike (T1598.003 recon tell)
let mailHits = EmailUrlInfo
    | join kind=inner (EmailEvents | where EmailDirection == "Inbound") on NetworkMessageId
    | extend urlDomain = tolower(UrlDomain)
    | join kind=inner (lookalikes) on $left.urlDomain == $right.LookalikeDomain
    | summarize recipients = make_set(RecipientEmailAddress, 20), subjects = make_set(Subject, 10)
             by LookalikeDomain;
dnsHits
| join kind=leftouter (mailHits) on LookalikeDomain
| where CreatedDate > ago(60d)          // registered recently = classic SideWinder staging
| order by firstSeen asc
```

## Triage guidance

- **Likely malicious:** a newly-registered domain that fuzzy-matches our ministry/port-authority correspondents (e.g. `<our-gov>-gov-XX`, `port-<city>[.]live`, `mofa-*`) that is *both* linked in an inbound email to sector-relevant recipients *and* resolved by an internal host; several look-alikes sharing a registrar/nameserver/ASN cluster (SideWinder infrastructure reuse); document/office-viewer-themed decoy domains (`document-viewer[.]info`, `ms-office.app`) appearing in inbound links to a small targeted recipient set.
- **Likely benign / expected:** legitimate typo domains our own marketing/partners registered defensively; brand-monitoring hits on look-alikes that no internal host ever resolves and no email ever references (off-victim only — track, don't escalate); CDN/registrar parking pages; a partner ministry's real (correctly-spelled) domain flagged by an over-broad fuzzy matcher.
- **Pivot next:** confirmed impersonating domain with internal resolution → pull the full inbound message, detonate the link from an in-region sensor (see HUNT-03 geofenced staging), block the domain and its infrastructure cluster, and sweep DNS/proxy for the whole cluster. If any host that resolved the domain also shows the EQNEDT32→mshta chain, this is an active intrusion — escalate to incident-response-coordinator. Feed the confirmed domain + registrant/NS pivot to cti-expert for infrastructure tracking and to detection-engineering as a TI-match analytic.

## References

- https://securelist.com/sidewinder-apt-updates-its-toolset-and-targets-nuclear-sector/115847/
- https://thehackernews.com/2024/10/sidewinder-apt-strikes-middle-east-and.html
- https://attack.mitre.org/groups/G0121/
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1598/003/
