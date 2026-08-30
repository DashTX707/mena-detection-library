# Hunt: Stealth Falcon — lookalike CDN/cache/search domain acquisition & staging

- **Hypothesis:** If Stealth Falcon is standing up infrastructure to target us, then their domains follow a recognisable *masquerading* naming convention — benign-sounding CDN/cache/search/ad/discovery service names (`...webcache`, `...imagehosting`, `...discover`, `...adhosting`, `...newschannel`) registered to blend malicious C2/staging with ordinary web traffic. The hunt tracks newly-registered domains matching that lexical pattern and the known IOC set, and cross-references any *resolution or connection* from our estate against them — a first-seen resolution from an at-risk user's device to a lookalike-cache domain that matches the actor's naming grammar is the finding; a passive-DNS match with no internal contact is intel-only.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — the actor registers C2/staging domains masquerading as CDN/cache/search/ad services to blend callbacks with benign traffic.

- **Actor procedure:** Stealth Falcon / Win32.StealthFalcon operators registered numerous domains deliberately crafted to look like content-delivery, cache, search and ad infrastructure — `windowsearchcache[.]com`, `incapsulawebcache[.]com`, `edgecacheimagehosting[.]com`, `adhostingcache[.]com`, `optimizedimghosting[.]com`, `upnpdiscover[.]org`, `ministrynewschannel[.]com`, and others (full IOC list in the pack). The RC4-encrypted C2 domain list is even stored in the registry so the malware never carries it in the clear. The masquerading grammar (a real-sounding infrastructure noun + cache/hosting/discover/CDN suffix) is more durable than any single domain, which the actor rotates freely.
- **Why a hunt, not a rule:** Domain registration is entirely off-victim — there is no host or network event at registration time to alert on; the activity lives in passive DNS, WHOIS and registration feeds. On the network side, a blocklist of the *known* IOC domains belongs in detection (and those specific domains are already in the detect lane / TI blocklist); this hunt is the durable, higher-level complement — hunting the *naming pattern and behaviour* of not-yet-known domains the actor will register next, which by definition has no signature yet. Deciding that `something-webcache.com` is actor infrastructure versus a genuine CDN requires registration-metadata and hosting-overlap analysis — pivoting and judgement, not a threshold. If a specific newly-confirmed domain proves malicious, hand the exact domain to detection-engineering for the blocklist; keep the pattern-hunt as ongoing intel work.

## Data sources required

- Passive DNS + newly-registered-domain (NRD) feeds and WHOIS/registration metadata — to surface pattern-matching domains and registration/hosting overlaps with known IOCs.
- Internal DNS resolver logs and web-proxy logs — to detect any resolution/connection from our estate to lookalike or IOC domains.
- Threat-intel IOC list from the pack (domains + IP `95.215.44.37`) as seed for hosting/registrant pivoting.
- SSL/TLS certificate transparency logs — to catch cert issuance for lookalike-cache hostnames before first use.

## Query starting point

Platform: `KQL / Microsoft Sentinel` — internal resolutions to IOC domains OR to the actor's lookalike-naming grammar

```kusto
let iocDomains = dynamic([
    "footballtimes.info","vegetableportfolio.com","windowsearchcache.com","electricalweb.org",
    "upnpdiscover.org","adhostingcache.com","adhostingcaches.com","simpleadbanners.com",
    "clickstatistic.com","bestairlinepricetags.com","fasttravelclearance.com","yeastarr.com",
    "amnkeysvc.com","amnkeysvcs.com","optimizedimghosting.com","incapsulawebcache.com",
    "edgecacheimagehosting.com","ministrynewschannel.com","ministrynewsinfo.com","airlineadverts.com"]);
DnsEvents
| where TimeGenerated > ago(30d)
| extend q = tolower(Name)
| where q in (iocDomains) or QueryResults has "95.215.44.37"
    // OR the masquerading naming grammar for not-yet-known domains:
    or q matches regex @"(?i)(webcache|imagehosting|imghosting|adhosting|edgecache|searchcache|upnpdiscover|newschannel)\.[a-z]{2,}$"
| summarize hits = count(), first = min(TimeGenerated), last = max(TimeGenerated),
            resolvers = make_set(ClientIP, 20) by q
| extend knownIOC = q in (iocDomains)
| order by knownIOC desc, first asc   // known IOCs first, then never-before-seen pattern hits
```

## Triage guidance

- **Likely malicious:** any internal resolution/connection to a domain on the IOC list or to IP `95.215.44.37`; a first-seen resolution to a lookalike `*webcache/*imagehosting/*discover` domain that shares registrant, name-server or hosting IP with a known IOC; certificate issuance for such a hostname immediately preceding first internal contact.
- **Likely benign / expected:** the naming grammar deliberately mimics *real* CDN/cache services, so genuine providers (Incapsula/Imperva, Akamai edge, image CDNs, `search`/`upnp` service hostnames) will match the regex — expect and baseline these; a passive-DNS/NRD match with zero internal contact is intelligence, not activity. Do not block on the pattern alone.
- **Pivot next:** for a confirmed hostile domain, hand the exact domain to detection-engineering for the TI blocklist and pivot on registrant/NS/hosting overlap to pre-empt the next rotation; check whether any internal host that resolved it also shows BITS C2 or the Shell-Extensions registry config (detect lane T1197/T1112) — if so this is an active compromise, escalate to incident-response-coordinator. Feed confirmed sender domains back to HUNT-03.

## References

- https://www.welivesecurity.com/2019/09/09/backdoor-stealth-falcon-group/
- https://citizenlab.ca/2016/05/stealth-falcon/
- https://attack.mitre.org/techniques/T1583/001/
