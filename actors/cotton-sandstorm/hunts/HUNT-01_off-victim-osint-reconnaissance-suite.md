# Hunt: Cotton Sandstorm / ASA off-victim OSINT reconnaissance suite (FLAGSHIP)

- **Hypothesis:** If Cotton Sandstorm / Aria Sepehr Ayandehsazan (Emennet Pasargad) is preparing an influence or hack-and-leak operation against our organization or our people, then — weeks before any lure, defacement or leak — its off-victim OSINT footprint should be visible as *our own* attack surface being enumerated: our subdomains and internet-exposed devices appearing freshly indexed in third-party technical databases, our corporate email format harvested, and our named high-risk individuals (military/defense personnel, executives, journalists) profiled across people-search and geolocation services. The hunt assumes the recon has already happened and asks "what of ours is exposed, and who of ours is being circled?" rather than waiting for a defender-side log that will never fire.
- **ATT&CK:**
  - T1596 — Search Open Technical Databases (reconnaissance)
  - T1589 — Gather Victim Identity Information (reconnaissance)
  - T1589.002 — Gather Victim Identity Information: Email Addresses (reconnaissance)
  - T1589.003 — Gather Victim Identity Information: Employee Names (reconnaissance)
  - T1591.001 — Gather Victim Org Information: Determine Physical Locations (reconnaissance)
  - T1590.001 — Gather Victim Network Information: Domain Properties (reconnaissance)

- **Actor procedure:** Per FBI/Treasury/INCD advisory AA24-233A, ASA runs a consistent OSINT stack: Shodan (`shodan[.]io`) and `ip2location[.]com` to find internet-exposed infrastructure and IP cameras (T1596); `subdomainfinder.c99[.]nl` to enumerate a target's subdomains and domain properties (T1590.001); `snov[.]io`, `hunter[.]io` and `email-format[.]com` to harvest email addresses tied to a target domain (T1589.002); people-search/reverse-image services `knowem[.]com`, `facecheck[.]id`, `socialcatfish[.]com`, `peekyou[.]com`, `ancestry[.]com`, `familysearch[.]org` to profile individuals (T1589); Instagram and LinkedIn plus a custom Python script correlating Instagram geolocation with OpenStreetMap to place people (T1589.003); and `Wikimapia[.]org` / OpenStreetMap to fix physical locations of Israeli military bases and the Air Force flight academy (T1591.001). Targets included Israeli fighter pilots and UAV operators.
- **Why a hunt, not a rule:** Every one of these queries runs on third-party infrastructure, entirely off-victim — there is no enterprise event that fires when someone Shodans your netblock or looks up your CFO on PeekYou. The value is attack-surface awareness and named-target early warning, not alerting. Base rates make a rule meaningless: "our subdomain is in a passive-DNS index" and "someone viewed a LinkedIn profile" are the normal state of the internet. This is a periodic, intel-driven exposure sweep whose output is a list of *what is exposed* and *who is being circled*, so the SOC can reduce the surface and pre-brief individuals — human-judgement work, not a detection.

## Data sources required

- External attack-surface management (ASM) / Shodan-Monitor for our own IP ranges and exposed services (RTSP/554, admin panels, cameras)
- Passive DNS / certificate-transparency feeds and subdomain-exposure monitoring of our owned domains
- Threat-intel & brand-monitoring feeds (persona sightings, breach mentions of corporate emails)
- HR / exec-protection roster of high-risk roles (defense/military personnel, executives, journalists, staff who post geotagged social media)
- Web-server referrer logs and email-gateway logs (rare inbound sliver: recon-tool referrers, first-contact profiling mail)

## Query starting point

Platform: `External / ASM + threat-intel tooling` (off-victim, so the "query" is largely against your own exposure surface, not a SIEM)

```bash
# (a) T1596 / T1590.001 — what of OURS is already indexed by the actor's recon stack
#     Run against our own ASNs/domains, on a recurring cadence, and diff week-over-week.
shodan search "net:<OUR_CIDR>" --fields ip_str,port,product,org   # esp. port:554 RTSP cameras
curl -s "https://api.c99.nl/subdomainfinder?domain=<our-domain.com>"   # mirror the actor's enum
# Flag: newly-exposed subdomains, RTSP/554 hosts, admin panels not in the approved asset inventory

# (b) T1589.002 — how much of our email format is harvestable
#     Query hunter.io / snov.io for OUR domain; the count of exposed addresses IS the exposure metric
```

```
# (c) rare defender-side sliver — recon-tool referrers hitting our web properties (Splunk SPL)
index=web sourcetype=access_combined
| eval ref=lower(referer)
| where match(ref,"shodan|c99\.nl|subdomainfinder|socialcatfish|peekyou|facecheck")
| stats count values(uri_path) AS paths values(clientip) AS srcips by ref
```

Companion (intel-side, not a SIEM query): monitor breach/paste feeds for corporate-domain emails and named high-risk individuals; watch for geotagged social posts by defense/exec staff that a Wikimapia/OpenStreetMap correlation could exploit; feed named targets to exec protection.

## Triage guidance

- **Likely malicious:** a burst of newly-indexed exposure (subdomains, an RTSP/554 camera, an admin panel) appearing in third-party databases shortly before other Cotton Sandstorm activity; a named defense/exec individual surfacing in persona contact after their geotagged posts were public; corporate emails appearing in a fresh dump right before targeted messaging; recon-tool referrers (c99, socialcatfish) in web logs.
- **Likely benign / expected:** routine search-engine and security-scanner indexing of public assets; our own red team or ASM vendor querying Shodan/c99; marketing staff and public figures with intentionally public profiles. Baseline our approved scanners and known-public roles and suppress.
- **Pivot next:** for any freshly-exposed asset, reduce the surface (restrict RTSP/554, take admin panels off the public internet — see detection pack T1595.001 for the scanning side). For any circled individual, pivot to HUNT-02 (is an ASA persona already engaging them?) and pre-brief exec protection. Newly-harvested email format → tighten anti-spoof and pre-warn high-risk recipients.

## References

- https://www.ic3.gov/CSA/2024/241030.pdf
- https://attack.mitre.org/techniques/T1596/
- https://attack.mitre.org/techniques/T1589/
- https://attack.mitre.org/techniques/T1590/001/
- https://attack.mitre.org/techniques/T1591/001/
