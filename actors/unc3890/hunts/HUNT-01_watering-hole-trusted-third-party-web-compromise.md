# Hunt: UNC3890 — watering-hole / strategic-web-compromise via a trusted third-party site (FLAGSHIP)

- **Hypothesis:** If UNC3890 has already reached our users through their signature access vector — a strategic web compromise — then the on-victim tell is NOT malware on the endpoint (that is a later stage), it is a *quiet outbound beacon*: an internal user browsing a **legitimate, trusted partner web asset** (an Israeli shipping/maritime portal, a sector login page) whose page then silently reports that visitor's data to an actor-controlled C2, or redirects them to a spoofed login. Because the malicious content lives on a third party's site, our own web-content telemetry never sees it — the only observable inside our perimeter is egress from a web-browsing user to a UNC3890 watering-hole/hosting IP (128.199.6.246, 161.35.123.176, 185.170.215.170), ideally *chained* from a Referer of a known-good partner domain. Either half — the partner-site visit or the raw egress — is thin; the visit-then-beacon sequence on the same host in the same session is the finding.
- **ATT&CK:**
  - T1189 — Drive-by Compromise (initial-access) — the watering hole on a legitimate Israeli shipping login page beacons visitor data to actor C2 128.199.6.246 and can serve fake logins; the hunt looks for that visitor beacon in our egress.
  - T1199 — Trusted Relationship (initial-access) — the malicious content sits on a *trusted third-party* web property (a partner/supplier shipping site), abusing that trust to reach our users; the hunt correlates partner-site visits with actor-C2 egress.
  - T1608.004 — Stage Capabilities: Drive-by Target (resource-development) — UNC3890 embedded the drive-by content and stood up fake-login pages on actor hosting (128.199.6.246, 185.170.215.170); the hunt's content-integrity leg watches our own/partner login pages for injected foreign script and beacon endpoints.

- **Actor procedure:** Mandiant observed UNC3890 embedding malicious content in the *legitimate login page of an Israeli shipping company*. When a visitor loaded that page, embedded code reported the visitor's data back to an actor C2 (128.199.6.246) and could redirect the victim to a fake login page (spoofing Office 365, LinkedIn, Facebook, Pfizer) hosted on actor infrastructure (128.199.6.246, 185.170.215.170). This is a classic strategic web compromise aimed at a specific sector audience — visitors from shipping/maritime, government, energy and defense orgs — rather than mass drive-by. The trust in the compromised third-party site is the delivery mechanism.
- **Why a hunt, not a rule:** The compromise itself is on someone else's server — there is nothing on our endpoints to alert on, and the initial visitor beacon is a single outbound web request that is indistinguishable from normal browsing without context. A standalone "traffic to 128.199.6.246" rule is just IOC-matching that expires the moment the actor re-hosts (Summiting Level 1 — an IP the adversary changes at will). The durable, hunt-worthy signal is *relational and behavioral*: a web-browsing user reaching an unfamiliar low-reputation host in the same session as a visit to a trusted partner login page — a Level-3/4 relationship the actor can't shed without abandoning the watering-hole technique. That fusion of "trusted-site referer + anomalous egress + no corresponding user-initiated navigation" is analyst correlation work, not an alert condition. If a specific durable observable falls out (e.g., our monitored partner login page serving a script element pointing to a non-partner beacon endpoint), hand *that* to detection-engineering as a content-integrity analytic (Summiting Level 4 — technique-core).

## Data sources required

- Web proxy / secure web gateway logs (URL, Referer, destination IP, user, user-agent, bytes) — the primary egress leg
- DNS resolver logs from user endpoints — resolution of watering-hole/hosting IPs and any fronting domains
- Netflow / firewall egress to the actor hosting IPs (128.199.6.246, 161.35.123.176, 185.170.215.170, 104.237.155.129, 146.185.219.88, 159.223.164.185)
- External web-content-integrity monitoring of *your own* and *key partner/supplier* login pages (injected script tags, foreign beacon endpoints, unexpected form-action changes) — the off-victim leg
- Threat-intel watchlist of partner/supplier maritime & sector domains you trust (to seed the Referer correlation)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — correlate a trusted partner-site visit with an in-session beacon to actor hosting

```kusto
let actorHosting = dynamic(["128.199.6.246","161.35.123.176","185.170.215.170",
                            "104.237.155.129","146.185.219.88","159.223.164.185"]);
// (a) users who visited a trusted maritime/sector partner login page (seed from watchlist)
let partnerVisits = _Im_WebSession(starttime=ago(14d))
    | where Url has_any (_GetWatchlist('trusted_partner_domains'))
    | where Url has_any ("login","signin","portal","account")
    | project sess=SrcIpAddr, User=SrcUserName, Device=DstHostname, partnerUrl=Url, tVisit=TimeGenerated;
// (b) egress from web-browsing users to actor hosting IPs
let beacons = _Im_WebSession(starttime=ago(14d))
    | where DstIpAddr in (actorHosting)
    | project sess=SrcIpAddr, User=SrcUserName, beaconIp=DstIpAddr, beaconUrl=Url,
              ua=HttpUserAgent, tBeacon=TimeGenerated;
partnerVisits
| join kind=inner (beacons) on sess
| where tBeacon between (tVisit .. tVisit + 5m)   // beacon within the same browsing session
| project sess, User, Device, partnerUrl, beaconIp, beaconUrl, ua, tVisit, tBeacon
| order by tVisit asc
```

## Triage guidance

- **Likely malicious:** a user's browser reaching one of the actor hosting IPs *seconds after* loading a trusted partner/maritime login page, with a Referer pointing back at that partner domain and no corresponding user-typed navigation; the same host then landing on a spoofed-brand login page (see HUNT-02); a partner login page observed serving a `<script>`/`<img>` element whose src resolves to a non-partner, low-reputation host. Any of these, especially clustered across several employees who all use the same partner portal, is consistent with an active watering hole.
- **Likely benign / expected:** legitimate third-party CDNs, analytics beacons, ad/marketing pixels and CAPTCHA providers that partner login pages embed — baseline these per partner domain before flagging; VPN/cloud egress IPs that happen to share a hosting provider with the actor (pivot on the exact IP, not the ASN); security scanners and uptime monitors that hit partner login pages on a schedule. A single hit to a hosting IP with no partner-site referer and a normal browser flow is weak on its own.
- **Pivot next:** if the beacon corroborates a partner-site visit, treat as a live strategic web compromise reaching your users — notify the partner/supplier (their site is compromised, T1199), pull the full session for that user, and pivot to HUNT-02 (did they land on a fake login and submit credentials?) and to the detection pack (did SUGARUSH/SUGARDUMP land? T1543.003 / T1555.003). If credential submission is confirmed, this is an incident — escalate to incident-response-coordinator and force-reset the affected user's credentials for every spoofed service.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-actor-targeting-israeli-shipping
- https://thehackernews.com/2022/08/suspected-iranian-hackers-targeted.html
- https://attack.mitre.org/techniques/T1189/
- https://attack.mitre.org/techniques/T1199/
- https://attack.mitre.org/techniques/T1608/004/
