# Hunt: CopyKittens — CDN-lookalike proxy infrastructure and fake-news/persona resource development (off-victim)

- **Hypothesis:** If CopyKittens is preparing or running an operation against us, then before any on-victim signal appears, their off-victim buildout is discoverable in external telemetry: newly-registered typosquat/masquerade domains impersonating CDNs, security vendors and services (brand strings `akamai`, `cloudflare`, `gstatic`, `twiter`, `fbstatic`, `mcafee`, `digicert`, `windefender`), those domains carrying fresh TLS/code-signing certificates visible in Certificate Transparency, watering-hole script injections appearing on watched publisher sites (the actor compromised the Jerusalem Post and similar news outlets), and fake-news/persona social-media accounts and fake-organization sites seeded to support lures. The *fusion* signal — a lookalike domain that (a) is newly registered, (b) has a CT-logged cert on our brand or a CDN brand, (c) resolves to an ASN that is **not** the impersonated provider's, and (d) then shows up as a proxy hop or referrer in our own proxy logs — is the finding. Any one alone is brand-monitoring noise; the chain is an operation aimed at us.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — typosquat/CDN-masquerade C2 domains (`alkamaihd.com/.net`, `cloudflare-statics.com`, `gstatic.online`, `twiter-statics.info`, `fbstatic-a.space`); hunted via passive-DNS/NRD/lookalike monitoring on brand strings.
  - T1584.004 — Compromise Infrastructure: Server (resource-development) — watering-hole compromise of legitimate news/org servers (Jerusalem Post); hunted via injected-script/defacement monitoring on watched publisher sites plus victim-side redirect telemetry.
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development) — fake personas/accounts and fake-news sites seeding lures; hunted via brand/persona monitoring (also carries the impersonation behavior this env maps here).
  - T1587.003 — Develop Capabilities: Digital Certificates (resource-development) — TLS certs on masquerade C2 domains (and code-signing certs); hunted via Certificate-Transparency correlation against brand/lookalike strings.
  - T1090 — Proxy (command-and-control) — *context, detection-lane* — C2 relayed through the CDN-lookalike infrastructure this hunt inventories; framed here, alerting in the detection pack.

- **Actor procedure:** CopyKittens' operational signature is extensive typosquatting/CDN-masquerading. They register large batches of lookalike domains impersonating Akamai (`alkamaihd.com/.net`, `akamaitechnology.tech`, `fbstatic-akamaihd.com`), Google/gstatic (`gstatic.online`, `ssl-gstatic.online`, `gsvr-static.co`, `googlusercontent.center`), Cloudflare (`cloudflare-statics.com`, `cloudflare-analyse.com`, `labs-cloudfront.com`), Twitter/Facebook (`twiter-statics.info`, `fb-statics.com`, `cdninstagram.center`), and security vendors (`mcafee-analyzer.com`, `digicert.online`, `symcd.xyz`, `windefender.org`). They stand up fake-news/organization sites (`news-bbc.press`, `israelnewsagency.link`, `ynet.link`, `primeminister-goverment-techcenter.tech`) and fake personas to theme lures around news and government topics, and they compromise real publisher sites for watering-hole redirects. TLS and code-signing certs (T1587.003) are applied to make the masquerade convincing. C2 is then relayed through this lookalike estate (T1090).
- **Why a hunt, not a rule:** Domain registration, CT issuance, persona creation and third-party-server compromise all happen **off our victim estate** — there is nothing on our endpoints to alert on, and a blocklist of yesterday's IOCs (Level-1 observables the actor rotates continuously) expires the moment they register the next batch. The durable, huntable pattern is the *methodology*: brand-string lookalikes + NRD + CT + ASN-mismatch, correlated to any first touch in our own proxy/DNS. That correlation across external intel and internal logs, with analyst judgement to separate a targeting operation from generic brand-abuse noise, is hunt work. When a confirmed-hostile apex first appears in our egress, hand the resolved list to detection-engineering for blocking — but the hunt itself is the discovery, not the block.

## Data sources required

- Passive DNS / newly-registered-domain feeds and domain-registration monitoring keyed to brand strings and our own name
- Certificate Transparency logs (crt.sh / CT monitor) for certs on lookalike and brand strings (TLS + code-signing issuer/subject)
- Web-proxy / DNS egress logs (our estate) — resolutions of and referrers from lookalike apexes; ASN of the resolved IP vs. the impersonated provider's ASN
- Watering-hole monitoring: injected-script/integrity monitoring on watched publisher sites our users visit; browser/proxy redirect chains (cross-ref detection pack T1189)

## Query starting point

Platform: `KQL / Microsoft Sentinel` — fuse external lookalike/CT intel with internal first-touch and ASN mismatch

```kusto
// (a) Lookalike / masquerade apexes from NRD + CT feeds (ingested to a watchlist)
let lookalikes = _GetWatchlist('copykittens_lookalike_domains')  // brand-string typosquats + CT hits
    | project apex = tostring(Column1), impersonated_provider = tostring(Column2), impersonated_asn = tostring(Column3);
// (b) Our own resolutions/proxy touches of those apexes, with the resolved ASN
DnsEvents
| where TimeGenerated > ago(30d)
| extend apex = strcat(split(Name,".")[-2], ".", split(Name,".")[-1])
| join kind=inner (lookalikes) on apex
| join kind=leftouter ( _GetWatchlist('ip_asn_map') ) on $left.IPAddresses == $right.ip
| extend asn_mismatch = (resolved_asn != impersonated_asn)
| where asn_mismatch                                   // lookalike NOT on the real provider's ASN
| summarize hosts=dcount(Computer), first=min(TimeGenerated), last=max(TimeGenerated),
            names=make_set(Name,20) by apex, impersonated_provider, resolved_asn
| order by first asc                                    // earliest first-touch = earliest lead
```
Corroborate each surviving apex with its CT record (issuer, NotBefore vs. first-seen), WHOIS registration age, and whether it appears as a redirect target from a compromised publisher site in proxy referrer chains.

## Triage guidance

- **Likely malicious:** a newly-registered apex whose subject/SAN impersonates a CDN or our brand, with a CT-logged cert issued days before first use, resolving to an ASN unrelated to the impersonated provider, and then appearing in our DNS/proxy as a first-touch — especially the known families (`alkamaihd`, `gstatic.online`, `cloudflare-statics`, `twiter-statics`, `windefender.org`) or a fake-news apex (`news-bbc.press`, `israelnewsagency.link`) as a redirect target. A watched publisher page suddenly serving an injected script pointing at a lookalike apex is a watering hole (T1584.004).
- **Likely benign / expected:** legitimate CDN edge nodes, multi-CDN failover and cert-management churn generate lookalike-*looking* names and frequent CT issuance — always confirm the ASN actually differs from the real provider before flagging; brand-protection vendors and researchers register defensive typosquats; internal marketing may stand up campaign microsites that resemble persona sites. Generic brand-abuse listings that name a look-alike but never touch our estate stay as intel, not findings.
- **Pivot next:** if a lookalike apex is both externally corroborated and internally touched, treat the touching host as a candidate infection — pivot to HUNT-01 (does it also show Matryoshka DNS C2?) and to detection-pack initial-access (T1189/T1566) for the delivery, add the resolved IPs/apex to blocking via detection-engineering, and preserve the persona/fake-news and CT artifacts as attribution intel. Confirmed victim-side redirect from a compromised publisher escalates to incident-response-coordinator.

## References

- https://www.clearskysec.com/wp-content/uploads/2017/07/Operation_Wilted_Tulip.pdf
- https://www.clearskysec.com/copykitten-jpost/
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1584/004/
- https://attack.mitre.org/techniques/T1585/001/
- https://attack.mitre.org/techniques/T1587/003/
- https://attack.mitre.org/techniques/T1090/
