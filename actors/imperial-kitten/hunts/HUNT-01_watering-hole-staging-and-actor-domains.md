# Hunt: Imperial Kitten — watering-hole compromised-server staging & CDN-masquerading actor domains

- **Hypothesis:** If Imperial Kitten is running (or preparing) a strategic-web-compromise operation against people who visit our estate's browsers, then the on-victim tell is not an implant yet — it is browsers on our network fetching JavaScript / beacons from **CDN- or analytics-masquerading domains that no one on our team ever chose to embed** (jquery-cdn.online, cdn.jguery.org, cdn-analytics.co, cdnpakage.com, fastanalizer.live, fastanalytics.live, hotjar.info, jquery-code-download.online, analytics-service.cloud/.online, prostatistics.live, jquery-stack.online), frequently proxied through a Matomo analytics endpoint. The off-victim corroborator is web-integrity / passive-DNS intel showing a legitimate partner or industry-peer Israeli/maritime site suddenly serving one of those script hosts, plus registration-pattern hits (young `.online/.live` domains, typosquatted jquery/hotjar/analytics strings) on newly acquired actor infrastructure. Either half alone is thin; a browser on our net beaconing to a typosquat CDN that also just appeared injected into a supplier's page is the finding.
- **ATT&CK:**
  - T1584.004 — Compromise Infrastructure: Server (resource-development) — actor compromises legitimate (often Israeli) web servers and turns them into watering holes; hunt the *served* injected script host and third-party web-integrity intel.
  - T1608.004 — Stage Capabilities: Drive-by Target (resource-development) — malicious JS staged on the compromised site, in several cases delivered/profiled via the Matomo platform to fingerprint visitors; hunt for the staged-script fetch and Matomo-proxied beacon.
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — the CDN/analytics-lookalike domains the beacons resolve to are freshly registered actor assets; hunt via passive DNS, domain-age and typosquat similarity.
  - (context) T1189 Drive-by Compromise / T1071.001 Web Protocols — the downstream initial-access these three resource-dev techniques set up; covered in the detection lane.

- **Actor procedure:** In the 2022–2023 Israeli watering-hole campaign the actor compromised legitimate websites and embedded malicious JavaScript that beaconed each visitor's public IP, screen and browser data back to actor-controlled infrastructure — repeatedly through the open-source **Matomo** analytics platform used as a visitor-profiling intermediary. Selected high-value visitors (transportation, logistics, maritime, technology, defense) were then progressed to IMAPLoader delivery. The staging infrastructure is a set of throwaway CDN/analytics-masquerading domains (jquery-*, cdn-*, *analytics*, hotjar.info) registered specifically to look like benign script/CDN hosts in a page's network tab.
- **Why a hunt, not a rule:** The compromise of the third-party server and the staging of the drive-by target happen on infrastructure we do not own — there is nothing on our endpoints to alert on for T1584.004/T1608.004 themselves. What is on-victim (a browser fetching a script host) is individually indistinguishable from the long tail of legitimate third-party CDN/analytics calls; a naive blocklist of the known IOC domains is a detection-lane job (and expires the moment the actor rotates domains). The durable hunt is the *correlation*: a never-before-seen script host on our proxy + young-domain / typosquat-similarity scoring + external web-integrity intel that the same host was injected into a partner site. That fusion and the similarity judgement is analyst work. If a robust observable falls out — e.g. any first-party page load that pulls a script from a domain <30 days old whose SLD is within edit-distance 2 of "jquery"/"hotjar"/"analytics" — hand that to detection-engineering as a scoped analytic (Summiting Level 3–4, technique-implementation on the masquerade pattern, not the throwaway domain string).

## Data sources required

- Web-proxy / SWG logs and DNS resolver logs (outbound URL, referrer, first-seen per domain) — the primary on-victim surface
- Passive-DNS + domain-registration enrichment (WHOIS age, registrar, nameserver clustering) for domain-age and typosquat scoring
- External web-integrity / threat-intel feed on compromised-site infrastructure and known watering-hole script hosts (the off-victim half)
- Optional: browser-telemetry / RUM or Matomo-request patterns if any first-party analytics is self-hosted

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — surface never-before-seen script/analytics hosts, then intersect with young-domain + typosquat scoring and the IOC watchlist

```kusto
// Known-IOC fast path + behavioral long-tail for rotated infrastructure
let iocDomains = dynamic(["jquery-cdn.online","cdn.jguery.org","cdn-analytics.co","cdnpakage.com",
  "fastanalizer.live","fastanalytics.live","hotjar.info","jquery-code-download.online",
  "analytics-service.cloud","analytics-service.online","prostatistics.live","jquery-stack.online"]);
let lurebait = dynamic(["jquery","hotjar","analytics","cdn","statistic","matomo"]);
let seen = DeviceNetworkEvents
    | where TimeGenerated > ago(30d)
    | where RemoteUrl matches regex @"\.(online|live|cloud|co|info)(/|$)"   // actor's preferred TLDs
    | extend host = tostring(parse_url(RemoteUrl).Host);
// (a) direct IOC hits
seen | where host in (iocDomains)
| extend verdict = "known-ioc"
| union (
// (b) never-before-seen host that LOOKS like a CDN/analytics lib (typosquat long-tail)
  seen
  | where host has_any (lurebait)
  | summarize firstSeen = min(TimeGenerated), hits = count(), devices = dcount(DeviceName) by host
  | where firstSeen > ago(30d)          // never-before-seen in the window = candidate rotated infra
  | where hits < 500                     // exclude the genuinely popular (real jquery/hotjar CDNs)
  | extend verdict = "typosquat-newhost"
)
| order by verdict asc, firstSeen desc
// PIVOT: enrich host with WHOIS age + check external web-integrity intel for the same host on a partner site
```

## Triage guidance

- **Likely malicious:** a browser on our net fetching script from a domain <30 days old whose SLD typosquats jquery/hotjar/analytics and is served from a page that has no business embedding it; the same host appearing in external web-integrity intel as injected into an Israeli/maritime/logistics partner site; a Matomo `matomo.php`/`piwik.php` beacon to a host we do not self-host; a beacon carrying public-IP/screen/browser fingerprint fields to any of the IOC domains.
- **Likely benign / expected:** real jQuery/Hotjar/Matomo/CDN usage — the *legitimate* `code.jquery.com`, `static.hotjar.com`, self-hosted Matomo — is high-volume and long-established; marketing tag-managers and A/B-testing tools inject third-party analytics broadly. Baseline the org's approved script hosts once and treat only never-before-seen, young-domain, low-volume typosquats as candidates. A single visit is noise; a script *embedded in a first-party or partner page load* is the discriminator.
- **Pivot next:** if a beacon is confirmed, pull the full referrer chain to find which compromised page served it, identify the users whose fingerprints were exfiltrated (they are the selection pool for IMAPLoader delivery), and pivot those users to the email-C2 hunt (HUNT-03) and inbound-lure hunt (HUNT-02). Push the confirmed script host + its passive-DNS neighbors to the proxy blocklist and to detection-engineering. If a partner/supplier site is the injection source, notify them — their server is compromised (T1584.004) and is an active incident on their side.

## References

- https://www.crowdstrike.com/en-us/blog/imperial-kitten-deploys-novel-malware-families/
- https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/yellow-liderc-ships-its-scripts-delivers-imaploader-malware.html
- https://attack.mitre.org/techniques/T1584/004/
- https://attack.mitre.org/techniques/T1608/004/
- https://attack.mitre.org/techniques/T1583/001/
