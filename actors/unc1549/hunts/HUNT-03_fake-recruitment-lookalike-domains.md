# Hunt: UNC1549 (TA455) — fake-recruitment lures and look-alike domain acquisition

- **Hypothesis:** If UNC1549 is spinning up an approach against our aerospace/defense staff, then before any payload lands they **register look-alike / job-themed domains** (`airbus.usa-careers[.]com`, `airplaneserviceticketings[.]com`, `airtravellog[.]com`) and run **social-media recruiter personas** to lure IT admins and defense-sector employees. The on-victim/near-victim tells are: our brand or an aerospace peer appearing in a newly-registered look-alike domain; those domains resolving in *our* proxy/DNS when an employee clicks a "job opportunity" link; and staff reporting recruiter outreach that pivots to an off-platform "careers portal." The finding is a newly-registered brand-adjacent domain **plus** either a click from our estate or a corroborating recruiter-persona report — either half alone is thin.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — actor registers look-alike/thematic recruitment and lure domains for credential harvest and C2 staging; hunted via newly-registered-domain and brand-permutation monitoring.
  - T1593.001 — Search Open Websites/Domains: Social Media (reconnaissance) — TA455 recruiter personas on professional networks identify and approach targets; off-victim, hunted via brand/persona monitoring and employee-awareness reporting.
- **Actor procedure:** UNC1549's initial access is a fake-recruitment operation (thematically an "Iranian Dream Job"). Operators build professional-network recruiter personas, approach aerospace/defense/IT staff with tailored job lures, and drive them to actor-registered look-alike domains hosting fake login pages that mimic legitimate companies to harvest credentials, and lure sites that deliver MINIBIKE/MINIBUS. Domains are thematically relevant (airline/aviation/careers) and often chain onto Azure C2. Israel-Hamas conflict-themed lure sites are also used.
- **Why a hunt, not a rule:** Domain registration and LinkedIn outreach happen entirely off-victim — there is nothing on our endpoints to alert on until an employee clicks. Newly-registered-domain feeds and typo/permutation generators produce thousands of candidates daily; only human judgement (is this permutation *of our brand or a partner*, is it aviation-themed, does WHOIS/registrar/hosting pattern-match the actor) turns a candidate into a lead. Fusing that with a proxy click or an HR/awareness report is correlation work. If a specific confirmed lure domain should be blocked going forward, that is a blocklist entry for detection-engineering — not a standing rule you author here.

## Data sources required

- Newly-registered-domain (NRD) feed + brand-permutation monitoring (dnstwist/urlscan/Certificate Transparency) keyed to our brand, our aerospace/defense partners, and aviation/careers themes.
- Proxy / secure web gateway + DNS resolver logs: outbound resolutions/clicks to candidate look-alike domains from user hosts.
- Email security gateway: inbound links to NRD/look-alike domains, user-reported phishing.
- HR / security-awareness reporting channel: employee reports of unsolicited recruiter outreach that moves off-platform (the social-media recon corroborator).

## Query starting point

Platform: `KQL / Microsoft Sentinel` — intersect a look-alike-domain watchlist with actual clicks/resolutions from our estate

```kusto
// Watchlist 'lookalike_nrd' populated from NRD + dnstwist against our brand/partners + the pack IOC domains
let actorDomains = dynamic(["usa-careers.com","airplaneserviceticketings.com","airtravellog.com",
    "automationagencybusiness.com","fdtsprobusinesssolutions.com","forcecodestore.com",
    "tini-ventures.com","thetacticstore.com","politicalanorak.com","vcs-news.com"]);
let candidates = _GetWatchlist('lookalike_nrd') | project DomainName, registeredOn=todatetime(RegisteredOn);
union
( DeviceNetworkEvents
  | where TimeGenerated > ago(30d)
  | extend host = tostring(split(RemoteUrl,"/")[0])
  | where host has_any (actorDomains) or host in (candidates | project DomainName)
  | project TimeGenerated, DeviceName, AccountName=InitiatingProcessAccountName, host, src="proxy" ),
( EmailUrlInfo
  | where TimeGenerated > ago(30d)
  | where Url has_any (actorDomains) or Url has_any (candidates | project DomainName)
  | project TimeGenerated, DeviceName="(email)", host=Url, src="email" )
| summarize events=count(), firstSeen=min(TimeGenerated), users=make_set(AccountName,25) by host, src
| order by firstSeen desc
```

## Triage guidance

- **Likely malicious:** a newly-registered domain that is a permutation of our brand or a named aerospace/defense partner, aviation/careers-themed, with privacy-protected WHOIS and hosting that later chains to Azure; an employee click from our estate to such a domain, especially followed by a credential-form POST; a staff report of a recruiter who insisted on moving to an external "application portal."
- **Likely benign / expected:** legitimate recruiters, job boards and career sites generate huge volumes of look-alike-ish traffic and real outreach — do not treat "employee visited a jobs site" as malicious; brand-monitoring false positives where a vendor legitimately uses your name; parked/for-sale NRDs with no content. The signal is *targeted* thematic permutation + a click/report, not generic recruiting traffic.
- **Pivot next:** urlscan/sandbox the candidate to confirm a fake login page or MINIBIKE dropper; if a user submitted credentials, force-reset and hunt for the resulting valid-account logon (detection-pack T1078) and any download/execution (T1204.001/.002); feed confirmed domains to the email/proxy blocklist via detection-engineering and to HUNT-01's Azure-C2 pivot. Preserve the persona/domain as attribution intel and brief the targeted employees.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/analysis-of-unc1549-ttps-targeting-aerospace-defense
- https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-unc1549-targets-israel-middle-east
- https://thehackernews.com/2024/02/iran-linked-unc1549-hackers-target.html
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1593/001/
