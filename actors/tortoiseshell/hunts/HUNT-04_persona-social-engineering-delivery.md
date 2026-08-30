# Hunt: TA456 / Imperial Kitten fake-persona social engineering & credential-portal capture

- **Hypothesis:** If Tortoiseshell is running its long-con recruitment social-engineering play against our staff, then employees (especially in defense/aerospace/maritime/IT roles) are corresponding with fake recruiter personas over social-media and personal-webmail services outside corporate mail controls, and clicking recruitment-themed links that land on attacker-hosted credential-capture portals — surfacing on the endpoint as browser navigations to newly-registered "careers/apply/login" lookalike domains and corporate credentials being submitted off-domain. The evidence stacks a never-before-seen anomaly (a job/careers portal domain absent from history and freshly registered) with a masquerading anomaly (a login page imitating a corporate/known brand) and an unexpected-relationship anomaly (corporate email/username POSTed to a non-corporate host).
- **ATT&CK:**
  - T1585 — Establish Accounts (resource-development)
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development)
  - T1585.002 — Establish Accounts: Email Accounts (resource-development)
  - T1566.003 — Phishing: Spearphishing via Service (initial-access)
  - T1056.003 — Input Capture: Web Portal Capture (credential-access)

- **Actor procedure:** Imperial Kitten / TA456 build elaborate, long-maintained fake personas (e.g. the "Marcella Flores" recruiter identity) across LinkedIn/Facebook and dedicated email accounts, cultivating rapport with targets over weeks before delivering lures. Because delivery rides social-media and personal-webmail services, it bypasses corporate mail gateways entirely (spearphishing via service). Links lead to attacker-hosted recruitment/login portals that capture submitted credentials. The account creation is off-victim, but the persona's outreach and the portal both leave web/proxy footprints on the target's endpoint.
- **Why a hunt, not a rule:** Persona and mailbox creation happen entirely on adversary infrastructure — nothing to alert on there — and social-media/webmail traffic plus job-hunting are normal, high-volume employee behavior. No single navigation is inherently malicious; the tell is the *stack*: a freshly-registered lookalike careers/login domain, reached from a social-media referrer, that harvests a corporate credential. Separating a real recruiter/careers site from a capture portal needs analyst judgement and persona/social-graph context → hunt. If a specific capture-portal pattern proves precise (corporate-domain credential POST to an off-domain freshly-registered host), route that to detection-engineering as a phishing-portal alert.

## Data sources required

- Web proxy / SWG logs — full URL, referrer (social-media / webmail origin), user-agent, POST indicators, domain age/reputation
- DNS resolver logs with newly-registered-domain and lookalike/typosquat enrichment (brand + "careers/apply/hr/login")
- Corporate identity logs — failed/succeeded auth from unusual geos shortly after a portal visit (credential replay)
- Email gateway (for the minority of lures that do touch corporate mail) + user-reported-phish mailbox
- Threat-intel: persona/social-graph and lookalike-domain monitoring feeds (off-victim, intel-driven)

## Query starting point

Platform: `SPL / Splunk` — corporate-brand lookalike careers/login domains reached from social/webmail referrers

```spl
index=proxy sourcetype=proxy
| eval dom=lower(url_domain), ref=lower(referrer_domain), u=lower(url)
| search (u="*career*" OR u="*apply*" OR u="*recruit*" OR u="*/hr*" OR u="*login*" OR u="*verify*")
| search (ref="*linkedin*" OR ref="*facebook*" OR ref="*t.me*" OR ref="*gmail*" OR ref="*outlook.live*" OR ref="*mail.*")
| lookup newly_registered_domains domain as dom OUTPUT reg_age_days
| lookup brand_lookalikes domain as dom OUTPUT imitates_brand
| where reg_age_days<120 OR isnotnull(imitates_brand)
| stats count values(src) as users values(ref) as referrers earliest(_time) as first by dom,imitates_brand,reg_age_days
| sort - count
```

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — browser POST to a fresh off-domain login page then identity anomaly

```kusto
let recent = DeviceNetworkEvents
| where TimeGenerated > ago(14d)
| where tolower(InitiatingProcessFileName) in ("chrome.exe","msedge.exe","firefox.exe")
| extend dom = tostring(parse_url(RemoteUrl).Host)
| where RemoteUrl has_any ("career","apply","recruit","login","verify","hr")
| where SentBytes > 300;                                    // form submission shape
recent
| join kind=leftouter (
    SigninLogs | where ResultType == 0
    | project AccountUpn = UserPrincipalName, ipAddr = IPAddress, loc = tostring(LocationDetails.countryOrRegion), SignInTime = TimeGenerated
) on $left.AccountName == $right.AccountUpn
| where SignInTime between (TimeGenerated .. TimeGenerated + 6h)   // replay after capture
| project TimeGenerated, DeviceName, AccountName, dom, RemoteUrl, loc, ipAddr
```

## Triage guidance

- **Likely malicious:** an employee submitting credentials to a <120-day-old lookalike "careers/apply/login" domain reached from a LinkedIn/Facebook/Telegram/personal-webmail referrer; the domain imitates your brand or a known company; a corporate credential appearing in an off-domain POST followed by a sign-in from an unusual geo within hours; several targeted staff (same team/clearance) contacted by the same persona/domain.
- **Likely benign / expected:** legitimate job hunting, real recruiter outreach, and genuine third-party ATS/careers portals (Workday, Greenhouse, LinkedIn apply) — allowlist known ATS/recruiting SaaS and established company careers domains; an employee using a reputable, long-registered job site is expected. Persona outreach alone (no lure/portal) is HR/awareness follow-up, not yet an incident.
- **Pivot next:** report the persona and lookalike domain to intel and takedown; force a password reset + session revocation for any user who submitted credentials and hunt for the resulting valid-account logon (detection pack T1078); check whether the same persona/domain cluster links to staging infra in HUNT-05. Confirmed credential capture with replay → escalate to IR.

## References

- https://www.proofpoint.com/us/blog/threat-insight/above-us-only-stars-exposing-ta456-intelligence-operation
- https://www.crowdstrike.com/en-us/adversaries/imperial-kitten/
- https://attack.mitre.org/techniques/T1585/
- https://attack.mitre.org/techniques/T1585/001/
- https://attack.mitre.org/techniques/T1585/002/
- https://attack.mitre.org/techniques/T1566/003/
- https://attack.mitre.org/techniques/T1056/003/
