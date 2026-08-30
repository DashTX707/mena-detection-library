# Hunt: Bahamut — off-victim credential-phishing portals, fake-news & persona infrastructure

- **Hypothesis:** If Bahamut is running a credential-harvesting operation against our executives / at-risk staff (diplomats, journalists, activists, defense/finance figures), then the on-victim tell is *not* malware — it is a **look-alike login portal impersonating our SSO/webmail plus an out-of-band approach from a fabricated persona**. Concretely: (a) certificate-transparency and brand-permutation feeds surface a newly-registered domain impersonating our government/webmail SSO branding, (b) our real portals see inbound HTTP referrers or credential-replay logins sourced from that look-alike, and (c) targeted users report contact from a "journalist"/"activist"/recruiter persona (fabricated social/email account) shortly before. Any one half is thin brand-monitoring noise; the *pair* — a spoofed portal that our own auth logs then see a referral or successful login from, tied to a persona approach to the same user — is the finding.
- **ATT&CK:**
  - T1589 — Gather Victim Identity Information (reconnaissance) — bespoke per-target lures imply detailed pre-attack collection of our executives'/at-risk individuals' identity & contact data; hunt via at-risk-individual exposure monitoring.
  - T1591 — Gather Victim Org Information (reconnaissance) — mimicry of our specific agency login portals/webmail branding implies recon of our org's portals and staff.
  - T1598.003 — Phishing for Information: Spearphishing Link (reconnaissance) — fake login pages with per-target content and click-pattern validation logic that harvest credentials; hunt via inbound-referrer analysis on the impersonated portals.
  - T1585 — Establish Accounts (resource-development) — fabricated journalist/activist/organization personas with invented histories used to approach targets.
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development) — fake social accounts amplify fake-news and initiate target contact.
  - T1585.002 — Establish Accounts: Email Accounts (resource-development) — attacker-provisioned sender addresses backing personas and lures; hunt via look-alike-sender/sender-reputation analytics at the mail gateway.
  - T1586.001 — Compromise Accounts: Social Media Accounts (resource-development) — repurpose already-compromised third-party accounts to reach targets from a trusted identity.

- **Actor procedure:** BlackBerry (2020) documented Bahamut as a hack-for-hire group whose *core* tradecraft is social engineering and credential harvesting, not malware (malware is a last resort). They research specific high-value individuals, build bespoke phishing content, and stand up fake login pages impersonating government agencies, private webmail, and trusted apps — some with embedded logic to detect victim click patterns and validate real targets before harvesting. This is fronted by a sprawling network of fake-news websites and fabricated social-media/email personas (journalists, activists, organizations) that lend credibility to the approach and, once credentials are stolen, feed account-takeover and further reach into the target's contacts.
- **Why a hunt, not a rule:** Portal spoofing, persona creation, and identity recon all happen *off-victim* — there is nothing on our endpoints to alert on, and a standalone "newly-registered look-alike domain" alert drowns in brand-monitoring false positives (typosquatters, parked domains, legitimate regional variants). The signal only becomes real when an external brand/CT hit is **fused** with an internal corroborator (an inbound referral from that domain to our real portal, a successful login whose password was just phished, an impossible-travel auth on an at-risk user's account) and with a reported persona approach. That fusion and per-user judgement is hunt work. If a durable internal observable falls out — e.g. successful interactive logins whose immediately-preceding referrer host is a CT-flagged look-alike of our SSO (a Level-4 relational observable) — hand *that* to detection-engineering as a scoped analytic; do not try to alert on "a persona messaged our exec."

## Data sources required

- External brand/CT intel: certificate-transparency logs + brand-permutation/newly-registered-domain feeds keyed to our SSO/webmail/agency brand and executive names (the off-victim half).
- Identity/auth analytics: Entra ID / ADFS / Okta sign-in logs for at-risk users — successful auth, impossible travel, new-ASN/new-country logins, and (where captured) HTTP referrer on the portal.
- Mail gateway: inbound sender domain/display-name look-alikes, first-contact senders to VIP/at-risk mailboxes, sender-reputation.
- User-reported persona approaches / phishing-report mailbox; VIP watchlist of at-risk individuals.

## Query starting point

Platform: `KQL / Microsoft Sentinel (Entra ID sign-in fused with CT/brand watchlist)`

```kusto
// Look-alike SSO/webmail domains from CT + brand-permutation feed (ingested as watchlist)
let lookalikes = _GetWatchlist('bahamut_lookalike_portals')  // domains impersonating our SSO/webmail brand
    | project LookalikeDomain = Domain, FirstSeen = TimeGenerated;
// At-risk users (execs, journalists, defense/finance) — VIP watchlist
let atrisk = _GetWatchlist('at_risk_individuals') | project UserPrincipalName = UPN;
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0                                   // successful auth
| where UserPrincipalName in (atrisk)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize logins = count(), countries = make_set(Country, 10),
            asns = make_set(AutonomousSystemNumber, 10), apps = make_set(AppDisplayName, 10)
        by UserPrincipalName, IPAddress, bin(TimeGenerated, 1d)
// Prioritise at-risk users authenticating from never-before-seen country/ASN
| join kind=leftouter (lookalikes) on $left.UserPrincipalName == $right.LookalikeDomain  // placeholder join; pivot on time-correlation below
| order by logins desc
```
Then pivot: for each at-risk user with an anomalous login, check the mail gateway for a first-contact persona sender and the phishing-report mailbox for a reported approach within the preceding 7 days; check CT for a look-alike of our portal registered in the same window.

## Triage guidance

- **Likely malicious:** a CT/brand hit impersonating *our* SSO/webmail registered days before an at-risk user authenticates from a never-before-seen country/ASN; a first-contact "journalist/activist/recruiter" email or social approach to a VIP that time-correlates with a spoofed-portal registration; a successful login whose password was entered on a referrer host that is not ours; the *same* look-alike domain appearing in both mail-gateway sender data and portal referrer logs.
- **Likely benign / expected:** legitimate travel by executives (baseline their normal countries/ASNs before flagging); ordinary typosquatters/parked domains with no inbound corroboration; press/recruiter outreach that is genuine; regional brand variants your org actually owns. A newly-registered look-alike with *zero* internal corroboration is intel to watch, not a finding.
- **Pivot next:** if a spoofed portal correlates with a successful at-risk-user login, treat as an active credential-harvest/ATO — escalate to incident-response-coordinator, force-reset and revoke sessions for the affected identity, hunt onward delivery (HUNT-04) and any resulting mailbox-rule/OAuth persistence, and preserve the persona/portal as attribution intel. Feed the confirmed look-alike domain to the detection pack's C2/distribution-domain blocklist (T1071.001).

## References

- https://blogs.blackberry.com/en/2020/10/blackberry-uncovers-massive-hack-for-hire-group-targeting-governments-businesses-human-rights-groups-and-influential-individuals
- https://www.bellingcat.com/news/mena/2017/06/12/bahamut-pursuing-cyber-espionage-actor-middle-east/
- https://attack.mitre.org/techniques/T1589/
- https://attack.mitre.org/techniques/T1591/
- https://attack.mitre.org/techniques/T1598/003/
- https://attack.mitre.org/techniques/T1585/
- https://attack.mitre.org/techniques/T1585/001/
- https://attack.mitre.org/techniques/T1585/002/
- https://attack.mitre.org/techniques/T1586/001/
