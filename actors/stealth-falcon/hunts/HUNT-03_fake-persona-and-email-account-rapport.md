# Hunt: Stealth Falcon — fictitious personas & email accounts building rapport with targets

- **Hypothesis:** If Stealth Falcon is preparing to phish our at-risk users, then weeks-to-months *before* any link is sent there is an off-victim tell: a newly-created, thinly-backed social-media persona or "journalist/NGO" front account, and a matching pretext email account from a lookalike/free-mail domain, opening friendly first contact ("interview request", "collaboration", "speaking opportunity") with journalists, activists and dissident-affiliated staff. The hunt fuses brand/persona-monitoring intel (the account) with inbound-message metadata (first contact from a never-before-seen sender to a high-risk user) — the pairing of a suspicious new persona *and* a first-contact pretext to exactly the population Stealth Falcon targets is the finding; a new follower or a cold email alone is not.
- **ATT&CK:**
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development) — actor-run personas (e.g. journalist "Andrew Dwight", front org "The Right to Fight") and Twitter accounts used to build rapport and later deliver links.
  - T1585.002 — Establish Accounts: Email Accounts (resource-development) — pretext email accounts tied to the fictitious orgs/personas used to send the approach and the aax.me links.

- **Actor procedure:** Operators invested months in social engineering: they stood up fake personas and front organizations, followed/engaged targets on Twitter, exchanged messages to establish trust, and only then delivered the malicious tracking link (HUNT-01) or macro document. The email side used accounts branded to the same fictitious entities, sending pretexts (collaboration/interview/speaking offers) that matched each target's public work as a journalist or activist. The whole rapport phase is off-victim and human — the value to the defender is early warning and takedown, not endpoint detection.
- **Why a hunt, not a rule:** The persona/account creation happens entirely on third-party platforms (Twitter, webmail) we do not control and cannot instrument, so there is no log to alert on. What little we can see — a first-contact email to a staffer, a new follower — is indistinguishable from legitimate press/NGO outreach at the single-event level; our journalists and activists are *supposed* to get cold contact from strangers. Only by correlating multiple weak signals (account age, no real footprint, lookalike domain, targeting exactly our high-risk cohort, later pivoting to an aax.me link) and applying human judgement about the pretext does a targeting campaign emerge. This is intelligence and takedown work; if a persona is confirmed hostile, the deliverable is a takedown request and a watch-list entry, not an alert.

## Data sources required

- Brand/persona-monitoring & social-media intelligence: newly-created accounts impersonating the org, its staff, or fictitious "journalist/NGO" fronts engaging our high-risk users.
- Inbound email metadata (mail-gateway / Defender for Office 365): first-contact senders, sender-domain age, SPF/DKIM/DMARC posture, display-name vs. domain mismatch — scoped to high-risk recipients.
- Newly-registered / lookalike-domain feeds (cross-ref HUNT-04) to spot pretext sender domains.
- HR/identity risk tagging of public-facing/high-risk users (journalists, comms, activists, diaspora contacts).

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender for Office 365)` — first-contact pretext emails to high-risk users from young/lookalike sender domains

```kusto
let riskUsers = _GetWatchlist('high_risk_public_facing_users') | project RecipientEmailAddress = SearchKey;
let knownSenders =   // senders this user has corresponded with before = established, lower interest
    EmailEvents
    | where TimeGenerated between (ago(365d) .. ago(30d))
    | distinct RecipientEmailAddress, SenderFromAddress;
EmailEvents
| where TimeGenerated > ago(30d)
| where RecipientEmailAddress in (riskUsers)
| where DeliveryAction == "Delivered"
| join kind=leftanti knownSenders on RecipientEmailAddress, SenderFromAddress   // FIRST contact only
| extend senderDomain = tostring(split(SenderFromAddress, "@")[1])
| extend pretext = Subject has_any ("interview","collaboration","speaking","opportunity","press","human rights","conference","invitation")
| join kind=leftouter ( _GetWatchlist('newly_registered_lookalike_domains') | project senderDomain = SearchKey, domainAgeDays ) on senderDomain
| where pretext or isnotempty(domainAgeDays)
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, senderDomain, domainAgeDays, Subject, SenderDisplayName
| order by domainAgeDays asc
```

## Triage guidance

- **Likely malicious:** a first-contact pretext (interview/collaboration/speaking) to a high-risk user from a young or lookalike sender domain with weak SPF/DKIM/DMARC; a social persona with near-zero history impersonating a journalist/NGO that engaged the same user shortly before an aax.me link appeared; display-name spoofing a real outlet with a mismatched domain.
- **Likely benign / expected:** journalists and activists legitimately receive constant cold outreach — real press, real conference invitations, real NGO collaboration all look like this. A well-established sender, a corporate domain with clean auth, or a contact the user already knows is expected. The persona side is heavy with false positives (parody, fan, and genuine new accounts); never action on account novelty alone.
- **Pivot next:** if a persona/email is assessed hostile, file platform takedown requests, add the sender/domain/persona to the watch-list, and warn the targeted user out-of-band. Pivot to HUNT-01 (did an aax.me link follow?) and HUNT-04 (does the sender domain belong to a lookalike-registration cluster?). Confirmed pre-attack targeting of a specific user is intel to brief that user and the SOC — not an incident unless a link/payload was delivered.

## References

- https://citizenlab.ca/2016/05/stealth-falcon/
- https://attack.mitre.org/techniques/T1585/001/
- https://attack.mitre.org/techniques/T1585/002/
