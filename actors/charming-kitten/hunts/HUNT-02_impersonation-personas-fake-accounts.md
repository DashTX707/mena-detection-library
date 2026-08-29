# Hunt: Charming Kitten impersonation personas & fake/compromised accounts (FLAGSHIP)

- **Hypothesis:** If Charming Kitten is running an identity-centric operation against us, then before any malware or credential-harvest link we should observe its signature *persona* tradecraft — fabricated social-media/email personas (journalists, conference organizers, activists) engaging our high-risk staff on LinkedIn/X/email, contact from otherwise-trusted-but-compromised third-party mailboxes, and exfil-stage mailboxes/OneDrive accounts whose names approximate our own organization (`<victim_org>@outlook.com`).
- **ATT&CK:**
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development)
  - T1585.002 — Establish Accounts: Email Accounts (resource-development)
  - T1586.002 — Compromise Accounts: Email Accounts (resource-development)
  - T1566.003 — Phishing: Spearphishing via Service (initial-access)
  - T1036.010 — Masquerading: Masquerade Account Name (stealth)

- **Actor procedure:** The hallmark of this actor. It cultivates fake personas — e.g. the "Mona Louri" human-rights-activist X/Twitter persona, and lures spoofing "Jamileh Nedai", "David Webb", "Daniel Serwer" — descending from the historical NEWSCASTER network, to build rapport over days-to-weeks before delivering a credential link or malware. It registers persona email accounts and hijacks *legitimate compromised* third-party mailboxes to lend authenticity and abuse existing trust. First contact and lure delivery frequently ride non-email services (LinkedIn/X DMs, fake Google Meet invitations). At the exfil stage it names attacker mailboxes/OneDrive to echo the victim org (`<victim_org>@outlook.com`) so the destination looks benign.
- **Why a hunt, not a rule:** Persona creation, email-account registration and third-party-mailbox compromise all happen off your perimeter and on platforms you don't log. There is no event to alert on until a human recognizes the social-engineering pattern. "Inbound mail from a real but compromised partner" is indistinguishable from legitimate mail by content alone, and "a new LinkedIn connection" has a base rate that makes alerting meaningless. This is a persona-tracking / attribution hunt: cluster avatar reuse, cross-platform linkage, reused bios and lure language, and correlate reported-contact tips — human-driven, iterative, not a rule. The one narrow account-name-masquerade signal (`org-lookalike@outlook.com`) is real but too rare/late to be a standalone alert.

## Data sources required

- Reported-contact / user-phish-report inbox (the primary lever for service-delivered lures)
- Social-media / brand-monitoring & persona-tracking intel (avatar hashes, bio reuse, cross-platform account linkage)
- SEG logs: senders, reply-to, display-name vs. envelope mismatch, first-time-sender to high-risk roles
- M365 Unified Audit / Exchange: outbound destinations, new external OneDrive share targets, exfil-mailbox naming
- Threat-intel persona indicator lists (known CK persona handles, spoofed-individual names)

## Query starting point

Platform: `KQL / Microsoft Sentinel` — (a) exfil destinations whose name echoes our org, and (b) first-contact senders spoofing named individuals CK is known to impersonate

```kusto
// (a) Account-name masquerade at exfil stage (T1036.010)
let orgTokens = dynamic(["contoso","conto so","contos0"]);  // our org + homoglyph variants
CloudAppEvents
| where ActionType in ("FileUploaded","SharingSet","AnonymousLinkCreated")
| extend dest = tolower(tostring(RawEventData.TargetUserOrGroupName))
| where dest has "outlook.com" or dest has "onedrive"
| where dest has_any (orgTokens)
| where AccountObjectId !in (KnownEmployeeIds)   // not one of our real users
| project TimeGenerated, InitiatingUser=AccountDisplayName, dest, ActionType, IPAddress
// (b) Inbound persona / spoofed-individual first contact (T1585.x / T1586.002 / T1566.003)
| union (
  EmailEvents
  | where SenderFromAddress !endswith "@contoso.com"
  | extend disp = tolower(SenderDisplayName)
  | where disp has_any ("mona louri","jamileh nedai","david webb","daniel serwer")
       or (SenderDisplayName has_any (KnownExecNames) and SenderFromAddress !in (KnownExecAddresses))
  | join kind=inner (highrisk_roles) on $left.RecipientEmailAddress == $right.email
  | project TimeGenerated, SenderDisplayName, SenderFromAddress, RecipientEmailAddress, Subject, Url=UrlCount)
```

Companion (out-of-band): triage every user-reported LinkedIn/X/Google-Meet "journalist/conference organizer" contact to high-risk staff; run reported persona handles/avatars through persona-tracking intel for avatar reuse and cross-platform linkage.

## Triage guidance

- **Likely malicious:** a "journalist/researcher/event organizer" persona that builds rapport over multiple messages before any link; display name of a known public figure over a free-webmail envelope; inbound mail from a real partner mailbox that suddenly sends unusual lure content (compromised third party); an external OneDrive/mailbox named to mimic our org receiving uploads; avatar/bio reused across platforms or matching a known CK persona.
- **Likely benign / expected:** genuine press or academic outreach verifiable against the outlet; real recruiters; legitimate partner correspondence; internal users sharing to their own personal accounts (confirm identity). Maintain a baseline of known-good partners and recruiters.
- **Pivot next:** confirm the person's identity out-of-band; if a persona is confirmed, sweep all high-risk staff for prior contact from the same handle/mailbox, hand persona indicators to intel for tracking, and treat any account that engaged as at-risk — pivot to the identity detection pack (impossible-travel, MFA-fatigue T1621, app-password T1556.006, inbox-hiding-rules T1564.008). A compromised-partner or org-lookalike-exfil hit is a likely active incident → escalate to IR.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/untangling-iran-apt42-operations
- https://attack.mitre.org/groups/G0059
