# Hunt: Cotton Sandstorm persona & sock-puppet cover-hacktivist network

- **Hypothesis:** If ASA is running an influence operation touching our brand, sector or staff, then before or alongside any technical compromise we should observe its signature *persona* tradecraft — fabricated cover-hacktivist groups and sock-puppet social/email accounts (Cyber Court, Cyber Flood, For-Humanity, Regiment GUD, Zeus is Talking, Anzu Team, Makhlab al-Nasr, NET Hunter, Emirate Students Movement) amplifying manufactured "grassroots" outrage, plus persona email/messaging accounts sending intimidation to our people (e.g. the Contact-HSTG hostage-family model). The hunt clusters these personas by reused avatars, handles, bios, domains and lure language rather than waiting for an on-network event.
- **ATT&CK:**
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development)
  - T1585.002 — Establish Accounts: Email Accounts (resource-development)

- **Actor procedure:** Persona fabrication is this actor's hallmark. ASA stands up cover-hacktivist fronts and amplifies them through the "Cyber Court" hub (`cybercourt[.]io`, Telegram `@cybercourt_io`) to manufacture apparent grassroots protest of the Israel–Hamas conflict, and runs standalone personas — "For-Humanity" (IPTV hijack with a generative-AI news anchor), "Regiment GUD" (impersonating the real French far-right group during the 2024 Paris Olympics), "Zeus is Talking", "Anzu Team" (vs. Sweden), "Cyber Flood" and "Contact-HSTG" (SMS/messaging intimidation of Israeli hostage families via `Contact-hstg[.]com`). It registers persona email accounts to send intimidation and to operate its cover businesses (e.g. `info@vps-agent[.]net`). Personas often reuse avatars, bios and generative-AI-produced media across platforms.
- **Why a hunt, not a rule:** Persona and email-account creation happen entirely off your perimeter, on platforms you don't log; there is no event to alert on until a human recognizes the influence pattern. "A new social account mentioned our brand" and "an inbound message from a free webmail account" have base rates that make alerting worthless. This is a persona-tracking / attribution hunt: cluster avatar-hash reuse, cross-platform linkage, reused bio and lure language, persona-domain overlap, and correlate user-reported intimidation contact — iterative, human-driven work, not a rule.

## Data sources required

- Social-media / brand-monitoring & persona-tracking intel (avatar hashes, bio reuse, cross-platform account linkage, Telegram channel monitoring)
- User-reported intimidation-message inbox and abuse reports (the primary lever for the Contact-HSTG-style messaging)
- Threat-intel persona indicator lists (known ASA persona handles, domains, and impersonated real groups)
- Secure email gateway / SMS-abuse logs (inbound persona-account contact to staff, display-name vs envelope mismatch)
- Newly-registered / lookalike-domain feeds (persona domains — overlaps HUNT-03)

## Query starting point

Platform: `Threat-intel + KQL / Microsoft Sentinel` — cluster known ASA persona indicators and surface inbound persona contact to staff

```kusto
// Inbound contact from known ASA persona domains/handles, or new free-webmail senders
// carrying persona / intimidation lure language, to any staff recipient
let personaDomains = dynamic(["cybercourt.io","cyberflood.io","zeusistalking.io","zeusistalking.net",
    "zeusistalking.com","rgud-group.net","rgud-group.com","pro-today.org","contact-hstg.com","vps-agent.net"]);
let personaHandles = dynamic(["cyber court","cyber flood","for-humanity","for humanity","regiment gud",
    "zeus is talking","anzu team","makhlab al-nasr","net hunter","emirate students"]);
EmailEvents
| where SenderFromDomain in (personaDomains)
    or (tolower(SenderDisplayName) has_any (personaHandles))
    or (Subject has_any ("hostage","you are being watched","regiment gud","cyber court"))
| project TimeGenerated, SenderFromAddress, SenderDisplayName, RecipientEmailAddress, Subject, UrlCount
```

Companion (out-of-band): run any reported persona handle/avatar through persona-tracking intel for avatar-hash and bio reuse; map the cover-hacktivist cluster (Cyber Court amplifying its satellites) and check whether any front is targeting our sector; correlate persona-domain registrations with HUNT-03 infrastructure clustering.

## Triage guidance

- **Likely malicious:** an inbound intimidation message referencing our staff/families from a free-webmail or persona-domain account (Contact-HSTG pattern); a "grassroots hacktivist" persona suddenly promoting outrage against our brand and amplified by the Cyber Court hub; a persona whose avatar/bio is reused across platforms or matches a known ASA front; a persona impersonating a real activist/political group to add credibility (Regiment GUD model).
- **Likely benign / expected:** genuine activist or press accounts verifiable against real organizations; real journalists/researchers contacting staff; legitimate brand mentions and criticism. Maintain a baseline of known-good outlets and suppress.
- **Pivot next:** confirm any persona out-of-band; if confirmed, sweep all staff for prior contact from the same handle/account, hand persona indicators (avatars, handles, domains) to intel for tracking, and pivot to HUNT-03 to cluster the persona's domain/hosting infrastructure. Intimidation contact against staff or their families is a live safety incident → escalate to IR and exec protection immediately.

## References

- https://www.ic3.gov/CSA/2024/241030.pdf
- https://blogs.microsoft.com/on-the-issues/2024/10/23/as-the-u-s-election-nears-russia-iran-and-china-step-up-influence-efforts/
- https://attack.mitre.org/techniques/T1585/001/
- https://attack.mitre.org/techniques/T1585/002/
