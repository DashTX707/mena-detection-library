# Hunt: Rocket Kitten — persona-driven social engineering, impersonation and off-email delivery

- **Hypothesis:** If Rocket Kitten is cultivating our staff for a spear-phish, then before any payload lands we should see the *rapport-building* footprint of their persona tradecraft: inbound mail from newly-created free-webmail/persona accounts that *impersonate* a real, recognizable person or a trusted third party (e.g. a security-research group), display-name spoofs of internal or known-contact identities, and user-reported approaches over social-media/messaging services (Facebook, LinkedIn) that then pivot the conversation to a file or link. The single anomaly (one first-contact email) is thin; the finding is the *stack* — display-name/impersonation mismatch + first-time external sender + a same-thread pivot to an attachment or OneDrive link, aimed at the academic/journalist/dissident-liaison population.
- **ATT&CK:**
  - T1566.003 — Phishing: Spearphishing via Service (initial-access) — first contact and lure delivery over Facebook/social messaging rather than corporate email.
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development) — fake Facebook/webmail personas (e.g. `mah.asf.xxx`) that build trust in fluent Farsi/Hebrew.
  - T1585.002 — Establish Accounts: Email Accounts (resource-development) — attacker-registered Yahoo/Gmail persona senders used to correspond and deliver lures.
  - T1586.002 — Compromise Accounts: Email Accounts (resource-development) — impersonation of a real, recognizable person / trusted third party, including a genuinely compromised contact's identity and documents.

- **Actor procedure:** Per Trend Micro's *Spy Kittens Are Back* and *Woolen-GoldFish*, Rocket Kitten leans heavily on human rapport. They stand up fake Facebook profiles that converse in perfect Farsi/Hebrew and recreate them under new random suffixes when removed (`mah.asf.xxx`); they register webmail personas (`[name]_asf@yahoo.com`) and impersonate trusted entities — a spoofed `clearsky.cybersec.group@gmail.com` posing as the ClearSky research team, and a known Israeli engineer whose computer they are assessed to have compromised to steal *genuine* documents (identical file metadata) later reused as authentic-looking lures against other Israeli targets. Contact is built patiently — one analyzed case had attackers reply in Hebrew to confirm an email's authenticity — before a malicious Office file or OneDrive link is delivered.

- **Why a hunt, not a rule:** The persona accounts and the compromised third party live entirely off our network; the social-media first contact never touches enterprise mail. What reaches us is a *plausible* email whose maliciousness is contextual — a first-time sender whose display name matches a known contact but whose address does not, a "trusted researcher" whose domain is free-webmail, a thread that only *later* pivots to a file. Alerting on "external first-time sender" or "display-name mismatch" alone drowns SOC in newsletters and genuine new contacts. The finding is the analyst-assembled pattern (impersonation + newness + lure-pivot + targeted recipient), plus fusion with user-reported social approaches — judgement work. If a precise, low-FP signature emerges (e.g. display-name-exact-match to an internal exec from an external free-webmail sender to a watchlist recipient), route that to detection-engineering.

## Data sources required

- Mail metadata / gateway logs (`EmailEvents`, message headers) — sender address vs. display name, sender first-seen date, SPF/DKIM/DMARC posture, free-webmail senders to watchlist recipients.
- Phishing-report mailbox / user-reported approaches (SOC abuse queue, security-awareness reporting button) — the social-media contacts that never hit mail logs.
- Brand / executive-impersonation and external threat intel — persona handles, look-alike sender addresses, spoofed research-group identities.
- Targeted-user watchlist (academics, journalists, dissident-liaison, policy staff) plus a roster of known-contact display names to detect impersonation.

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender for Office 365)` — surface impersonation-style first-contact senders to the targeted population that later carry a file/link.

```kusto
let watchlistRecipients = _GetWatchlist('targeted_users') | project RecipientEmailAddress = SearchKey;
let knownDisplayNames = _GetWatchlist('known_contacts') | project displayName = SearchKey;   // execs + trusted external contacts
EmailEvents
| where TimeGenerated > ago(45d)
| where EmailDirection == "Inbound"
| join kind=inner watchlistRecipients on RecipientEmailAddress
// free-webmail or first-time external sender
| extend senderDom = tostring(split(SenderMailFromAddress,"@")[1])
| where senderDom in ("gmail.com","yahoo.com","outlook.com","hotmail.com","protonmail.com")
       or AuthenticationDetails has_any ("spf=fail","dmarc=fail")
// impersonation: display name matches a known contact but address domain does not belong to them
| extend disp = tostring(SenderDisplayName)
| where disp in (knownDisplayNames) or disp has_any ("research","security","clearsky","cert","support")
| join kind=leftouter (
    EmailAttachmentInfo | where FileType has_any ("doc","docx","xls","xlsx","ppt","pptx","pdf","exe","zip")
    | project NetworkMessageId, FileName, FileType
  ) on NetworkMessageId
| join kind=leftouter (
    EmailUrlInfo | where Url has_any ("1drv.ms","onedrive","sharepoint","bit.ly","tinyurl")
    | project NetworkMessageId, Url
  ) on NetworkMessageId
| where isnotempty(FileName) or isnotempty(Url)        // lure-pivot present
| project TimeGenerated, SenderMailFromAddress, disp, RecipientEmailAddress, Subject, FileName, Url
| order by TimeGenerated asc
```

## Triage guidance

- **Likely malicious:** a first-time free-webmail sender whose display name impersonates a known researcher, colleague or trusted group, writing to a watchlist academic/journalist in fluent regional language, whose thread carries or later delivers an Office file or OneDrive link; a user-reported Facebook/LinkedIn approach from a plausible persona that steers toward a shared file; genuine-looking documents whose metadata belongs to a known external individual arriving from an address that is *not* theirs.
- **Likely benign / expected:** conference organizers, journalists' genuine sources, and academic collaborators legitimately reach out from personal webmail — corroborate with the recipient before calling it; marketing/newsletter senders trip free-webmail + link heuristics; display-name collisions with common words ("Support","Security") are noisy — require the impersonation to match a *specific* known contact or trusted third party. A first-contact email with no lure-pivot and no impersonation is normal correspondence.
- **Pivot next:** enrich the sender/persona against external intel and the actor's known handles; check whether the impersonated third party is themselves compromised (T1586.002) by validating document metadata provenance; if the recipient engaged and received a file/link, follow into HUNT-01 (credential harvesting) or the detection lane's macro-execution analytics (T1204.002/T1137.001); preserve persona artifacts as attribution intel and brief the targeted users directly.

## References

- https://documents.trendmicro.com/assets/wp/wp-the-spy-kittens-are-back.pdf
- https://documents.trendmicro.com/assets/wp/wp-operation-woolen-goldfish.pdf
- https://attack.mitre.org/techniques/T1566/003/
- https://attack.mitre.org/techniques/T1585/001/
- https://attack.mitre.org/techniques/T1585/002/
- https://attack.mitre.org/techniques/T1586/002/
