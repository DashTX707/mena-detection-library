# Hunt: Imperial Kitten — fake recruiter personas & attacker-controlled C2 mailboxes

- **Hypothesis:** If Imperial Kitten is targeting our people, then two off-victim resource-development footprints become observable at our perimeter: (1) **fabricated recruiter/professional personas** — LinkedIn/social profiles and free-webmail identities impersonating recruiters, HR or industry contacts — reaching our staff with CV/recruitment-themed rapport-building and eventually a macro-enabled Excel lure; and (2) **attacker-controlled Yandex and `update-platform-check.online` mailboxes** used as the IMAP command-and-control endpoints. The hunt looks for inbound contact from persona mailboxes (leviblum@, brodyheywood@, justin.w0od@, n0ah.harrison@, giorgosgreen@, oliv.morris@, harri5on.patricia@, d3nisharris@, hardi.lorel@ yandex.com; itdep@/office@update-platform-check.online) and their behavioral cousins (leetspeak'd personal names on consumer webmail, recruitment subject lines to non-HR staff, brand-monitoring hits on look-alike personas), and — separately — any *outbound* IMAP/993 session from a non-mail-client host to those same mailbox providers, which would mean a persona mailbox has flipped from lure-delivery to live C2.
- **ATT&CK:**
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development) — long-running fake recruiter/professional personas (TA456/Tortoiseshell lineage) used to build rapport before delivering CV lures; hunt via brand/persona monitoring + inbound social-engineering pattern.
  - T1585.002 — Establish Accounts: Email Accounts (resource-development) — attacker-created Yandex and update-platform-check.online webmail accounts serving as both lure senders and IMAP C2 mailboxes; hunt inbound sender IOCs and the leetspeak-name pattern.
  - (context) T1566.001 Spearphishing Attachment / T1071.003 Mail Protocols — the delivery and C2 these personas/mailboxes enable; covered in the detection lane.

- **Actor procedure:** The cluster (overlapping TA456/Tortoiseshell) runs long-lived fabricated personas — recruiters, journalists, attractive "professional contacts" — to social-engineer employees at transportation, logistics, maritime, technology and defense targets, delivering CV/recruitment-themed lures. Delivery uses macro-enabled Excel workbooks that drop a Python reverse shell. The C2 mailboxes are consumer Yandex accounts and mailboxes at `update-platform-check.online` (itdep@, office@) that IMAPLoader and StandardKeyboard poll over IMAP for tasking. The persona webmail addresses themselves (note the deliberate leetspeak: `justin.w0od`, `n0ah.harrison`, `harri5on.patricia`, `d3nisharris`) are usable network IOCs.
- **Why a hunt, not a rule:** The creation of the persona and the mailbox happens on third-party platforms we do not control — there is no endpoint event for T1585.001/T1585.002. The inbound side is thin on its own: an email from a Yandex address, or a LinkedIn recruiter message, is overwhelmingly benign, so a standalone "block Yandex" or "flag recruiter emails" rule is unacceptable false-positive load and out of scope for detection. The finding lives in *correlation and human judgement*: a consumer-webmail sender with a leetspeak'd human name, sending a recruitment lure with an Office attachment to an engineering/maritime employee who has no recruiting relationship, corroborated by external brand-monitoring showing a matching fake persona. The exact IOC mailboxes will rotate; hunt the pattern, keep the mailbox list as a pivot. A durable observable (non-mail-client process opening IMAP/993 to yandex — the C2 flip) belongs to detection-engineering (see HUNT/detection T1071.003).

## Data sources required

- Mail-gateway / message-tracking logs (sender address, display name, subject, attachment type, recipient role) — inbound persona-lure surface
- External brand-/persona-monitoring and social-media takedown intel (fake recruiter profiles impersonating our org or peers) — the off-victim half
- HR/recruiting system context (is there a real requisition/relationship?) to separate genuine recruiters from personas
- Network + EDR IMAP/993 telemetry (for the C2-flip pivot; primary detection lives in the detection pack)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR — EmailEvents)` — IOC sender fast path plus the leetspeak-webmail + recruitment-lure behavioral pattern

```kusto
let iocSenders = dynamic(["leviblum@yandex.com","brodyheywood@yandex.com","justin.w0od@yandex.com",
  "n0ah.harrison@yandex.com","giorgosgreen@yandex.com","oliv.morris@yandex.com",
  "harri5on.patricia@yandex.com","d3nisharris@yandex.com","hardi.lorel@yandex.com",
  "itdep@update-platform-check.online","office@update-platform-check.online"]);
let consumerWebmail = dynamic(["yandex.com","yandex.ru"]);
EmailEvents
| where TimeGenerated > ago(90d)
| extend senderDom = tostring(split(SenderMailFromAddress,"@")[1])
| where SenderMailFromAddress in (iocSenders)          // (a) known IOC mailboxes
    or (
        senderDom in (consumerWebmail)                  // (b) consumer webmail...
        and SenderMailFromAddress matches regex @"[a-z]+[0-9][a-z.]*@"  // ...with digit-in-name (leetspeak)
        and (Subject has_any ("CV","resume","recruit","vacancy","position","opportunity","offer","HR"))
      )
| where AttachmentCount > 0                              // lure carries the Office doc
| join kind=leftouter (EmailAttachmentInfo | where FileType has_any ("xls","xlsm","xlsb","doc","docm","zip"))
    on NetworkMessageId
| project TimeGenerated, SenderMailFromAddress, SenderDisplayName, Subject, RecipientEmailAddress, FileName, FileType
| order by TimeGenerated desc
// PIVOT: cross-ref RecipientEmailAddress against HR for a real requisition; check brand-monitoring for a matching fake persona
```

## Triage guidance

- **Likely malicious:** any inbound from the IOC mailbox list; a consumer-webmail sender with a digit-in-name (leetspeak) human display name sending an Office attachment with a recruitment theme to a non-HR employee who has no recruiting relationship; a LinkedIn/social persona flagged by brand-monitoring that also sent email; a persona thread that pivots from rapport-only messages to "please review the attached CV/role details.xlsm". The strongest signal is the same persona confirmed on both social and email against a targeted employee.
- **Likely benign / expected:** legitimate recruiters and staffing agencies use consumer webmail and send real CVs constantly; digit-bearing addresses are common (many people have numbers in their handle); HR receives genuine recruitment mail all day. Scope to *unsolicited* contact to engineering/maritime/defense staff who are not hiring managers, and let the HR-relationship check and brand-monitoring corroboration carry the discrimination. One recruiter email is noise.
- **Pivot next:** if a lure is confirmed, detonate the attachment in a sandbox to confirm the VBA→Python reverse-shell chain (hand the child-process behavior to the detection lane, T1204.002/T1059.006), pull all recipients of the same persona to scope the target set, and pivot every recipient host to the email-C2 outbound-IMAP hunt and the AppDomainManager/malware-footprint hunt (HUNT-03). Report the fake persona for takedown and add the mailbox + any newly discovered persona to the pivot watchlist. If any recipient host is already beaconing IMAP/993 to Yandex/update-platform-check.online, this is a live compromise — escalate to incident-response-coordinator.

## References

- https://thehackernews.com/2023/11/iran-linked-imperial-kitten-cyber-group.html
- https://www.crowdstrike.com/en-us/blog/imperial-kitten-deploys-novel-malware-families/
- https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/yellow-liderc-ships-its-scripts-delivers-imaploader-malware.html
- https://attack.mitre.org/techniques/T1585/001/
- https://attack.mitre.org/techniques/T1585/002/
