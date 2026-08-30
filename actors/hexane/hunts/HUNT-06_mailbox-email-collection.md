# Hunt: HEXANE mailbox email collection (anomalous mailbox access & bulk sync)

- **Hypothesis:** If HEXANE is collecting mail from a compromised mailbox — either via valid credentials from its password-spraying or through a mailbox-reading implant — then the espionage objective should surface as anomalous mailbox-access behavior: bulk item reads or a full mailbox sync/export inconsistent with the user's normal client pattern, access from new/foreign infrastructure or non-standard mail clients/protocols (legacy IMAP/EWS/Graph), and/or newly created inbox rules that auto-forward or hide mail. The finding is a mailbox accessed in a bulk/automation shape from anomalous provenance, not a user simply reading email.
- **ATT&CK:**
  - T1114 — Email Collection (collection)

- **Actor procedure:** As part of its espionage objectives HEXANE collected email content from compromised mailboxes. With valid accounts obtained through password spraying against Exchange/OWA/O365, mail is a high-value, low-noise collection target — readable directly through the mail service or synced out in bulk, and easily persisted with forwarding rules.
- **Why a hunt, not a rule:** Mailbox access is what mail systems are *for*; users legitimately read, search, sync and export their own mail across many devices and clients, so raw "mailbox accessed" or "items read" events have an overwhelming benign base rate. The discriminating signal is anomalous provenance and shape — bulk sync from a first-seen IP/geo/client, or a new hide-and-forward rule — which requires per-user baselining and correlation with sign-in anomalies (password-spray follow-through), a judgement call rather than a precise selector. Auto-forwarding-rule creation, if reliably scoped, is a candidate to hand to detection-engineering.

## Data sources required

- Microsoft 365 / Exchange mailbox audit (UnifiedAuditLog: `MailItemsAccessed`, `MailboxLogin`, `New-InboxRule`, `Set-Mailbox` forwarding, sync/export ops)
- Azure AD / Entra sign-in logs (client app, protocol, IP/geo — correlate to spray follow-through, HUNT ties to T1078/T1110.003 detection lane)
- Baseline of each user's normal mail clients, protocols and geos
- Outbound mail-flow logs (auto-forward to external domains)

## Query starting point

Platform: `KQL / Microsoft Sentinel` — bulk mailbox access / new forwarding rule from anomalous provenance

```kusto
// (a) Bulk MailItemsAccessed via non-interactive/legacy protocol from a first-seen IP
let known = OfficeActivity
    | where TimeGenerated between (ago(60d)..ago(2d))
    | summarize by UserId, ClientIP;
OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation in ("MailItemsAccessed","MailboxLogin")
| where ClientInfoString has_any ("IMAP","POP","EWS","Graph","eM Client","non-interactive") or isempty(ClientInfoString)
| join kind=leftanti known on UserId, ClientIP        // first-seen IP for this user
| summarize accesses = count(), items = sum(tolong(coalesce(column_ifexists("ItemCount","0"),"0"))),
           ips = make_set(ClientIP, 10) by UserId, ClientInfoString
| where accesses >= 50
| order by accesses desc

// (b) New auto-forward / hide rule: Operation in ("New-InboxRule","Set-Mailbox")
//     with ForwardTo/RedirectTo external OR DeleteMessage/MoveToFolder(RSS/Archive) = classic mail-theft persistence
```

## Triage guidance

- **Likely malicious:** a mailbox bulk-synced or exported via legacy IMAP/EWS/Graph from a first-seen foreign IP shortly after a password-spray sign-in success; a newly created inbox rule auto-forwarding to an external address or silently moving/deleting security-notification mail; mail access from infrastructure overlapping HUNT-02 C2.
- **Likely benign / expected:** users legitimately add new devices, travel, use mobile clients, configure vacation/forward rules and export mail; e-discovery/DLP/backup tools access mailboxes at scale. Baseline sanctioned mail-access services and normal per-user clients/geos; a single new device is routine.
- **Pivot next:** confirmed mailbox collection → force credential reset + revoke sessions/tokens, remove malicious rules, scope which mail was accessed, correlate the sign-in to the password-spray detection lane (T1110.003/T1078), and escalate to IR — an actively read/forwarded mailbox is a live data-theft incident.

## References

- https://www.clearskysec.com/siamesekitten/
- https://www.secureworks.com/research/lyceum-takes-center-stage-in-middle-east-campaign
- https://attack.mitre.org/techniques/T1114/
