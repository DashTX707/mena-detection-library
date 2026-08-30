# Hunt: Predatory Sparrow — hack-and-leak collection & exfiltration over web service (pre-publication staging)

- **Hypothesis:** Before the wipe and the Telegram leak, the actor **collects and stages the data it will publish**. In the steel-plant operation it exfiltrated tens of thousands of internal emails and "top secret" documents, then leaked them as "proof" of IRGC affiliation. Publication happens off-victim over a web/messaging service (T1567) — not endpoint-observable at the publish step — but the **collection and outbound-staging that feed it are on-victim and huntable**. So if the actor is in a hack-and-leak phase in our estate, the tell is: bulk local/mail collection (a burst of document and mailbox reads by one identity), archived into RAR/ZIP staging, followed by an **anomalous outbound transfer to a web/messaging service** — Telegram API endpoints, paste sites, anonymous file-share, or a cloud bucket — from a host that has no business talking to them. The finding is the **collection burst → archive → outbound-to-web-service chain on one entity**, since the actor's model is "steal in bulk, then dump publicly," not slow trickle to private C2.
- **ATT&CK:**
  - T1567 — Exfiltration Over Web Service (exfiltration) — stolen documents, emails and CCTV "proof" are pushed out and published through Telegram/social/web services in a hack-and-leak model rather than to private infrastructure; hunt the on-victim collection+staging and the anomalous outbound leg.

- **Actor procedure:** In the June 2022 steel-plant operation (Khuzestan / Mobarakeh / Hormozgan) the actor **collected sensitive documents and "top secret" files** from compromised systems and **exfiltrated tens of thousands of internal emails**, subsequently publishing them via its Telegram channel alongside CCTV footage of the molten-metal spill, framing the release as evidence of IRGC ties. The exfiltration/publication is deliberately public — a **hack-and-leak** — so the data leaves for a *web/messaging service the public can see*, not a covert C2. The bulk, one-shot nature of the collection (whole mailboxes, document troves) and the archive-then-upload staging are the on-victim precursors that a defender can actually observe in the window before publication.

- **Why a hunt, not a rule:** The publication act (T1567) lands on Telegram/paste/social — infrastructure the defender cannot instrument — so there is nothing to alert on at the leak itself. The on-victim precursors (document reads, mailbox export, archive creation, an HTTPS upload) are each individually normal: users read files, admins export mailboxes, backup makes archives, and outbound HTTPS is constant. The signal is only in the **chain and volume** — bulk collection by one identity, staged into an archive, then an outbound spike to a service that host never uses — which demands correlation across file, mail, process, and network telemetry plus a data-egress-volume judgement. That is hunt work. A durable piece (e.g., "archive creation followed within N minutes by ≥X MB outbound to a first-seen web-service domain from the same host") is a fair handoff to detection-engineering as a scoped DLP-adjacent analytic.

## Data sources required

- File-access / collection telemetry (4663 object-access, EDR `DeviceFileEvents`): bulk reads across document shares and staging directories; archive creation (`.rar`/`.zip`/`.7z`, WinRAR/`rar.exe` command lines — note the actor's `hackemall` RAR habit)
- Mail-export auditing: Exchange/M365 mailbox export and bulk-access logs (`New-MailboxExportRequest`, eDiscovery/`MailItemsAccessed`, IMAP/EWS bulk pulls) — the "tens of thousands of emails" leg
- Network egress: proxy/firewall/DNS + `DeviceNetworkEvents` for outbound to Telegram API (`api.telegram.org`, `*.t.me`), paste sites, anonymous file-share, and cloud storage; **data-transfer volume** per host/destination
- Per-host/identity egress baseline (from the wiki) to make "first-seen destination" and "volume outlier" meaningful

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — chain bulk collection + archive staging + anomalous outbound-to-web-service on one entity

```kusto
let lookback = 14d;
// (a) bulk document/mail collection + archive staging by one identity
let stage = DeviceFileEvents
    | where TimeGenerated > ago(lookback)
    | where ActionType in ("FileAccessed","FileCreated")
    | extend isArchive = FileName has_any (".rar",".zip",".7z")
    | summarize docs = countif(FileName has_any (".doc",".docx",".pdf",".xls",".xlsx",".pst",".eml",".msg")),
                archives = countif(isArchive), archiveNames = make_set_if(FileName, isArchive, 10),
                first = min(TimeGenerated), last = max(TimeGenerated)
             by DeviceName, InitiatingProcessAccountName
    | where docs >= 200 and archives >= 1;                 // bulk collection funneled into an archive = leak package
// (b) anomalous outbound to a web/messaging service from the same host, after staging
let egress = DeviceNetworkEvents
    | where TimeGenerated > ago(lookback)
    | where RemoteUrl has_any ("api.telegram.org","t.me","pastebin","anonfiles","gofile","mega.nz","transfer.sh","dropbox","0x0.st")
         or RemotePort in (443)
    | summarize bytesOut = sum(coalesce(toint(column_ifexists("SentBytes","0")),0)),
                dests = make_set(RemoteUrl, 15), egressTime = min(TimeGenerated) by DeviceName
    | where dests has_any ("telegram","t.me","paste","anon","gofile","mega","transfer","0x0");  // first-seen/rare service
stage
| join kind=inner (egress) on DeviceName
| where egressTime between (first .. (last + 6h))           // egress follows the collection/staging
| project DeviceName, InitiatingProcessAccountName, docs, archives, archiveNames, dests, egressTime
| order by docs desc
```

## Triage guidance

- **Likely malicious:** one identity performing a bulk read of documents/mailboxes (hundreds to thousands) funneled into a RAR/ZIP archive, followed by an outbound transfer to Telegram's API, a paste site, or anonymous file-share from a host that never contacts such services; mailbox export of *many* mailboxes by a non-eDiscovery account; archive creation with WinRAR using a password immediately before egress (the actor's `hackemall` tradecraft). Corroboration from HUNT-04's OSINT lane (a pre-leak teaser naming our org) turns this from suspicious to active.
- **Likely benign / expected:** legitimate eDiscovery/legal-hold exports, backup and archival jobs that create large archives, and sanctioned cloud-storage/collaboration egress — baseline the accounts, hosts, and destinations that do this normally. Developers and marketing may reach Telegram/paste/file-share legitimately; the differentiator is the **collection-burst-then-egress chain on one entity to a first-seen destination**, not any single leg. A single large upload with no preceding bulk collection is probably benign.
- **Pivot next:** a confirmed collection→archive→web-service chain is likely active hack-and-leak staging — and for this actor, hack-and-leak typically runs *alongside* a destructive payload, so treat it as a live incident: escalate to incident-response-coordinator, preserve the staged archive and egress logs (attribution + scope), and immediately run HUNT-03 (pre-detonation discovery) and the destructive-detection lane on the same host set, because the leak and the wipe are two faces of the same operation. Feed the destination indicators and any teaser correlation back to cti-expert.

## References

- https://www.picussecurity.com/resource/blog/predatory-sparrow-inside-the-cyber-warfare-targeting-irans-critical-infrastructure
- https://en.wikipedia.org/wiki/Predatory_Sparrow
- https://attack.mitre.org/techniques/T1567/
