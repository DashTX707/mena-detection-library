# Hunt: UNC1549 (TA455) — reconnaissance from compromised third-party mailboxes and the trusted-relationship pivot

- **Hypothesis:** If UNC1549 is preparing to reach us through a trusted third party (vendor, contractor, partner), then the reconnaissance happens *inside the third party's mailbox*, not on our endpoints — operators read compromised inboxes to learn our legitimate business processes (password-reset flows, invoice/PO threads, project names) and gather victim environment/network information so the follow-on lure is authentic. The near-victim tell we *can* see is on the trust boundary: a known vendor/partner contact suddenly emailing lures that quote our internal process language, or a vendor account authenticating into our Citrix/VMware/Azure Virtual Desktop and then behaving unlike that vendor's baseline. The finding is anomalous vendor-mailbox behaviour (on tenants we can see) **or** a trusted-partner inbound that references non-public internal process detail — correlated with an out-of-baseline vendor VDI/logon.
- **ATT&CK:**
  - T1590.005 — Gather Victim Network Information: IP Addresses (reconnaissance) — actor reviews compromised inboxes / third parties to identify legitimate business processes and victim environment info before pivoting; hunted via mailbox audit logs on tenants in scope and trust-boundary anomalies.
  - T1199 — Trusted Relationship (initial-access) — corroborating context: the pivot rides third-party vendor/contractor accounts and their Citrix/VMware/AVD access with VDI-breakout (detection-lane; cited to anchor the trust-boundary side of this hunt).
- **Actor procedure:** GTIG documents UNC1549 pivoting into aerospace/defense targets through compromised third-party vendor, contractor and partner accounts. Before the pivot, operators mine the compromised inbox: they read legitimate threads, identify real business processes (e.g. password-reset requests), and gather environment info to craft authentic-looking lures. They then abuse the third party's Citrix/VMware/Azure Virtual Desktop access, using VDI-breakout to escape the virtualized session into the target network.
- **Why a hunt, not a rule:** The reconnaissance itself is invisible to the ultimate victim — it occurs in someone else's mailbox — so there is nothing to alert on directly; and where we *do* have visibility (a managed vendor tenant, our own VDI/trust boundary) the signal is behavioural drift, not a discrete event. Distinguishing "vendor doing normal vendor things" from "attacker wearing the vendor's identity" requires a per-vendor baseline and human correlation of mailbox, auth and VDI-session evidence. That judgement is hunt work. A crisp fall-out (e.g. a vendor account launching an interactive shell/tunnel inside a VDI session it never previously did) can be handed to detection-engineering.

## Data sources required

- Exchange Online / M365 unified audit log for in-scope managed vendor tenants: `MailItemsAccessed`, `Send`, inbox-rule creation, unusual `ClientIP`/geo for mailbox access (the off-victim recon, where visible).
- Our email security gateway: inbound mail from trusted-partner domains whose content quotes internal process/project language or drives a credential/action.
- Identity provider sign-in logs (Entra ID / on-prem): vendor/partner account logons — new device, new geo, atypical MFA, impossible travel.
- VDI/session telemetry (Citrix, VMware Horizon, AVD): process launches and child processes inside brokered vendor sessions (VDI-breakout corroborator).

## Query starting point

Platform: `KQL / Microsoft Sentinel (Entra ID + M365 audit)` — vendor-account access anomaly correlated with unusual mailbox reads

```kusto
let vendors = _GetWatchlist('third_party_accounts') | project UserPrincipalName, HomeGeo, KnownIPs=split(KnownIP, ";");
let signins = SigninLogs
    | where TimeGenerated > ago(30d)
    | join kind=inner vendors on UserPrincipalName
    | extend geoNew = tostring(LocationDetails.countryOrRegion) != HomeGeo
    | where geoNew or ResultType == 0 and IPAddress !in (KnownIPs)      // new geo / new source for a vendor identity
    | project loginTime=TimeGenerated, UserPrincipalName, IPAddress,
              geo=tostring(LocationDetails.countryOrRegion), DeviceDetail;
let mailboxRecon = OfficeActivity
    | where TimeGenerated > ago(30d)
    | where Operation in ("MailItemsAccessed","New-InboxRule","Set-InboxRule")
    | where UserId in (vendors | project UserPrincipalName)
    | summarize reads=count(), folders=dcount(tostring(Folders)), ips=make_set(ClientIP,10)
              by UserId, bin(TimeGenerated,1h)
    | where reads > 200 or folders > 15;                               // bulk inbox sweep, not normal reading
signins
| join kind=inner (mailboxRecon) on $left.UserPrincipalName == $right.UserId
| where abs(datetime_diff('hour', loginTime, TimeGenerated)) <= 12
| order by reads desc
```

## Triage guidance

- **Likely malicious:** a vendor/partner identity signing in from a new country/IP and then bulk-reading mailbox folders or creating hiding inbox rules; a trusted-partner inbound that quotes our internal password-reset or PO process verbatim before pushing a link; a vendor account entering a Citrix/VMware/AVD session and spawning `cmd`/`powershell`/`ssh`/a tunneler it has never launched (VDI-breakout).
- **Likely benign / expected:** vendors travel, use shared/rotating egress IPs, and legitimately read many mail items during support work; automated mailbox integrations (ticketing, journaling, e-discovery) generate high `MailItemsAccessed` volume — baseline each vendor identity and its integrations first. Cross-org email that references a shared project is normal for a real partner.
- **Pivot next:** confirm whether the vendor tenant itself is compromised (coordinate with the third party); if a VDI-breakout is suspected, hunt the brokered session's process tree and any resulting internal RDP/WinRM fan-out (detection-pack T1021.001/T1021.006) and Azure C2 (HUNT-01). A confirmed attacker-in-vendor-identity reaching our network is a live trusted-relationship compromise — escalate to incident-response-coordinator, constrain/step-up the vendor's access, and notify the partner.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/analysis-of-unc1549-ttps-targeting-aerospace-defense
- https://attack.mitre.org/techniques/T1590/005/
- https://attack.mitre.org/techniques/T1199/
