# Hunt: HEXANE persona & account establishment/compromise and tooling acquisition

- **Hypothesis:** If HEXANE is running a Siamesekitten-style social-engineering operation against us, then the operator-side scaffolding should be discoverable off-victim — fake LinkedIn/social personas impersonating an HR or recruitment firm, attacker-registered sender email accounts fronting those personas, *compromised* legitimate third-party mailboxes used to lend trust, and the acquisition of offensive tooling staged for downstream use. The finding is a persona + sender-account + (optionally) a trusted-but-anomalous third-party sender all pointing at the same lure narrative and infrastructure, not a lone unfamiliar recruiter.
- **ATT&CK:**
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development)
  - T1585.002 — Establish Accounts: Email Accounts (resource-development)
  - T1586.002 — Compromise Accounts: Email Accounts (resource-development)
  - T1588.002 — Obtain Capabilities: Tool (resource-development)

- **Actor procedure:** HEXANE created fake LinkedIn personas impersonating HR/recruitment staff of a legitimate company to approach targeted employees, established attacker email accounts to support the phishing, and compromised legitimate third-party email accounts to send from trusted senders. Alongside its custom implants (DanBot, Milan) it obtained additional tooling — password-spraying scripts, credential harvesters — to support operations.
- **Why a hunt, not a rule:** Persona creation, attacker-mailbox registration and tool acquisition all happen on platforms and infrastructure outside our control — LinkedIn, third-party mail providers, criminal markets — so there is no endpoint or SIEM event to alert on. The signals that reach us (a first-contact from an unfamiliar sender, a recruiter profile, a message from a real-but-out-of-pattern partner) are individually indistinguishable from legitimate business. Fusing brand-monitoring persona alerts with mail-sender anomalies and threat intel into "this is a HEXANE persona set" is analyst judgement, not a precise selector — a hunt that feeds takedowns and mail blocklists.

## Data sources required

- Brand/persona monitoring feed (LinkedIn & social impersonation of us or a staffing firm)
- Mail-gateway sender telemetry — first-seen sender domains, newly-registered sender domains, auth (SPF/DKIM/DMARC) results
- Trusted-partner mail baseline — known-good third-party senders and their normal patterns (to spot compromise: new geo, new client, anomalous send burst)
- Threat intel on HEXANE personas/tooling; underground/tool-acquisition reporting
- User-reported phishing / recruiter-contact submissions

## Query starting point

Platform: `KQL / Microsoft Sentinel` — trusted third-party sender behaving anomalously (compromise) + first-seen persona domains

```kusto
// (a) Compromised trusted third-party mailbox: a known-good partner domain suddenly sending from new IP/geo with lure themes
let trusted = _GetWatchlist("trusted_partner_senders") | project SenderFromDomain = Domain;
EmailEvents
| where TimeGenerated > ago(30d)
| join kind=inner trusted on SenderFromDomain
| summarize msgs = count(), newIPs = dcount(SenderIPv4), ipset = make_set(SenderIPv4, 15),
           subjects = make_set(Subject, 20) by SenderFromDomain
| where newIPs >= 2                                   // partner sending from unusual infrastructure
| order by msgs desc

// (b) First-seen recruiter/HR-themed sender domains registered in the last 60d hitting priority roles
// EmailEvents | where Subject has_any ("opportunity","position","vacancy","CV","resume","recruit")
//   and SenderFromDomain !in (known_senders_90d) and domain_age_days < 60
```

## Triage guidance

- **Likely malicious:** a LinkedIn/social persona impersonating our brand or a staffing firm whose contact email uses a newly-registered lookalike domain; a real trusted-partner mailbox suddenly sending recruitment-themed lures from a new country/ASN (account compromise); sender infrastructure overlapping HUNT-02 domains; tooling (password-spray kits, credential harvesters) attributed to HEXANE surfacing in intel targeting our sector.
- **Likely benign / expected:** genuine new recruiters, vendors and partners onboard constantly; a first-seen sender or a partner emailing from a mobile/travel IP is routine. Baseline sanctioned staffing vendors and known partner sending infrastructure; require a lure narrative + infra overlap before flagging.
- **Pivot next:** confirmed persona/account set → report for platform takedown, blocklist sender domains, and warn the contacted roles (feeds HUNT-01). A compromised trusted-partner mailbox actively phishing us is an active-delivery event → hand the sender/domain to the phishing detection lane and, if any recipient interacted, escalate to IR.

## References

- https://www.clearskysec.com/siamesekitten/
- https://attack.mitre.org/groups/G1001/
- https://attack.mitre.org/techniques/T1585/001/
- https://attack.mitre.org/techniques/T1585/002/
- https://attack.mitre.org/techniques/T1586/002/
- https://attack.mitre.org/techniques/T1588/002/
