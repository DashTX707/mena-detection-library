# Hunt: HEXANE off-victim identity & role reconnaissance (recruitment-lure targeting)

- **Hypothesis:** If HEXANE is preparing a Siamesekitten-style recruitment lure against us, then *before* any payload lands we should see the off-victim footprint of its target-list building — external OSINT harvesting of employee names, corporate email addresses and specifically IT/communications/HR role-holders — surfacing as (a) reconnaissance hits against our public identity surface (careers pages, `mail`/OWA login portals, email-format enumeration/SMTP RCPT probing, LinkedIn scraping of our staff) and (b) a subsequent burst of inbound social-engineering contact concentrated on the exact roles HEXANE prioritizes. No single scrape is evidence; the finding is role-selectivity + a matching contact wave.
- **ATT&CK:**
  - T1589 — Gather Victim Identity Information (reconnaissance)
  - T1589.002 — Gather Victim Identity Information: Email Addresses (reconnaissance)
  - T1591.004 — Gather Victim Org Information: Identify Roles (reconnaissance)

- **Actor procedure:** In the ClearSky-documented Siamesekitten campaign HEXANE profiled employees in IT and communications roles at Israeli organizations, harvested their identities and email addresses, then approached them through fake HR/recruitment personas with tailored job offers. The reconnaissance is deliberately off-victim (LinkedIn, public sites, email-format guessing) so it precedes and predicts the intrusion rather than being part of it.
- **Why a hunt, not a rule:** The load-bearing evidence lives outside our telemetry — LinkedIn views, third-party scraping, off-victim email harvesting leave little or nothing in our logs, and what we can see (bot hits on the careers page, SMTP RCPT-TO enumeration, a spike in InMail/recruiter contact) has an enormous benign base rate from real recruiters, marketing tools and search crawlers. There is no precise, low-false-positive observable to alert on; the value is an analyst correlating a *role-selective* pattern (only IT/comms/OT staff) against threat intel on active HEXANE personas. This is intel-fused hunting, not detectable signature logic.

## Data sources required

- External web/CDN/WAF logs for careers & OWA/mail portals (scraping cadence, user-agent, ASN/geo — flag Iran-nexus/VPS ASNs)
- Mail gateway SMTP logs — RCPT-TO enumeration / high invalid-recipient ratio from single sources
- Brand-/attack-surface-monitoring feed (LinkedIn persona alerts, employee-data-for-sale, credential-dump mentions)
- HR / recruiting-inbox reports of unsolicited recruiter contact (role, sender domain, persona)
- Threat-intel on active HEXANE/Siamesekitten personas & lure domains (ties to HUNT-02/03)

## Query starting point

Platform: `KQL / Microsoft Sentinel` — SMTP recipient-enumeration burst correlated to IT/comms role holders

```kusto
// Mail-gateway RCPT enumeration: one source probing many of our addresses, high invalid-recipient ratio
let window = 7d;
EmailEvents
| where TimeGenerated > ago(window)
| where DeliveryAction in ("Blocked","Junked") or RecipientEmailAddress == "" 
| summarize probed = dcount(RecipientEmailAddress),
           invalidRatio = countif(isempty(RecipientEmailAddress)) * 1.0 / count(),
           roles = make_set(RecipientEmailAddress, 50)
    by SenderIPv4, SenderFromDomain
| where probed >= 20 and invalidRatio > 0.4          // enumeration shape, not normal mail
| order by probed desc
// Pivot: intersect 'roles' hit against the IT/comms/OT distribution list (HEXANE's priority roles).
// Selectivity toward those roles + a matching recruiter-contact wave = finding, not the raw probe.
```

## Triage guidance

- **Likely malicious:** email-format/RCPT enumeration from a VPS/Iran-nexus ASN followed within days by recruiter-persona contact to the *same* IT/communications/OT individuals; careers-page scraping from the same infrastructure that later serves a lure domain (correlate with HUNT-02); persona contact whose domain is a newly-registered lookalike of a real staffing firm.
- **Likely benign / expected:** legitimate recruiters, marketing-automation and SEO/search crawlers hit careers pages and enumerate addresses constantly; a single unsolicited InMail to one employee is normal noise. Baseline known recruiting vendors and crawler ASNs and suppress them.
- **Pivot next:** if role-selective recon + a persona wave is confirmed, pivot to HUNT-03 (persona/account infrastructure) and HUNT-02 (lure/C2 domains) to characterize the operation, and pre-brief the targeted roles. If a lure has already been clicked, this has moved past recon — hand the delivery domain to the phishing detection lane and escalate.

## References

- https://www.clearskysec.com/siamesekitten/
- https://attack.mitre.org/groups/G1001/
- https://attack.mitre.org/techniques/T1589/
- https://attack.mitre.org/techniques/T1589/002/
- https://attack.mitre.org/techniques/T1591/004/
