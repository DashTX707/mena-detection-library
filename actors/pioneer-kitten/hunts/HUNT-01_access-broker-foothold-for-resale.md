# Hunt: Pioneer Kitten access-broker foothold being staged for resale (FLAGSHIP)

- **Hypothesis:** If Pioneer Kitten has already brokered — or is preparing to broker — access to our network, then the on-victim tell is not the ransomware (that comes later, from an affiliate) but a *quiet resale-staging pattern*: a durable foothold on an internet-facing edge appliance (NetScaler/Ivanti/PAN-OS/F5), credential material harvested into files and read/collected in bulk, and long-dwell low-touch persistence — with the *external* corroborator being one of our domains, IP ranges, or "domain admin @ <us>" access lots appearing for sale on an initial-access-broker forum or in ransomware-affiliate chatter. The hunt correlates the internal harvest/persistence signal with off-victim access-sale intel; either half alone is thin, the pair is the finding.
- **ATT&CK:**
  - T1657 — Financial Theft (impact) — access-brokering / ransom-share collaboration with NoEscape, RansomHouse, ALPHV/BlackCat; sale of domain-admin access on marketplaces
  - T1552.001 — Unsecured Credentials: Credentials In Files (credential-access) — bulk reading of credential-bearing files that feed the salable "full domain control" package

- **Actor procedure:** The FBI assesses a significant share of Pioneer Kitten's (Br0k3r / xplfinder) US activity is a for-profit initial-access-broker operation: they exploit an edge appliance, deploy a webshell that appends captured logons to `netscaler.1`, harvest and repurpose admin credentials to reach domain controllers, establish redundant persistence, then **sell full-domain-control / domain-admin access on cyber marketplaces** and hand off to a ransomware affiliate for a percentage of the ransom. The salable asset is a bundle of working credentials + a reliable re-entry path, assembled quietly and held (sometimes for months) until a buyer is found.
- **Why a hunt, not a rule:** The financial-theft / access-brokering act itself (T1657) happens off-victim on forums and messaging apps and is not endpoint-observable — there is nothing to alert on. What *is* on-victim (credential-file reads, a dormant edge foothold, DC access from an appliance-sourced credential) is individually low-fidelity and blends with administration, so a standalone rule would drown in false positives. The finding only exists in the **correlation** of an internal harvest/dwell signal with an *external* threat-intel hit naming our org's access for sale — that fusion and judgement is hunt work. If a specific durable internal observable falls out (e.g., a DC logon by an identity whose credential was first seen captured on an edge appliance — a Level-4 relational observable), hand that to detection-engineering as a scoped analytic; do not try to alert on "someone sold our access."

## Data sources required

- External / dark-web intel feed: initial-access-broker forum listings, ransomware-affiliate chatter, "domain admin access for sale" brokers keyed to our domains / ASN / brand (the off-victim half)
- Edge-appliance file-integrity + access telemetry (NetScaler/Ivanti/PAN-OS/F5): credential-capture files (`netscaler.1`), webshell dwell, long-lived unexpected re-entry
- Identity/auth analytics: DC and privileged-app logons whose source credential was first observed on an edge appliance; long-dwell service/local accounts (cross-ref HUNT-05, detection pack T1136.001/T1078)
- File-access auditing (4663) / EDR file-read telemetry on credential-bearing files (`.kdbx`, `unattend.xml`, `web.config`, `*.ovpn`, exported hives)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — fuse external access-sale intel with internal bulk credential-file reads on the same asset

```kusto
// (a) External IAB / affiliate intel naming our estate (ingested as a watchlist/TI table)
let brokered = ThreatIntelIndicator
    | where Description has_any ("domain admin","full domain control","access for sale","IAB","initial access")
    | where DomainName in (_GetWatchlist('our_domains')) or NetworkSourceIP in (_GetWatchlist('our_asn'))
    | project brokeredTime = TimeGenerated, DomainName, NetworkSourceIP, Description;
// (b) Internal bulk credential-file reads clustered on one host/account (resale-package assembly)
let credHarvest = DeviceFileEvents
    | where TimeGenerated > ago(45d)
    | where ActionType == "FileAccessed"
    | where FileName has_any (".kdbx","unattend.xml","web.config",".ovpn","password","credential",".pfx","ntds.dit")
    | summarize files = dcount(FolderPath), fileset = make_set(FileName, 20),
                first = min(TimeGenerated), last = max(TimeGenerated)
             by DeviceName, InitiatingProcessAccountName
    | where files >= 5;                      // bulk read = package assembly, not one lookup
credHarvest
| join kind=leftouter (brokered) on $left.DeviceName == $right.DomainName
// Prioritise hosts/accounts that ALSO carry an edge-appliance foothold or an external for-sale hit
| order by files desc
```

## Triage guidance

- **Likely malicious:** an external intel hit offering "domain admin / full domain control" of *our* domain or ASN that time-correlates with an internal edge foothold + bulk credential-file harvest; a DC or Citrix XenDesktop logon using a credential that was first captured on a NetScaler `netscaler.1` file; a dormant local/service account (e.g. `sqladmin$`, `adfsservice`) created weeks ago now brokering re-entry; long-dwell persistence with near-zero interactive activity punctuated by a single credential-collection burst.
- **Likely benign / expected:** password-manager and IaC repos legitimately hold credential files that admins and backup jobs read on a cadence — baseline the readers; vulnerability scanners and DLP tools touch `web.config`/`unattend.xml` broadly; brand-monitoring false positives where a broker lists a look-alike domain, not ours. A single credential-file read by a known admin is expected; a bulk read fanning across shares by a non-admin identity, or one corroborated by an external for-sale listing, is not.
- **Pivot next:** if the external listing corroborates an internal foothold, treat as an active brokered compromise heading toward ransomware detonation — this is a live incident, escalate to incident-response-coordinator immediately, force-rotate all credentials reachable from the harvested set, hunt the edge foothold (detection pack T1190/T1505.003) and the persistence (T1053.005/T1574.001), and pre-position for affiliate ransomware (cross-actor ransomware playbook). Preserve the forum listing as attribution intel.

## References

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a
- https://attack.mitre.org/groups/G0117/
- https://attack.mitre.org/techniques/T1657/
- https://attack.mitre.org/techniques/T1552/001/
