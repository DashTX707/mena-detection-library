# Hunt: Off-victim leak personas & acquired C2 infrastructure (Karma / Homeland Justice)

- **Hypothesis:** If Void Manticore has compromised us (or is preparing to), the earliest externally-observable signals live *off* our host telemetry: (a) a hack-and-leak persona — "Karma"/"KarMa" (Telegram + Karmabelow80), "Homeland Justice" — publishing or teasing our stolen data on a leak channel, and (b) newly-acquired attacker infrastructure making inbound connections to our internet-facing servers from an ASN/geo cluster distinct from Scarred Manticore's espionage infrastructure. This is an intelligence + inbound-anomaly hunt: brand/leak-site monitoring for our org name and data, correlated with never-before-seen inbound source ASNs on the same edge servers that carry SharePoint/web-shell exposure.
- **ATT&CK:**
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development) — Karma/Homeland Justice personas on Telegram and leak sites amplifying destruction
  - T1583 — Acquire Infrastructure (resource-development) — external C2 (reached over SSH/443) and leak websites (Karmabelow80); a distinct post-handoff attacker-IP set begins hitting the victim

- **Actor procedure:** Void Manticore operates influence personas ("Anti-Zionist Jewish Hackers" front) to leak exfiltrated data and magnify the psychological impact of wiping. It stands up its own C2 and leak infrastructure; after the Scarred-Manticore handoff a *separate* set of attacker IPs (report appendix: 64.176.169.22, 64.176.172.235/165/101, 64.176.173.77) begins accessing the victim network, distinct from the espionage partner's infrastructure.
- **Why a hunt, not a rule:** Persona/infrastructure standup is off-victim and invisible to host logs — there is no event to alert on, so this is inherently investigative (brand-monitoring + threat-intel pivoting). The inbound-ASN half *could* alert, but raw "new source ASN on the edge" is far too noisy for a standalone rule on an internet-facing server; the value is analyst correlation of a never-before-seen inbound cluster with a leak-site mention of our name and with edge exposure (SharePoint CVE-2019-0604 / web shell). Static IPs are Level-1 (the adversary rotates them freely) — use the appendix IPs only as retro-hunt pivots, and anchor the forward hunt on the *relationship* (new ASN → our exposed edge host) rather than the addresses.

## Data sources required

- External brand / leak-site & Telegram monitoring for the org name, brands, and sample stolen-data identifiers (Karma / KarMa / Homeland Justice / Karmabelow80 channels)
- Edge firewall / web-proxy / IIS access logs (inbound source IP, ASN, geo) for internet-facing servers — with a per-server historical source-ASN baseline
- Threat-intel enrichment (ASN, geo, passive DNS, hosting reputation) for inbound source IPs
- Retro-hunt list of report IOC IPs (pivots only, not the basis of the hunt)

## Query starting point

Platform: `KQL / Microsoft Sentinel` — never-before-seen inbound source ASN on an internet-facing server, plus IOC-IP retro pivot

```kusto
// Baseline: source ASNs each edge server has legitimately received over 60d
let known_edge_asn =
    CommonSecurityLog
    | where TimeGenerated between (ago(60d) .. ago(2d))
    | where DeviceVendor == "edge-fw" and Direction == "inbound"
    | extend asn = tostring(parse_json(AdditionalExtensions).SourceASN)
    | summarize by DestinationIP, asn;
let void_ips = dynamic(["64.176.169.22","64.176.172.235","64.176.172.165","64.176.173.77","64.176.172.101"]);
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where Direction == "inbound"
| extend asn = tostring(parse_json(AdditionalExtensions).SourceASN),
         geo = tostring(parse_json(AdditionalExtensions).SourceGeoCountry)
| where DestinationIP in (
        // scope to internet-facing web / SharePoint servers (edge asset list)
        toscalar(_GetWatchlist("EdgeWebServers") | summarize make_set(SearchKey)))
| summarize firstSeen = min(TimeGenerated), hits = count(),
            ports = make_set(DestinationPort, 10), srcIps = make_set(SourceIP, 25)
        by DestinationIP, asn, geo
| join kind=leftanti (known_edge_asn) on DestinationIP, asn      // never-before-seen ASN on THIS server
| extend iocHit = set_has_element(void_ips, tostring(srcIps))    // retro pivot on appendix IPs
| order by firstSeen asc
```

## Triage guidance

- **Likely malicious:** our org name or recognizably-ours data appearing on a Karma/Homeland-Justice-style leak channel or Telegram post; a never-before-seen inbound ASN establishing sustained sessions to an internet-facing SharePoint/web server that also shows web-shell or CVE-2019-0604 indicators; any inbound match to the report's appendix IPs; a distinct new attacker-IP cluster arriving *after* signs of prior long-dwell espionage. Leak-site exposure of our data is confirmation the destructive phase is imminent or underway.
- **Likely benign / expected:** new inbound ASNs from CDNs, cloud providers, search-engine crawlers, uptime monitors, or a newly-onboarded partner/VPN egress; a leak-site name-collision with a similarly-named unrelated entity. Enrich the ASN and validate the mention refers to us before escalating.
- **Pivot next:** if a leak mention or hostile inbound cluster confirms, pivot on-host to the edge web server for web shells (HUNT-03), web-shell-parented recon (HUNT-05), and the reverse-SOCKS/RDP tunnel, then to the handoff/destruction chain (HUNT-01). A confirmed leak of our data → notify incident-response-coordinator and legal/comms; treat as active breach + impending destruction.

## References

- https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/
- https://socradar.io/blog/dark-web-profile-storm-842-void-manticore/
- https://attack.mitre.org/techniques/T1585/001/
- https://attack.mitre.org/techniques/T1583/
