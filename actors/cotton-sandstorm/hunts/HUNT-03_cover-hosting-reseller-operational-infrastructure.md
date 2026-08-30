# Hunt: Cotton Sandstorm cover-hosting resellers & operational infrastructure acquisition

- **Hypothesis:** If ASA is provisioning infrastructure to stage an operation against us or our region, then its acquisition footprint should be discoverable through attribution pivots — persona/operational domains registered through fictitious cover-hosting reseller storefronts (Server-Speed, VPS-Agent) upstreamed from a small set of providers (BAcloud, Stark Industries / PQ Hosting), commercial-VPN exit nodes used for anonymized access, and abused web/cloud SaaS (generative-AI services, cover-reseller storefronts) — clustered by shared registrant, hosting, TLS and reseller lineage rather than any single indicator.
- **ATT&CK:**
  - T1583 — Acquire Infrastructure (resource-development)
  - T1583.001 — Acquire Infrastructure: Domains (resource-development)
  - T1583.006 — Acquire Infrastructure: Web Services (resource-development)

- **Actor procedure:** ASA anonymizes operations through commercial VPNs (Private Internet Access, Windscribe, ExpressVPN, Urban VPN, NordVPN) and procures servers via its *own* fictitious cover-hosting resellers "Server-Speed" (`server-speed[.]com`, ~Apr 2023–May 2024) and "VPS-Agent" (`vps-agent[.]net`, ~May 2024 onward), themselves upstreamed from BAcloud (Lithuania) and Stark Industries Solutions / PQ Hosting (UK/Moldova) — providing plausible deniability that malicious infrastructure came from a legitimate provider (T1583/T1583.006). It registers persona and operational domains for influence and C2 — `cybercourt[.]io`, `zeusistalking[.]io/net/com`, `rgud-group[.]net/com`, `pro-today[.]org`, `cyberflood[.]io`, `onlinelive[.]info`, `Contact-hstg[.]com`, and `il-cert[.]net` (RAT C2) (T1583.001). It also abuses generative-AI SaaS (Remini, Voicemod, Murf AI, Appy Pie) to produce influence content (T1583.006). The advisory warns VPN nodes are shared and are NOT exclusive indicators.
- **Why a hunt, not a rule:** Domain registration, VPS acquisition and SaaS sign-up all happen off-victim on attacker/third-party infrastructure — nothing in your telemetry fires. Worse, the advisory explicitly flags the VPN exit nodes as shared commercial infrastructure, so blind-blocking them causes collateral damage and single-indicator attribution is unsafe. This is an attribution/clustering hunt: pivot from a seed domain or reseller to co-registered and co-hosted infrastructure (shared registrant emails like `info@vps-agent[.]net`, common upstream ASN, TLS-cert and registrar patterns, reseller lineage) to pre-empt future domains — human-driven graph analysis, not an alert. Any confirmed operational domain becomes an IOC for the C2/exfil detection packs, but the *discovery* method is a hunt.

## Data sources required

- Passive DNS, WHOIS/RDAP history and certificate-transparency logs (registrant, registrar, TLS-cert clustering)
- Newly-registered / lookalike-domain feeds (persona and operational domains)
- Hosting/ASN reputation data (BAcloud, Stark Industries / PQ Hosting upstreams; reseller storefront pivots)
- Commercial-VPN exit-node lists (for *retrospective* correlation of inbound access, not blind blocking)
- Threat-intel infrastructure feeds (known ASA domains/IPs from AA24-233A as pivot seeds)

## Query starting point

Platform: `Passive-DNS / WHOIS pivoting + Splunk SPL for retrospective VPN-access correlation`

```
# (a) T1583.001/.006 — pivot from a seed to co-registered/co-hosted infrastructure (RDAP/pDNS tooling)
#   seed domains: server-speed.com, vps-agent.net, onlinelive.info, il-cert.net, cybercourt.io
#   pivots: shared registrant email (info@vps-agent.net), same registrar+creation-window,
#           same upstream ASN (BAcloud / Stark Industries / PQ Hosting), reused TLS cert SANs
#   OUTPUT: candidate not-yet-public ASA domains sharing >=2 pivots -> promote to IOC watchlist
```

```
# (b) T1583 — retrospective: successful auth to sensitive/admin services from commercial-VPN ASNs
index=auth (action=success)
| iplocation src_ip
| lookup commercial_vpn_asn.csv asn OUTPUT vpn_provider
| where isnotnull(vpn_provider) AND (app IN ("admin","cms","streaming","vpn","owa"))
| stats count values(vpn_provider) AS vpn dc(src_ip) AS ips by user app
| where count > 0    // correlate, do NOT auto-block (shared nodes) — feed to identity hunt
```

## Triage guidance

- **Likely malicious:** a freshly-registered domain sharing registrant email, registrar/creation-window, upstream ASN or TLS SANs with known ASA seeds (server-speed/vps-agent/onlinelive/il-cert); a cover-reseller storefront whose only real customers are a handful of thin operational sites; admin/CMS/streaming logins from a commercial-VPN node coinciding with other ASA activity against the same asset.
- **Likely benign / expected:** legitimate small hosts on BAcloud/Stark/PQ (these are real bulletproof-adjacent but also host benign tenants — presence alone is not proof); employees/vendors on commercial VPNs for legitimate reasons; SaaS sign-ups by real users. Never attribute on a shared VPN node or shared upstream ASN alone — require stacked pivots.
- **Pivot next:** promote any multi-pivot candidate domain to the C2/exfil detection watchlists (detection pack T1071.001 / T1567) and to HUNT-04 (is it staging a payload?) and HUNT-07 (is it a leak-staging server?). Feed persona domains back to HUNT-02. If a VPN-node login is corroborated by other stacked signals, treat the account as at-risk and pivot to the valid-accounts detection surface.

## References

- https://www.ic3.gov/CSA/2024/241030.pdf
- https://attack.mitre.org/techniques/T1583/
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1583/006/
