# Hunt: MuddyWater external infrastructure & resource-development tracking

- **Hypothesis:** If MuddyWater is preparing or running an operation against us, then off-endpoint preparation — lookalike/spoofed domains, adversary-controlled file-sharing accounts, staged commodity tooling, and brand impersonation in email — will leave traces in our email gateway, proxy, DNS and external attack-surface / passive-DNS feeds *before or during* endpoint compromise. This is an intel-led enrichment hunt, not an endpoint sweep.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development)
  - T1583.006 — Acquire Infrastructure: Web Services (resource-development)
  - T1588.001 — Obtain Capabilities: Malware (resource-development)
  - T1588.002 — Obtain Capabilities: Tool (resource-development)
  - T1590.004 — Gather Victim Network Information: Network Topology (reconnaissance)
  - T1684.001 — Social Engineering for Impact: Impersonation (resource-development)
- **Actor procedure:** MuddyWater registers domains that **spoof legitimate brands** (e.g. `microsoftonlines[.]com`), uses file-sharing services **OneHub, Sync, and TeraBox** to distribute tooling, adopts **publicly available malware** and **legitimate tools (ConnectWise, RemoteUtilities, SimpleHelp)** to blend in, **maps target networks** and brokers that access to other Iran-nexus actors, and **impersonates** Microsoft security updates (`support@microsoftonlines[.]com`) and TMCell/Altyn Asyr in lures.
- **Why a hunt, not a rule:** Almost none of this is endpoint-observable — it happens on adversary and third-party infrastructure. Detection requires correlating external threat-intel (registrations, passive DNS, lookalike-domain feeds) with our own email/proxy telemetry and human judgement about brand-spoofing and access-brokering. That is analyst-driven enrichment, not deterministic alerting.

## Data sources required

- Email security gateway logs (sender domain, display-name/brand, auth results)
- Proxy / DNS logs (access to `onehub.com`, `sync.com`, `terabox.com` and to newly-registered/lookalike domains)
- External attack-surface / passive-DNS / newly-registered-domain and lookalike-domain intel feeds
- CTI platform (this pack's IOCs + G0069 infrastructure reporting)

## Query starting point

Platform: `Splunk SPL`

```
(index=proxy OR index=dns OR index=email)
| eval dom=lower(coalesce(url_domain, query, sender_domain, dest_host))
| eval brandspoof=if(match(dom,"(microsoftonline|microsoft|office365|onedrive|outlook).*[^a-z](com|net)")
        AND NOT match(dom,"(microsoft\.com|microsoftonline\.com|office\.com|live\.com)$"),1,0)
| eval filesharing=if(match(dom,"(onehub|sync|terabox)\."),1,0)
| where brandspoof=1 OR filesharing=1
| stats count values(dom) as domains values(index) as seen_in
        values(src_ip) as src min(_time) as first by dom, brandspoof, filesharing
| sort first
```

## Triage guidance

- **Likely malicious:** Email from a Microsoft/brand lookalike domain registered within the last 90 days; user uploads/downloads to OneHub/Sync/TeraBox where no business relationship exists; a lookalike domain that resolves and receives clicks close in time to a phishing wave; passive-DNS overlap with known MuddyWater infrastructure.
- **Likely benign / expected:** Legitimate corporate use of Sync/TeraBox by specific teams (enumerate and allowlist); long-established, well-reputed lookalike-adjacent domains that are actually first-party; marketing/newsletter senders using Microsoft branding legitimately.
- **Pivot next:** Any user who transacted with flagged infrastructure → endpoint review (HUNT-01/HUNT-14); feed confirmed domains/senders to detection-engineer as IOC-based blocks and to email gateway; share network-topology-recon indicators with IR/intel for access-broker tracking.

## References

- https://attack.mitre.org/groups/G0069/
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a
