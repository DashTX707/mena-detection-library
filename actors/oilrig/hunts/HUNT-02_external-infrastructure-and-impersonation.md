# Hunt: OilRig external infrastructure — fake portals, compromised servers/accounts & staged payloads

- **Hypothesis:** If OilRig is preparing or running an operation against us, then off-endpoint preparation — fake VPN/conference/job-application portals on lookalike domains, compromised third-party servers repurposed as C2, adversary-created M365/cloud mail accounts, compromised sender accounts, and malware staged on decoy sites — will leave traces in our email gateway, proxy, DNS and external attack-surface / passive-DNS feeds around the time of endpoint compromise. This is an intel-led enrichment hunt, not an endpoint sweep.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development)
  - T1586.002 — Compromise Accounts: Email Accounts (resource-development)
  - T1584.004 — Compromise Infrastructure: Server (resource-development)
  - T1585.003 — Establish Accounts: Cloud Accounts (resource-development)
  - T1608.001 — Stage Capabilities: Upload Malware (resource-development)
- **Actor procedure:** OilRig **sets up fake VPN portals, conference sign-ups and job-application websites**, **compromised an Israeli HR site to use as a C2 server**, **created M365 email accounts to serve as C2** (Earth Simnavaz), **compromised legitimate email accounts to send phishing**, and **hosts malware on fake websites** designed for specific target audiences.
- **Why a hunt, not a rule:** almost none of this is endpoint-observable — it lives on adversary and third-party infrastructure. Detection requires correlating external threat intel (registrations, passive DNS, lookalike feeds) with our own email/proxy telemetry plus human judgement about brand-spoofing, HR/job-portal lures and C2 repurposing of otherwise-legitimate sites. That is analyst-driven enrichment, not deterministic alerting.

## Data sources required

- Email security gateway logs (sender domain, display name, SPF/DKIM/DMARC results, first-seen sender)
- Proxy / DNS logs (access to newly-registered/lookalike VPN/job/conference domains and to unfamiliar M365 tenant senders)
- External attack-surface / passive-DNS / newly-registered-domain & lookalike-domain intel feeds
- CTI platform (this pack + G0049 infrastructure reporting)

## Query starting point

Platform: `Splunk SPL`

```
(index=proxy OR index=dns OR index=email)
| eval dom=lower(coalesce(url_domain, query, sender_domain, dest_host))
| eval lure=if(match(dom,"(vpn|portal|careers?|jobs?|apply|recruit|conference|summit|signup|login|owa|webmail)"),1,0)
| eval brandspoof=if(match(dom,"(microsoft|office365|onedrive|outlook|citrix|fortinet|pulse|globalprotect)") AND NOT match(dom,"(microsoft|office|live|citrix|fortinet)\.com$"),1,0)
| where lure=1 OR brandspoof=1
| stats count values(index) as seen_in values(src_ip) as src min(_time) as first max(_time) as last by dom, lure, brandspoof
| join type=left dom [| inputlookup newly_registered_domains]
| sort first
```

## Triage guidance

- **Likely malicious:** email or web access to a VPN/careers/conference lookalike domain registered within ~90 days; a first-time external M365 tenant sender that immediately solicits credentials; passive-DNS overlap with known OilRig infrastructure; a previously-legitimate third-party site suddenly serving executables or receiving beacon-shaped traffic (repurposed C2).
- **Likely benign / expected:** genuine corporate recruiting/conference vendors and legitimate M365 partner tenants (enumerate and allowlist); long-established brand-adjacent domains that are actually first-party; marketing senders using Microsoft branding legitimately.
- **Pivot next:** any user who transacted with flagged infrastructure → endpoint review (HUNT-03/HUNT-09); confirmed domains/senders → detection-engineer as IOC blocks + email-gateway rules; share compromised-server and cloud-C2 indicators with IR/intel.

## References

- https://attack.mitre.org/groups/G0049/
- https://www.trendmicro.com/en_us/research/24/j/earth-simnavaz-cyberattacks.html
