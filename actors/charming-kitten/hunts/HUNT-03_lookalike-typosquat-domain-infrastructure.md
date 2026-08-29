# Hunt: Charming Kitten lookalike / typo-squatted domain infrastructure

- **Hypothesis:** If Charming Kitten is staging a credential-harvesting campaign against us or our brand, then in newly-registered-domain, passive-DNS and certificate-transparency feeds we should observe its signature naming pattern — multi-word hyphen-separated lookalike domains on `.top/.online/.site/.live/.buzz` (and compromised legitimate domains repurposed as redirectors) that spoof our brand or the Google/Microsoft login services our users trust — resolving on shared hosting and fronted by Cloudflare, before or during phishing.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development)
  - T1584.001 — Compromise Infrastructure: Domains (resource-development)

- **Actor procedure:** APT42 registers large numbers of typo-squatted / lookalike domains — several hyphen-separated words on `.top`, `.online`, `.site`, `.live`, `.buzz` — to host fake login pages, redirects and staging. Observed: `ksview[.]top` → `honest-halcyon-fresher[.]buzz`; `review[.]modification-check[.]online` (behind the `n9[.]cl` shortener); `nterview[.]site` → `admin-stable-right[.]top`; `shortlinkview[.]live` → `panel-view[.]live`; `drive-file-share[.]site`; `panel-live-check[.]online`. It also compromises and repurposes existing legitimate domains as redirectors, and fronts infrastructure with Cloudflare to obscure hosting. Chains are multi-hop and short-lived.
- **Why a hunt, not a rule:** These domains are registered off-victim and rotate constantly — any static blocklist is stale within days, so this is a Level-1 IOC space best used as *pivots*, not alert seeds. The durable signal is the *naming grammar and TLD/registrar/hosting cluster*, which has a real false-positive rate (plenty of benign multi-word `.online`/`.site` domains exist). A hunt fuzzy-matches NRD/CT feeds against our brand and the login-service brands our users see, then clusters candidates by registrar/nameserver/hosting to raise confidence — human-judged, not a firing rule. Confirmed clusters become blocklist entries and are handed to detection-engineering for perimeter URL/DNS rules.

## Data sources required

- Newly-registered-domain (NRD) feed + WHOIS/RDAP (registrar, creation date, nameservers)
- Passive DNS (resolution history, shared-IP/hosting pivots)
- Certificate Transparency logs (new certs for brand-lookalike / service-lookalike SANs)
- Proxy / DNS resolver logs (did any internal host actually resolve/visit a candidate?)
- Threat-intel domain feeds and prior CK infrastructure clusters

## Query starting point

Platform: `Splunk SPL` (NRD + CT ingested as lookups) — surface fresh lookalike candidates on CK's preferred TLDs, then confirm any that our users touched

```
| inputlookup nrd_feed.csv
| where match(domain, "\.(top|online|site|live|buzz)$")
| eval hyphens=mvcount(split(domain,"-"))-1
| where hyphens>=2
   OR like(domain,"%drive%") OR like(domain,"%onedrive%") OR like(domain,"%share%")
   OR like(domain,"%login%") OR like(domain,"%panel%") OR like(domain,"%view%")
   OR like(domain,"%mail%") OR like(domain,"%meet%") OR like(domain,"%account%")
   OR like(domain,"%<brandtoken>%")
| where creation_age_days<45
| stats values(domain) AS domains count by registrar nameserver hosting_asn
| where count>=2                         /* cluster: same registrar/NS/ASN = higher confidence */
| join type=left domain
    [ search index=proxy OR index=dns earliest=-45d
      | stats count AS internal_hits values(src_ip) AS hosts by domain ]
| sort - internal_hits - count
```

## Triage guidance

- **Likely malicious:** multi-word hyphenated `.top/.online/.site/.live/.buzz` domain spoofing our brand or a login service (Google/Drive/OneDrive/M365/LinkedIn), registered <45 days, clustered with siblings on the same registrar/nameserver/ASN, Cloudflare-fronted, resolving to a fake login page; any such domain an internal host actually resolved or visited.
- **Likely benign / expected:** legitimate businesses on cheap TLDs; our own marketing microsites and partner domains; parked/for-sale domains with no login content. Confirm content by (safe, sandboxed) retrieval before calling it — many multi-word `.online` domains are innocuous.
- **Pivot next:** for a confirmed lookalike, pivot passive-DNS for co-hosted siblings and the redirect chain (shortener → lure → fake login) and check SEG for inbound mail carrying the URL; pivot to HUNT-01/02 for who was targeted. Confirmed, stable infrastructure is a repeatable, precise observable → hand the domain/URL patterns to detection-engineering for perimeter DNS/proxy/SEG blocking (Summiting Level 1–2 IOC, use as pivots + short-lived blocks, not the basis of behavioral detection).

## References

- https://cloud.google.com/blog/topics/threat-intelligence/untangling-iran-apt42-operations
- https://attack.mitre.org/groups/G0059
