# Hunt: Dark Caracal — actor domain/infra & Bandook/CrossRAT/Pallas capability development (off-victim clustering)

- **Hypothesis:** If Dark Caracal (the Lebanon/GDGS mercenary cluster) is preparing or running an operation against us, then the earliest tell lives entirely off-victim: newly-registered C2/staging/external-template domains sharing the actor's registration habits (Porkbun / NameSilo, cheap disposable TLDs `.top/.live/.club/.icu/.monster/.info`), Bandook/CrossRAT samples that carry the lineage fingerprint (AES-CFB with the hardcoded IV `0123456789123456`, the `&&&&`-suffixed Base64 C2 wire format, shared command opcodes), and Certum-signed binaries appearing in certificate-transparency / signer-reputation feeds. No single one of these is a compromise; the finding is a *cluster* — a fresh domain on the actor's registrar+TLD pattern that also resolves near a Certum-signed sample exhibiting the AES-IV fingerprint. This is threat-intel and infrastructure work that pre-positions blocklists and watchlists *before* the phish lands, not an on-victim alert.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — passive-DNS / WHOIS pivoting on Porkbun+NameSilo registrations and disposable-TLD patterns to surface new actor C2 before it is used
  - T1587.001 — Develop Capabilities: Malware (resource-development) — sample clustering on the Bandook/CrossRAT/Pallas code-and-config reuse (AES-CFB IV, opcode set, build variants) to spot new builds pre-deployment
  - T1588.003 — Obtain Capabilities: Code Signing Certificates (resource-development) — certificate-transparency and signer-reputation tracking of the abused Certum signer to catch newly-signed Bandook samples

- **Actor procedure:** Dark Caracal registers C2 and external-template/staging domains through Porkbun and NameSilo on low-cost TLDs; both the 2018 operation and the 2020 Bandook resurgence share these registrars, and Check Point tied the resurgence to the original cluster partly through this infrastructure continuity. The operators maintain and evolve Bandook across builds (a ~120-command full build, a signed full build, and a slimmed 11-command signed build) alongside the CrossRAT Java implant and the Pallas Android implant. The lineage fingerprint that survives rebuilds is the AES-CFB encryption with the hardcoded IV `0123456789123456` and the Base64+`&&&&` C2 payload format. To defeat reputation checks the 2019–2020 samples were digitally signed with Certum (Polish CA) code-signing certificates. Known domains from the Check Point appendix: `ntsclouds.com`, `jtoolbox.org`, `mainsrv.top`, `olex.live`, `megawoc.com`, `fikofiko.top`, `p2020.club`, `pronews.icu`, `mbcde.net`, `horizongb.com`, `2ndprog.monster` and others.
- **Why a hunt, not a rule:** Domain registration, malware compilation and certificate purchase all happen on the adversary's own infrastructure — there is nothing on our endpoints to alert on. The value is proactive clustering: a passive-DNS hit on a Porkbun/`.top` domain is far too broad to alert on alone (thousands of benign domains match), and a Certum-signed binary is legitimately common. Only the *fusion* — a new domain matching the registrar+TLD pattern whose hosted sample carries the AES-IV/opcode fingerprint, or a Certum signer whose thumbprint already appears on known Bandook samples — produces an actionable watchlist entry. That correlation and judgement is hunt/intel work. If a durable indicator falls out (e.g. a specific Certum thumbprint confirmed on multiple Bandook samples — a Summiting Level-2 signer observable), hand it to detection-engineering as a scoped signer watchlist rather than trying to alert on "a `.top` domain was registered."

## Data sources required

- Passive DNS + domain-registration intel (WHOIS/RDAP): registrar = Porkbun/NameSilo, disposable TLDs, registration-date recency, name-server and hosting overlap with known Bandook domains
- Malware-sample repositories / sandbox feeds (VirusTotal, internal detonation): strings and config for the AES-CFB IV `0123456789123456`, the `&&&&` C2 marker, Bandook command-opcode set, UPX packing
- Certificate Transparency logs + code-signing reputation feed: Certum-issued code-signing certs, thumbprints already associated with Bandook samples
- Internal DNS/proxy resolution logs (to check whether any newly-clustered actor domain has *already* been resolved by our estate — pivot into on-victim reality)

## Query starting point

Platform: `KQL / Microsoft Sentinel` — cross-reference a newly-clustered actor-infrastructure watchlist against our own resolution logs to promote an off-victim cluster into an on-victim lead.

```kusto
// Actor infra watchlist (ingested from passive-DNS/CT clustering: Porkbun/NameSilo + disposable TLD
// + AES-IV/opcode sample overlap + Certum signer). Known-bad seeds pre-loaded from the Check Point appendix.
let darkcaracal_infra = _GetWatchlist('darkcaracal_domains')
    | project ActorDomain = Domain, Cluster = ClusterReason, FirstSeen;
// Have any clustered actor domains ALREADY been resolved inside our estate? (off-victim -> on-victim pivot)
DnsEvents
| where TimeGenerated > ago(30d)
| extend q = tolower(Name)
| join kind=inner (darkcaracal_infra | extend q = tolower(ActorDomain)) on q
| summarize resolvers = dcount(ClientIP), clients = make_set(ClientIP, 25),
            first = min(TimeGenerated), last = max(TimeGenerated)
         by q, Cluster
| order by first asc   // earliest internal resolution of a freshly-clustered actor domain = highest priority
```

## Triage guidance

- **Likely malicious:** a newly-registered domain on Porkbun/NameSilo + disposable TLD that shares name-servers or hosting with a known Bandook C2 AND hosts a sample carrying the AES-CFB IV `0123456789123456` or the `&&&&` C2 marker; a Certum-signed binary whose thumbprint matches a previously-confirmed Bandook sample; any of the known appendix domains resolving inside our estate.
- **Likely benign / expected:** Porkbun/NameSilo and cheap TLDs are enormously popular with legitimate small sites — registrar+TLD alone is noise; Certum signs vast quantities of legitimate software — the signer alone is not a signal; a security tool or researcher in your org resolving a known-bad domain during analysis (baseline your sandbox/researcher egress IPs and exclude).
- **Pivot next:** when a cluster hit is corroborated (fingerprinted sample OR internal resolution), promote the domain/thumbprint to the detection pack's C2 (T1071.001) and code-signing (T1553.002) watchlists, sweep DNS/proxy for any host that resolved it, and if an internal client already reached it, treat as active delivery and pivot to HUNT-02 (cloud staging) and the on-victim loader detections (T1059.001 / T1055.012). Escalate to incident-response-coordinator if resolution correlates with an Office→PowerShell lineage on the same host.

## References

- https://research.checkpoint.com/2020/bandook-signed-delivered/
- https://www.lookout.com/documents/reports/lookout-dark-caracal-20180118-us.pdf
- https://www.eff.org/deeplinks/2020/12/dark-caracal-you-missed-spot
- https://attack.mitre.org/groups/G0070/
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1587/001/
- https://attack.mitre.org/techniques/T1588/003/
