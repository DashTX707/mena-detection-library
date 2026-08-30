# Hunt: Sea Turtle — targeting research and trusted-relationship (third-party) compromise

- **Hypothesis:** Sea Turtle reaches its ultimate victims *through* trusted intermediaries, and it selects targets deliberately by geopolitical interest rather than opportunistically. If we are a target — or an intermediary the actor will use to reach a downstream target — then two off-victim signals precede any on-host activity: (1) deliberate organizational and DNS reconnaissance of our estate (WHOIS lookups, DNS-footprint enumeration, external attack-surface scanning) consistent with pre-operation research against an entity aligned to Turkish state interest (Kurdish/PKK-affiliated groups, Cypriot/Greek and MENA government/telecom, ISPs, DNS registrars/registries, IT/MSPs); and (2) if we are a DNS provider, registrar, telecom or MSP, an anomalous change or access on *our* side that the actor would use to pivot into a downstream customer — an unexpected admin action in a customer's DNS zone, a support/API access from an unusual source, or a provider-side configuration change with no ticket. This is intel-and-context work: the recon signal alone is background noise for any internet-facing org, but recon that matches the actor's victimology **stacked** with a provider-side trust anomaly aimed at a geopolitically-relevant customer is the finding.
- **ATT&CK:**
  - T1591 — Gather Victim Org Information (reconnaissance) — actor performs targeted organizational research to select victims aligned to Turkish state interest; surfaces as victimology-matched external interest / OSINT footprinting rather than broad scanning.
  - T1199 — Trusted Relationship (initial-access) — actor abuses compromised DNS providers, registrars, registries, telecoms and MSPs to reach downstream victims; hunt via third-party-risk monitoring and provider-side change alerting on customer zones/accounts.

- **Actor procedure:** Sea Turtle's victimology is consistently geopolitical — Kurdish and PKK-affiliated organizations, Cypriot and Greek government and telecom, and MENA government, telecom, ISP, IT-service-provider and DNS registrar/registry targets — indicating deliberate organizational research (T1591) rather than opportunistic targeting. Operationally, the actor's defining move is to compromise a *trusted third party* (a DNS registrar, ccTLD registry, DNS provider or IT/telecom service provider) and abuse the trust that intermediary holds to reach the real target — altering a downstream customer's DNS records from inside the provider, or using provider access as a springboard. For organizations that *are* such providers, the actor's presence shows up as anomalous privileged actions against customer assets, not against the provider's own data.
- **Why a hunt, not a rule:** Target-selection research happens entirely off-victim on public sources and third-party systems — there is nothing on our endpoints to alert on, and generic "someone scanned us" telemetry is far too noisy to be a rule for any internet-facing org. The trusted-relationship compromise, by definition, occurs at a partner outside our boundary; even when we *are* the provider, distinguishing a malicious customer-zone change from legitimate managed-service administration requires knowing which customers are geopolitically relevant and whether a given change was authorized — pure analyst context. The value is fusing victimology-aware recon signals with third-party-risk intelligence and provider-side change auditing, and reasoning about *which* customer relationship an espionage actor would rationally abuse. If a specific provider-side observable proves reliable (e.g. a customer DNS-zone change from a source outside the approved management network), route that to detection-engineering; the cross-context judgement stays here.

## Data sources required

- External attack-surface / recon telemetry: WHOIS-lookup and DNS-enumeration signals against owned zones, internet-scan/OSINT footprinting attributable to actor-consistent sources
- Third-party-risk / supply-chain intelligence: breach notifications and change alerts from our registrars, DNS providers, telecoms and MSPs
- Provider-side change/access audit (if we are a DNS/registrar/telecom/MSP): customer-zone record-change logs, support/API access logs, admin-action logs scoped to customer assets
- Victimology context list: our own geopolitical-relevance markers and those of managed customers (Kurdish/PKK, Cyprus/Greece/MENA gov/telecom, registries)

## Query starting point

Platform: `Splunk SPL` — provider-side customer-zone change auditing fused with victimology relevance (provider view)

```spl
index=dns_mgmt_audit action IN ("record_change","zone_transfer","ns_update","apikey_use")
| lookup customer_context.csv customer_id OUTPUT geopolitical_relevance sector region
| eval offsource   = if(NOT src_ip IN (approved_mgmt_cidrs.csv), 1, 0)         /* access outside mgmt net */
| eval no_ticket   = if(isnull(change_ticket) OR change_ticket="", 1, 0)       /* unauthorized change */
| eval ns_to_actor = if(match(new_value, "intersecdns\.com|lcjcomputing\.com"), 1, 0)
| eval relevant    = if(geopolitical_relevance="high"
                        OR sector IN ("government","telecom","isp")
                        OR region IN ("MENA","Cyprus","Greece"), 1, 0)
| eval risk = offsource + no_ticket + (ns_to_actor*2) + relevant
| where risk >= 2                                                              /* stack, don't single-fire */
| stats values(action) as actions values(new_value) as changes
        max(risk) as risk min(_time) as first max(_time) as last
        by customer_id actor_account src_ip geopolitical_relevance sector
| sort - risk - last
```

*(If we are NOT a provider, invert this: run the recon half — search external-attack-surface / WHOIS-lookup logs for enumeration of owned zones, and fuse with third-party-risk feeds naming our registrar/DNS provider in a breach.)*

## Triage guidance

- **Likely malicious:** a customer DNS-zone change (especially an NS update toward `intersecdns.com`/`lcjcomputing.com`) performed from outside the approved management network, with no change ticket, against a geopolitically-relevant customer; a provider admin/API credential used from an unusual geography against multiple customers' zones; recon of our estate matching the actor's victimology that precedes a third-party breach notice for our registrar or DNS provider.
- **Likely benign / expected:** managed-service providers legitimately change customer DNS records constantly, often via automation or from varied support locations; WHOIS lookups and internet-wide scanning hit every public org daily and are overwhelmingly benign research, security scanners and crawlers; onboarding/migration produces bulk zone changes. A change *with* a ticket from the approved management network, or generic untargeted recon with no victimology match, is expected.
- **Pivot next:** an unauthorized customer-zone change toward actor nameservers is a live trusted-relationship compromise being used to hijack a downstream victim — escalate to incident-response-coordinator, notify and lock the affected customer zone(s), audit the abused provider account's full action history, and pivot to HUNT-01/02/03 to scope the DNS hijack, rogue cert and interception for the downstream target. Treat provider-side credential compromise as the root and rotate/segment management access.

## References

- https://blog.talosintelligence.com/seaturtle/
- https://www.huntandhackett.com/blog/turkish-espionage-campaigns
- https://attack.mitre.org/techniques/T1591/
- https://attack.mitre.org/techniques/T1199/
