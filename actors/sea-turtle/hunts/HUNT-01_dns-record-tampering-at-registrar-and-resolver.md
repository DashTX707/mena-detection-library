# Hunt: Sea Turtle — DNS record tampering at the registrar/registry/resolver (SIGNATURE)

- **Hypothesis:** If Sea Turtle is targeting us, the earliest and most durable tell is *not* on any host we own — it is an unauthorized change to our own authoritative delegation. If the actor has hijacked our resolution, then our NS and/or A records at the registrar/registry/DNS provider will show an out-of-band change — a delegation swapped toward an actor-controlled nameserver (historically `ns1/ns2.intersecdns.com`, `ns1/ns2.lcjcomputing.com` → `95.179.150.101`), an A record repointed to a VPS in the documented MitM set, and/or an abrupt TTL collapse toward 1 second to minimise caching and allow rapid reversion — with the corroborators being a DNSSEC-validation failure for the affected zone and a fresh Certificate-Transparency entry for the same name (see HUNT-02). Any one signal is thin; a delegation/A change **stacked** with a TTL collapse and a CT or DNSSEC anomaly on the same zone is the finding. DNS reconnaissance of our zone (T1590.002) is the off-victim precursor that selects *which* upstream operator to compromise.
- **ATT&CK:**
  - T1584.002 — Compromise Infrastructure: DNS Server (resource-development) — actor alters our NS/A records at the compromised registrar/registry/provider to redirect resolution to MitM nodes; the core behavior this hunt is built to catch.
  - T1590.002 — Gather Victim Network Information: DNS (reconnaissance) — actor first maps our DNS architecture and upstream registrar/registry to choose the hijack point; surfaces as unusual external enumeration of our zone and precedes the tampering.

- **Actor procedure:** Sea Turtle's signature tradecraft (Talos 2017–2019) is to avoid attacking the ultimate victim directly. Instead they compromise a third-party DNS registrar, ccTLD registry or DNS provider, then alter the victim organization's NS and A records *at that operator* to point resolution at actor-controlled man-in-the-middle VPS nodes. TTLs are frequently lowered to as little as 1 second so poisoned answers do not persist in caches and the records can be reverted quickly once credentials are captured. They operate their own nameservers (`intersecdns.com`, `lcjcomputing.com` at `95.179.150.101`) to serve the falsified responses. Reconnaissance of the target's public DNS footprint drives selection of which upstream provider to hit.
- **Why a hunt, not a rule:** The tampering happens on infrastructure we do not own and cannot instrument with EDR — the registrar/registry/provider is outside our boundary, so there is no host log to alert on. The signal lives in *external* vantage points (registrar change notifications, passive DNS, DNSSEC validation, CT logs) that are noisy on their own: registrars legitimately change records, CDNs run 1-second TTLs, and providers rotate nameservers during migrations. The finding only exists when an analyst correlates an unexpected delegation/A change against known-good baseline **and** a second off-victim anomaly on the same zone. If a specific, reliable observable falls out (e.g. our authoritative NS set diverging from an approved allow-list — a durable Level-4 configuration observable), hand *that* to detection-engineering as a scoped monitor; do not try to alert on "a registrar somewhere changed a record."

## Data sources required

- Registrar/registry account audit log + registry-lock / change-notification feed (the authoritative-change vantage; off-victim, provider-side)
- Passive DNS (Farsight/DNSDB, SecurityTrails, Circl pDNS) — historical NS/A/TTL for our owned zones
- DNSSEC validation telemetry (validating resolver logs / RIPE Atlas / dnsviz) — SERVFAIL/bogus for our zones
- Certificate Transparency feed keyed to our domains (shared with HUNT-02) as the corroborating stack

## Query starting point

Platform: `Splunk SPL` — passive-DNS + registrar-audit fusion against a baseline of our approved delegation

```spl
(index=passivedns OR sourcetype=dnsdb) domain IN (owned_zones.csv)
| eval is_new_ns   = if(match(rdata_ns, "intersecdns\.com|lcjcomputing\.com") OR NOT rdata_ns IN (approved_ns.csv), 1, 0)
| eval is_mitm_a   = if(rdata_a IN (mitm_vps_ips.csv), 1, 0)          /* 26 Talos MitM IPs + 95.179.150.101 */
| eval ttl_collapse= if(record_type="A" AND ttl<=60, 1, 0)           /* abrupt drop toward 1s */
| stats max(is_new_ns) as ns_change max(is_mitm_a) as a_to_mitm max(ttl_collapse) as ttl_low
        values(rdata_ns) as ns values(rdata_a) as a min(first_seen) as first by domain
| eval anomaly_stack = ns_change + a_to_mitm + ttl_low
| where anomaly_stack >= 2                                            /* single signal is thin; stack it */
| join type=left domain [ search index=registrar_audit action=record_change
        | stats latest(actor) as changed_by latest(_time) as change_time by domain ]
| join type=left domain [ search index=dnssec result IN ("SERVFAIL","bogus")
        | stats count as dnssec_fail by domain ]
| table domain anomaly_stack ns a a_to_mitm ttl_low changed_by change_time dnssec_fail
```

## Triage guidance

- **Likely malicious:** our NS delegation pointing at `intersecdns.com` / `lcjcomputing.com` or any nameserver not on the approved list; an A record for a login/VPN/webmail host resolving into the documented MitM VPS set; a TTL dropped to 1–60s on a record that has been stable for months; a registrar change with no matching internal change ticket; any of the above stacked with a DNSSEC SERVFAIL/bogus or a fresh CT entry (HUNT-02) for the same name.
- **Likely benign / expected:** planned DNS migrations and CDN onboarding legitimately change NS records and run very low TTLs — reconcile against change tickets and the approved-provider list; blue/green cutovers cause short-lived A changes; some registrars show apparent "changes" that are just glue-record refreshes. A change *with* an approved ticket and staying within the approved delegation is normal.
- **Pivot next:** an unauthorized delegation/A change is a live DNS hijack in progress — escalate to incident-response-coordinator immediately, engage the registrar to lock and revert (enable registry lock / RRSIG), force-rotate every credential that could have transited a spoofed portal during the exposure window, and pivot to HUNT-02 (rogue certificate) and HUNT-03 (MitM interception) to scope credential loss. Preserve passive-DNS and registrar-audit records as evidence.

## References

- https://blog.talosintelligence.com/seaturtle/
- https://www.huntandhackett.com/blog/turkish-espionage-campaigns
- https://attack.mitre.org/techniques/T1584/002/
- https://attack.mitre.org/techniques/T1590/002/
