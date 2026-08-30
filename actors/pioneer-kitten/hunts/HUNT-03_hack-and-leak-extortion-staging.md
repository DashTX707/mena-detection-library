# Hunt: Pioneer Kitten hack-and-leak extortion staging (Pay2Key-style leak site + social amplification)

- **Hypothesis:** If Pioneer Kitten is running a Pay2Key-style hack-and-leak or extortion operation touching our organization, then two off-victim tells appear together: (a) adversary-controlled **web infrastructure** — a Tor `.onion` leak site or extortion page — hosted on cloud infrastructure **registered to a previously compromised victim organization** (they abuse victim cloud tenancy to stand up the leak site), and (b) **actor-controlled social-media accounts** publicizing the compromise and tagging our brand / media outlets to amplify the narrative. The on-victim corroborator is anomalous use of *our* cloud tenancy to stand up unexpected public-facing infrastructure. The hunt fuses brand/leak-site monitoring with cloud-tenancy anomaly review.
- **ATT&CK:**
  - T1583.006 — Acquire Infrastructure: Web Services (resource-development) — Pay2Key `.onion` leak site hosted on cloud infra registered to a compromised victim org; abuse of catbox.moe / ngrok / cloud accounts for hosting and relay
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development) — actor accounts publicize compromises and tag victim/media orgs to amplify the hack-and-leak

- **Actor procedure:** In the late-2020 Pay2Key information operation (assessed to undermine Israeli cyber infrastructure rather than for ransom), the actors operated a `.onion` leak site hosted on cloud infrastructure registered to a previously compromised victim organization, then publicized the compromises on social media, tagging the accounts of victim and media organizations to maximize reach. The same tradecraft — abusing a victim's own cloud tenancy to host adversary infrastructure and driving a public narrative — recurs in their extortion collaboration with ransomware affiliates.
- **Why a hunt, not a rule:** The leak site and the social-media accounts live entirely on third-party infrastructure (Tor, cloud, social platforms) — off-victim, un-loggable by us, nothing to alert on. Discovery is intelligence work: dark-web/leak-site monitoring and brand monitoring, correlated by a human. The one on-victim thread — unexpected public-facing infrastructure standing up inside *our* cloud tenancy — is real telemetry, but "a new public endpoint/VM appeared" has far too high a base rate in a live cloud estate to alert on blindly; it needs judgement about whether the resource is adversary-staged. If a precise cloud-audit signal emerges (e.g. a new public bucket/site created by a principal that never provisions infrastructure, then serving to Tor exit nodes), that scoped analytic can go to detection-engineering.

## Data sources required

- Dark-web / leak-site monitoring (ransomware and hack-and-leak sites, `.onion` extortion pages) keyed to our brand, domains, executives
- Brand / social-media monitoring for actor accounts naming or tagging our org, and for the Pay2Key persona pattern
- Cloud audit logs (CloudTrail / Azure Activity / GCP Admin) — creation of new public-facing infrastructure, buckets, VMs, DNS, static-site hosting, esp. by unusual principals
- Cloud egress / access logs — our tenancy serving content to Tor exit nodes or to external/media consumers

## Query starting point

Platform: `KQL / Microsoft Sentinel (Azure Activity + AWS CloudTrail)` — unexpected public infra stood up in our tenancy by an unusual principal

```kusto
// New public-facing infrastructure created in our cloud tenancy, ranked by how out-of-character the principal is
let infraCreate = dynamic(["Microsoft.Web/sites/write","Microsoft.Storage/storageAccounts/write",
    "Microsoft.Network/publicIPAddresses/write","Microsoft.Compute/virtualMachines/write",
    "CreateBucket","PutBucketWebsite","PutBucketPublicAccessBlock","RunInstances","CreateDistribution"]);
let baseline = AzureActivity
    | where TimeGenerated between (ago(90d)..ago(7d))
    | where OperationNameValue has_any (infraCreate)
    | summarize by Caller;                          // principals that normally provision infra
union AzureActivity, AWSCloudTrail
| where TimeGenerated > ago(7d)
| where OperationNameValue has_any (infraCreate) or EventName in (infraCreate)
| extend principal = coalesce(Caller, tostring(parse_json(UserIdentity).arn))
| where principal !in (baseline)                    // never-before-provisioner = suspicious
| project TimeGenerated, principal, OperationNameValue, EventName, ResourceId = coalesce(_ResourceId, tostring(RequestParameters))
| order by TimeGenerated desc
// Pivot: does this new resource serve content to Tor exit nodes / external media? (cross-ref egress logs)
```

## Triage guidance

- **Likely malicious:** a public site / bucket / VM stood up in our tenancy by a principal that has never provisioned infrastructure, especially one later observed serving to Tor exit nodes or hosting data belonging to *another* organization; a leak-site or extortion page naming our org appearing on a ransomware/hack-and-leak site that time-correlates with an internal compromise; a freshly created social-media account posting our internal data and tagging us and media outlets (Pay2Key amplification pattern).
- **Likely benign / expected:** DevOps and platform teams legitimately create public sites, buckets and VMs constantly — baseline by principal and by tagged project; marketing/PR runs official brand social accounts; security researchers and journalists reference breaches without being the actor. A new endpoint from a known infra-provisioning service principal within a tagged project is expected; the same from a dormant or non-infra identity is not.
- **Pivot next:** a confirmed leak site on our tenancy or naming our org is a live extortion/impact event — escalate to incident-response-coordinator, engage legal/comms, preserve the cloud resource and its audit trail as evidence, and hunt inward for the access path (cross-ref HUNT-01 access-broker foothold and detection pack T1530/T1567.002 cloud data movement). Actor social accounts and leak URLs feed back to CTI for infrastructure tracking and takedown.

## References

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a
- https://attack.mitre.org/groups/G0117/
- https://attack.mitre.org/techniques/T1583/006/
- https://attack.mitre.org/techniques/T1585/001/
