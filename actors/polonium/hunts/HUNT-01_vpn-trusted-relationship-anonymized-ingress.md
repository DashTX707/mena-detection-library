# Hunt: POLONIUM — VPN / trusted-relationship initial access via anonymized ingress

- **Hypothesis:** If POLONIUM is entering our estate, the first on-victim tell is not malware but an *ingress-shape anomaly*: a remote-access session (Fortinet SSL-VPN or a managed IT-service-provider connection) that authenticates from an AirVPN/VPS exit node shared with MOIS-affiliated groups, or that arrives through a trusted third-party provider account outside its normal window/scope. Neither an AirVPN login nor a provider session is malicious alone — the finding is a trusted-relationship or remote-access session whose *source reputation, geovelocity, and provider-session scope* stack into an implausible combination on the same identity, especially one reusing credentials leaked in September 2021.
- **ATT&CK:**
  - T1199 — Trusted Relationship (initial-access) — supply-chain-style access through a compromised IT service provider reaching downstream victims; hunt provider-originated sessions outside normal scope.
  - T1090 — Proxy (command-and-control) — AirVPN service and VPS relays used to anonymize the true source; hunt VPN/provider logons sourced from AirVPN/HostGW exit IPs.

- **Actor procedure:** Microsoft observed POLONIUM reaching Israeli victims through **compromised IT service providers** (trusted third-party relationships), and ~80% of victims ran Fortinet devices likely entered via CVE-2018-13379 or Fortinet VPN credentials **leaked online in September 2021**. The group routes connections through **AirVPN** (also used by MERCURY/MuddyWater) and HostGW VPS relays, so the authenticating source IP is an anonymizing exit node, not the actor's true location. IP-only infrastructure means no attacker domains to pivot on — the tell is source-IP reputation plus session shape.
- **Why a hunt, not a rule:** The trusted-provider account and the AirVPN exit are individually legitimate — MSPs log in remotely every day and some staff use commercial VPNs — so a standalone alert on either drowns in noise. The finding lives in the *correlation*: a provider identity authenticating from an AirVPN/VPS ASN, off its normal schedule, into hosts it does not normally touch, ideally matching a leaked-credential list. That fusion and judgement is hunt work. If a durable observable falls out — e.g., any interactive VPN logon sourced from a curated AirVPN/HostGW exit-node set (a Level-3 network observable) — hand that to detection-engineering as a scoped analytic.

## Data sources required

- VPN / remote-access authentication logs (Fortinet FortiOS SSL-VPN, RADIUS, Entra ID sign-in logs) with source IP + ASN enrichment
- Threat-intel / IP-reputation feed tagging AirVPN exit nodes and HostGW ranges (45.80.148.0/22, 185.244.129.0/24) and the pack's VPS IP list
- Managed-service-provider / third-party account inventory: which identities are provider-owned, their normal source ranges, hours, and in-scope hosts
- Leaked-credential monitoring (Sept-2021 Fortinet VPN credential dumps) matched to active accounts

## Query starting point

Platform: `KQL / Microsoft Sentinel (Entra ID sign-in + VPN logs)`

```kusto
let airvpn_vps = dynamic(["212.73.150.174","94.156.189.103","51.83.246.73",
    "185.244.129.109","172.96.188.51","45.137.148.7","146.70.86.6"]);
let provider_ids = _GetWatchlist('msp_service_accounts') | project UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(30d)
| extend asn = tostring(parse_json(AutonomousSystemNumber))
| where IPAddress in (airvpn_vps)
     or asn has_any ("AirVPN","HostGW")
     or ipv4_is_in_any_range(IPAddress, "45.80.148.0/22", "185.244.129.0/24")
| join kind=leftouter (provider_ids) on UserPrincipalName
| extend isProvider = isnotempty(UserPrincipalName1)
// stack anomalies: anonymized source AND (provider identity OR impossible travel OR off-hours)
| extend offHours = hourofday(TimeGenerated) !between (5 .. 20)
| where isProvider or offHours
| project TimeGenerated, UserPrincipalName, IPAddress, asn, Location, isProvider, offHours, AppDisplayName
| order by TimeGenerated desc
```

## Triage guidance

- **Likely malicious:** a provider/MSP identity authenticating from an AirVPN or HostGW exit into hosts outside its documented scope, off-hours, then followed by remote-tool execution; a Fortinet VPN logon from an AirVPN exit on an account whose credentials appear in the Sept-2021 leak; impossible travel between a normal corporate login and an AirVPN exit within minutes on one identity.
- **Likely benign / expected:** staff or admins who legitimately use commercial VPNs (baseline them per identity); scheduled MSP maintenance windows from the provider's own documented ranges; a single AirVPN login by a developer with no follow-on privileged access. AirVPN alone is thin — the provider-scope or leaked-credential overlay is what makes it a finding.
- **Pivot next:** if a provider identity + anonymized source + out-of-scope host access align, treat as candidate initial access — pivot to that host for Creepy-family execution (detection pack T1059.001/T1218.004), hunt cloud-C2 (HUNT-03) and discovery bursts (HUNT-05), and force-rotate the provider credential. If it corroborates a live foothold, escalate to incident-response-coordinator.

## References

- https://www.microsoft.com/en-us/security/blog/2022/06/02/exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/
- https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/
- https://attack.mitre.org/techniques/T1199/
- https://attack.mitre.org/techniques/T1090/
