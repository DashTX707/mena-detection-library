# Hunt: Agrius valid-account reuse over commercial-VPN infrastructure — anonymized last-hop logons into exposed apps/RDP

- **Hypothesis:** If Agrius is entering or re-entering the environment with stolen-but-legitimate credentials over acquired anonymization infrastructure, then we should observe successful authentications to exposed applications, VPN/SSL-VPN and RDP whose source is a commercial-VPN/hosting ASN (observed ProtonVPN) rather than a residential/enterprise ISP, arriving at off-hours or from geographies inconsistent with the account's normal pattern (impossible travel), and — the strongest tell — RDP or interactive logons *sourced from an internet-facing web server* (the web-shell host) into internal systems, which no legitimate user workflow produces.
- **ATT&CK:**
  - T1078.002 — Valid Accounts: Domain Accounts (initial-access) — reuse of brute-forced/sprayed/dumped domain creds for logon, RDP and lateral movement
  - T1583 — Acquire Infrastructure (resource-development) — commercial-VPN (ProtonVPN) last-hop anonymization into victim networks
- **Actor procedure:** Agrius anonymizes its last hop with commercial VPN services such as ProtonVPN, then authenticates with valid domain credentials it obtained via SMB brute force/spraying and LSASS/SAM dumping, reusing them for RDP and follow-on lateral movement. It also tunnels RDP through its ASPXSpy web shells and Plink, so interactive sessions can originate from the compromised web server itself. Initial access is frequently via CVE-2018-13379 (FortiOS SSL-VPN) — credential/session theft that feeds legitimate-looking logons.
- **Why a hunt, not a rule:** authentication with valid credentials is, by definition, "normal" — it blends with legitimate remote work, and commercial-VPN egress is used legitimately by real employees and contractors, so an ASN block or a single-logon alert produces heavy false positives. Off-victim infrastructure acquisition itself is not observable in defender logs at all (a visibility-gap primitive). The durable signal (Summiting Level 3 behavior) is the *combination*: valid-account success **from** a commercial-VPN/hosting ASN **plus** geo/temporal anomaly **or** an RDP source that is itself a server/web-shell host — correlation across identity and network telemetry with per-account baselining, not a threshold.

## Data sources required

- Windows Security 4624/4625 (logon success/failure with `LogonType`, source IP), 4648 (explicit-cred logon), 4768/4769 (Kerberos TGT/TGS)
- VPN / SSL-VPN concentrator auth logs (FortiOS, etc.) with source IP + geo
- IP enrichment: ASN / hosting / commercial-VPN reputation (ProtonVPN and VPN-provider ranges), geolocation
- Network flow / RDP (3389) session logs — RDP source host attribution (is the source an internal server / web host?)

## Query starting point

Platform: `KQL / Microsoft Sentinel`

```
// Valid-account success from a commercial-VPN/hosting ASN, with off-hours / geo-anomaly, or RDP from a server
SigninLogs
| union (SecurityEvent | where EventID == 4624 | extend IPAddress = tostring(IpAddress), UserPrincipalName = TargetUserName, ResultType = "0", LogonType = tostring(LogonType))
| where ResultType == "0"
| extend hour = datetime_part("hour", TimeGenerated)
| join kind=leftouter ( // enrichment table of commercial-VPN / hosting ASNs
    _GetWatchlist("commercial_vpn_asns") | project Network=SearchKey, ASNLabel=asn_label
  ) on $left.IPAddress == $right.Network
| where isnotnull(ASNLabel) or ipv4_is_in_any_range(IPAddress, dynamic(["<protonvpn ranges>"]))
| extend offhours = iff(hour < 6 or hour > 20, 1, 0)
| summarize logons=count(), cities=make_set(Location, 10), asns=make_set(ASNLabel,5),
            srcs=make_set(IPAddress,10), min(TimeGenerated), max(TimeGenerated)
            by UserPrincipalName, bin(TimeGenerated, 1h), offhours
| where logons > 0
| sort by offhours desc, logons desc
```
Companion: from RDP (`LogonType==10`) 4624 events, resolve whether the *source* host is an internet-facing
server / known web-shell host (join to web-shell findings, detection lane / HUNT-03) — RDP from a web server is high signal.

## Triage guidance

- **Likely malicious:** a domain account authenticating successfully from a ProtonVPN/commercial-VPN/hosting ASN it has never used; impossible travel (two distant logons inside a travel-infeasible window); off-hours interactive/RDP logon for an account that is normally 9–5; **RDP or interactive logon sourced from an internet-facing web server** or relayed through a localhost/Plink tunnel; a burst of 4625 failures (spray/brute — detection lane) immediately preceding a 4624 success for the same or a nearby account.
- **Likely benign / expected:** employees/contractors who legitimately use commercial VPNs; travelling users; service accounts with known remote patterns; sanctioned jump-host RDP. Baseline each account's normal ASNs, geographies, hours and RDP sources; VPN egress alone is not a finding.
- **Pivot next:** trace the session's activity — discovery burst (HUNT-02), staging chain (HUNT-01), credential dumping (detection lane). If the source is a web-shell host, pivot to the web-shell/command-exec detections (detection lane) and lateral tool transfer (HUNT-03). Confirmed valid-account abuse from anonymized infra on a wiper actor's kill chain is a live intrusion — escalate to incident-response-coordinator.

## References

- https://www.sentinelone.com/labs/from-wiper-to-ransomware-the-evolution-of-agrius/
- https://unit42.paloaltonetworks.com/agonizing-serpens-targets-israeli-tech-higher-ed-sectors/
- https://attack.mitre.org/groups/G1030/
