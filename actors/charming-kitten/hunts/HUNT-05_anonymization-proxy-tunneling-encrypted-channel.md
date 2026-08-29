# Hunt: Charming Kitten anonymization, proxy, tunneling & encrypted C2 channel

- **Hypothesis:** If Charming Kitten is operating hands-on-keyboard in our cloud/network, then in sign-in and network telemetry we should observe its access-anonymization tradecraft — cloud logins and C2 egress via ExpressVPN exit nodes, Cloudflare-fronted domains and ephemeral VPS ASNs (geo-infeasible vs. the user's normal locations) — and, on-host, TAMECAT's AES-encrypted web channel identifiable by a random 16-char IV carried in a non-standard `Content-DPR` HTTP header, plus tunneled/non-browser encrypted egress that hides C2 in TLS.
- **ATT&CK:**
  - T1090 — Proxy (command-and-control)
  - T1572 — Protocol Tunneling (command-and-control)
  - T1573 — Encrypted Channel (command-and-control)

- **Actor procedure:** APT42 proxies/anonymizes access through ExpressVPN exit nodes, Cloudflare-fronted domains and ephemeral VPS to obscure the true source of M365 logins and C2. Its C2 is encrypted: NICECURL runs over HTTPS/TLS (`curl --ssl-no-revoke`); TAMECAT AES-encrypts POST content with key `kNz0CXiP0wEQnhZXYbvraigXvRVYHk1B` and a **random 16-character IV sent in a `Content-DPR` header** — a narrow, distinctive network tell — layering symmetric crypto over its web channel, and tunnels traffic to look legitimate.
- **Why a hunt, not a rule:** VPN/Cloudflare/VPS traffic is enormous and mostly legitimate; alerting on "login from a VPN" or "TLS to Cloudflare" drowns the SOC. The signal is *relational and stacked*: a login from a hosting/VPN ASN that is geo-infeasible against the same user's baseline, correlated with the anomalous process→network behavior in HUNT-04. The `Content-DPR` IV header is real and fairly specific but low-volume and easily changed by the actor (Level-2 observable) — a strong hunt pivot, not a durable standalone rule. Encryption defeats content inspection, so tunneling detection leans on volume/timing anomalies that need baselining. All of this is judgement-heavy → hunt.

## Data sources required

- Cloud sign-in logs (Entra ID / M365) with ASN, IP, geo, device
- ASN / IP reputation & VPN/hosting-provider enrichment (ExpressVPN, known VPS ranges)
- Proxy / SWG logs with request headers (to catch `Content-DPR`) where TLS is inspected
- Network flow / firewall (bytes-per-session, session duration, non-browser TLS egress)
- EDR / Sysmon EID 3 (process→network for the encrypted egress)

## Query starting point

Platform: `KQL / Microsoft Sentinel` — geo-infeasible sign-ins from VPN/hosting ASNs, plus the `Content-DPR` header tell

```kusto
// (a) Anonymized / geo-infeasible cloud login (T1090)
SigninLogs
| where ResultType == 0
| extend asn = tostring(parse_json(tostring(NetworkLocationDetails))[0])
| join kind=inner (IPReputation | where tag in ("VPN","Hosting","ExpressVPN","VPS")) on $left.IPAddress == $right.IP
| summarize logins=count(), ips=make_set(IPAddress,10), asns=make_set(AutonomousSystemNumber,10),
            countries=make_set(Location,10) by UserPrincipalName, bin(TimeGenerated,1d)
| where array_length(countries) > 1                 // mixes home + VPN/VPS geo in same window
// enrich: does the user ever normally log in from these ASNs?  (compare to 30d baseline)
| join kind=leftouter (
    SigninLogs | where TimeGenerated between (ago(60d)..ago(2d))
    | summarize baseline_asns=make_set(AutonomousSystemNumber,50) by UserPrincipalName) on UserPrincipalName
| project TimeGenerated, UserPrincipalName, logins, asns, baseline_asns, countries

// (b) TAMECAT encrypted-channel tell (T1573) — requires TLS-inspected proxy
// ProxyLogs | where http_method == "POST" and isnotempty(header_content_dpr)
//           | where InitiatingProcess !in ("chrome.exe","msedge.exe","firefox.exe")
//           | project TimeGenerated, src_host, url, header_content_dpr, bytes_out
```

## Triage guidance

- **Likely malicious:** successful M365 login from an ExpressVPN/VPS/hosting ASN the user has never used, geo-infeasible against their normal locations, especially clustered with app-password or KMSI use; any HTTP POST carrying a `Content-DPR` header from a non-browser process; long-lived encrypted non-browser egress with steady byte volume (tunneling) to a rare destination.
- **Likely benign / expected:** users on a corporate VPN or personal VPN with a documented pattern; travelling staff; cloud/dev-ops hosts with legitimate VPS egress. `Content-DPR` is a legitimate (if rare) client-hints response header — confirm it is on a *request* from a script host, not a normal CDN response. Baseline per-user VPN/ASN history and per-host egress.
- **Pivot next:** correlate the anonymized login to session/token anomalies and app-password creation (detection pack T1550.004 / T1556.006 / T1621); on a `Content-DPR` or tunneling hit pivot to HUNT-04 (glitch/tebi C2) and the host's script chain (HUNT-06). Confirmed anonymized hands-on-keyboard access is a live incident → escalate to IR.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/untangling-iran-apt42-operations
- https://attack.mitre.org/groups/G0059
