# Hunt: Homeland Justice long-dwell external remote re-entry (compromised-account RDP/VPN over a ~14-month window)

- **Hypothesis:** If Storm-0842 has retained access and is re-entering with stolen valid accounts over RDP/VPN — as it did across the ~14-month Albanian dwell, including logging into a print server over RDP to stage the encryptor — then the authentication itself will look legitimate, but the *context* will not: successful external RDP/VPN logons from anomalous source geography/ASN, at off-hours, on accounts that never previously used remote access, or an account authenticating from two geographically infeasible locations in a short window. This is an attack-based hunt keyed on relational/context anomalies stacked on a valid-account logon, because the credential is real and no signature will fire.
- **ATT&CK:**
  - T1133 — External Remote Services (initial-access / persistence via valid remote access)

- **Actor procedure:** Per AA22-264A, over the long dwell the actor repeatedly re-entered the environment using RDP and VPN with compromised accounts (obtained via credential theft — detection-pack T1003), and for the destructive stage logged into a victim organization print server over RDP to use it as a payload distribution point. The access blends with legitimate administration; only the source, timing, and account-behavior context betray it.
- **Why a hunt, not a rule:** External remote access with valid credentials is LOW detection-feasibility because, by construction, it authenticates successfully and mimics sanctioned use — a rule on "successful VPN/RDP logon" is pure noise, and any single contextual signal (one off-hours logon, one new-geo session) has a base rate full of travelling staff, new remote workers, and VPN egress shifts. The value is in *stacking* anomaly primitives on the same principal — never-before-seen source ASN **and** off-hours **and** first-ever remote logon for that account **and** (strongest) geographic infeasibility — and in walking the graph from the entry account to what it then touched (lateral RDP to servers, admin-share writes). That cross-source correlation is judgement-heavy → hunt. The durable core (Summiting Level 3-4, header/behavior): *geographically-infeasible successive authentications by one account* — a candidate to hand to detection-engineering as an impossible-travel rule once the org's legitimate egress/geo baseline is established.

## Data sources required

- VPN/gateway authentication logs (source IP, ASN, geo, account, timestamp)
- Windows Security 4624 Type 10 (RemoteInteractive/RDP) + 4625 failures + Network Policy Server / RADIUS logs
- Per-account remote-access history baseline (has this account used RDP/VPN before? from where? when?)
- GeoIP/ASN enrichment + a graph of which internal hosts each remote session then reached (lateral RDP)

## Query starting point

Platform: `KQL / Microsoft Sentinel` — valid-account remote logons stacking geo/ASN/timing/novelty anomalies

```kusto
let lookback = 180d;
let bh_start = 7;  let bh_end = 19;   // business hours (local)
let baseline =
    SigninLogs
    | where TimeGenerated between (ago(lookback)..ago(14d))
    | summarize knownASNs = make_set(tostring(parse_json(NetworkLocationDetails)[0].networkNames)),
                knownCountries = make_set(Location) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(14d)
| where ResultType == 0                                        // successful
| where AppDisplayName has_any ("RDP","VPN","Remote","Gateway") or ClientAppUsed has "VPN"
| extend hourLocal = datetime_part("hour", TimeGenerated),
         asn = tostring(parse_json(AutonomousSystemNumber))
| join kind=leftouter baseline on UserPrincipalName
| extend newASN     = iff(asn !in (knownASNs), 1, 0),
         newCountry = iff(Location !in (knownCountries), 1, 0),
         offHours   = iff(hourLocal < bh_start or hourLocal > bh_end, 1, 0)
| extend anomalyStack = newASN + newCountry + offHours
| where anomalyStack >= 2                                      // stack, don't single-flag
| project TimeGenerated, UserPrincipalName, IPAddress, Location, asn,
          newASN, newCountry, offHours, anomalyStack
| order by anomalyStack desc, TimeGenerated asc
// Impossible travel pivot: same UPN, two Locations, delta-time < feasible travel
// Graph pivot: 4624 Type10 where source = these sessions -> which servers reached next
```

## Triage guidance

- **Likely malicious:** a successful RDP/VPN logon from a never-before-seen ASN/country for that account, off-hours, on an account with no prior remote-access history; two authentications by one account from geographically infeasible locations within hours; a remote session that immediately pivots to internal RDP against servers (print/file/DB) it never touched before, or is followed by admin-share writes (detection-pack T1021/T1570). Stack 2+ of these on one principal before calling it.
- **Likely benign / expected:** traveling executives, newly-remote staff, VPN provider egress-IP/ASN changes, and cloud-VDI ranges all produce new-geo/new-ASN logons legitimately — corroborate against HR travel, known VPN egress ranges, and the account's role. A single anomaly on an account with a plausible business reason is inconclusive, not a finding; note "requires N days more baseline" for borderline off-hours-only cases.
- **Pivot next:** confirmed anomalous re-entry → pivot to what the session did (lateral RDP graph, tool transfer, HUNT-01 staging), reset the account and hunt for the credential-theft origin (detection-pack T1003 LSASS/SAM). If the entry account reached a print/file server later used as a distribution point, treat as active pre-detonation dwell and escalate to IR. Impossible-travel logic, once baselined, is a clean **handoff to detection-engineering**.

## References

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a
- https://www.microsoft.com/en-us/security/blog/2022/09/08/microsoft-investigates-iranian-attacks-against-the-albanian-government/
- https://attack.mitre.org/techniques/T1133/
