# Hunt: OilRig identity abuse — valid accounts, external remote services, RDP & brute force

- **Hypothesis:** If OilRig has harvested credentials (STEALHOOK / password-filter DLL / LaZagne), then identity telemetry will show those accounts used in anomalous ways — new-device/impossible-travel logons through VPN/Citrix/OWA (external remote services), lateral RDP fan-out from an unusual source, or an authentication-failure spike preceding a successful logon (brute force) — that blends with legitimate use but deviates from each account's own baseline.
- **ATT&CK:**
  - T1078 — Valid Accounts (defense-evasion)
  - T1133 — External Remote Services (persistence)
  - T1021.001 — Remote Services: Remote Desktop Protocol (lateral-movement)
  - T1110 — Brute Force (credential-access)
- **Actor procedure:** OilRig **uses compromised credentials to access other systems**, **persists via VPN, Citrix and OWA** external remote services, **uses RDP for lateral movement**, and **uses brute force to obtain credentials** — with the Earth Simnavaz chain harvesting plaintext creds via a password-filter DLL and exfiltrating them for reuse.
- **Why a hunt, not a rule:** valid-account abuse is, by definition, legitimate-looking authentication; RDP and VPN logons are routine; brute-force thresholds fire constantly on benign lockouts. The signal is per-account/per-host deviation (new geo/device/time, RDP to hosts never previously reached, failures immediately followed by success) — statistical baselining that belongs in a hunt, with confirmed patterns handed to detection-engineering.

## Data sources required

- Windows Security 4624 (type 10 = RDP, type 3 = network), 4625 (failed logon), 4648 (explicit-credential logon)
- VPN / Citrix / OWA / M365 sign-in logs (source IP, geo, device, MFA result)
- Identity-provider / Azure AD sign-in + risk telemetry

## Query starting point

Platform: `KQL/Sentinel`

```
SigninLogs
| where TimeGenerated > ago(14d)
| extend geo = tostring(LocationDetails.countryOrRegion)
| summarize logons=count(), geos=make_set(geo), devices=make_set(DeviceDetail.deviceId),
          fails=countif(ResultType != 0), success=countif(ResultType == 0),
          apps=make_set(AppDisplayName)
  by UserPrincipalName, bin(TimeGenerated, 1h)
| extend distinct_geos = array_length(geos)
| where (distinct_geos > 1)                                 // impossible-travel candidate
     or (fails > 20 and success > 0)                        // brute-force-then-success
     or (apps has_any ("Citrix","VPN","Outlook Web App"))   // external remote services surface
| order by fails desc, distinct_geos desc
```

For RDP fan-out, pair with: `SecurityEvent | where EventID==4624 and LogonType==10 | summarize dcount(Computer) by Account, bin(TimeGenerated,1h) | where dcount_Computer > 3`.

## Triage guidance

- **Likely malicious:** a service or admin account authenticating from a new country/ASN or new device; RDP (type 10) from a host that never initiated RDP before to multiple internal targets; a burst of 4625 failures resolving into a 4624 success; OWA/VPN logon shortly after a credential-theft event on a DC.
- **Likely benign / expected:** travelling staff, VPN pools with shifting egress IPs, legitimate jump-host RDP admins, and users mistyping passwords. Baseline per account and allowlist known admin jump paths.
- **Pivot next:** tie the source host to prior discovery/credential activity (HUNT-03, detection lane); check for service creation / scheduled tasks on RDP targets (detection lane); confirmed compromised-account reuse → escalate to IR and hand the stable pattern to detection-engineering.

## References

- https://attack.mitre.org/groups/G0049/
- https://www.trendmicro.com/en_us/research/24/j/earth-simnavaz-cyberattacks.html
