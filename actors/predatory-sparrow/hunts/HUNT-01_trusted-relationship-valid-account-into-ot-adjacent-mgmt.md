# Hunt: Predatory Sparrow — trusted-relationship & valid-account access into OT-adjacent management servers (FLAGSHIP)

- **Hypothesis:** If Predatory Sparrow (Gonjeshke Darande) is staging a pre-detonation foothold in our estate, the quiet tell is *not* the wiper — that fires last, all at once — but a **trusted upstream provider or valid privileged account reaching a central OT-management / technical-support / distribution server it has no operational reason to touch**, then fanning downstream. The actor reached "roughly 70% of Iran's fuel stations" not by hacking each one but by compromising the *shared central management system that operates the fuel-pump software* (T1199), and deployed the railway wiper with *existing domain privileges* (T1078). So the observable is: a third-party/vendor account or a privileged service account authenticating to an OT-adjacent management host from a new source, off-hours, or over a protocol it never used before — followed by that host initiating outbound admin sessions (SMB/WinRM/RDP/WMI) to a fleet of downstream operator endpoints. Either half is thin; the pair — anomalous inbound trusted access **plus** downstream fan-out from the same jump host — is the finding.
- **ATT&CK:**
  - T1199 — Trusted Relationship (initial-access) — abuse of the shared central management/technical-support platform to fan out to downstream fuel stations / operators; largely invisible from any single downstream victim, so it must be hunted at the provider/jump-host tier.

- **Actor procedure:** In the October 2021 and December 2023 fuel-station operations the actor reached the stations by **compromising the central management / technical-support server for the fuel-pump software** and operating from it with valid, privileged access to the downstream station population. In the July 2021 railway operation it deployed the Meteor toolchain across many domain-joined hosts using **existing domain privileges** and Active Directory Group Policy from a single foothold. The pattern is consistent: obtain trusted/privileged access to a *one-to-many* control point (vendor management platform, DC, distribution server), then use that point's legitimate reach to touch everything downstream at once. The destructive payload is synchronized to a fixed time (scheduled task `mstask` at 23:55) so the fan-out and the detonation are deliberately separated in time — giving defenders a dwell window in which only the access anomaly is visible.

- **Why a hunt, not a rule:** A vendor account logging into a management server and that server pushing config to endpoints is *exactly what the platform is for* — a standalone "vendor logon" or "management fan-out" alert would fire constantly and be tuned away. The signal exists only in **correlation and context**: this specific source is new for this account, this timing is off-cadence, and the same jump host that received the anomalous inbound session is now initiating an unusually broad downstream sweep. That fusion of identity-analytics, host-lineage, and OT-adjacency judgement is hunt work. If a durable relational observable falls out — e.g., "an interactive logon to the OT-management server by a vendor identity from an ASN never previously seen for that identity, followed within N hours by WinRM to >X downstream hosts" — that is a Level-4 relational analytic worth handing to detection-engineering; do not try to alert on "trusted relationship abused."

## Data sources required

- Identity/auth analytics on OT-adjacent management/support/distribution servers: Windows Security 4624/4648 (logon type, source IP/host, auth package), Azure AD/Entra sign-in logs for vendor/federated identities, VPN/RADIUS/jump-host session logs
- Vendor/third-party access inventory: which external identities and source ASNs are *expected* for each management platform (the baseline that makes "new source" meaningful)
- East-west telemetry from the jump host: outbound SMB (5145), WinRM/WS-Man (Microsoft-Windows-WinRM/Operational), RDP (4624 type 10), WMI (Microsoft-Windows-WMI-Activity) to downstream operator endpoints — the fan-out half
- Network flow / OT-DMZ firewall logs between the enterprise/IT segment and the OT-adjacent management zone (crossing the IT/OT boundary is itself a rare, high-value event)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — fuse anomalous inbound trusted access to a mgmt host with downstream fan-out from that same host

```kusto
let mgmt_hosts = _GetWatchlist('ot_adjacent_mgmt_servers') | project DeviceName = SearchKey;   // fuel/pump/HMI/distribution mgmt, DCs, vendor jump hosts
let vendor_ids = _GetWatchlist('third_party_service_accounts') | project Account = SearchKey;
// (a) Anomalous inbound trusted/privileged logon to a management host: new source ASN/host for this identity
let anomalous_access = SigninLogs
    | union (SecurityEvent | where EventID in (4624,4648) | extend AccountName = Account, IPAddress = IpAddress)
    | where TimeGenerated > ago(21d)
    | where AccountName in (vendor_ids) or TargetDeviceName in (mgmt_hosts)
    | summarize seen_ips = make_set(IPAddress, 25), first = min(TimeGenerated), last = max(TimeGenerated) by AccountName, DeviceName = TargetDeviceName
    | mv-expand src = seen_ips to typeof(string)
    // exclude source IPs on this identity's approved-source baseline (see wiki/watchlist); flag the rest
    | where isnotempty(src) and src !in (_GetWatchlist('approved_vendor_sources'));
// (b) Fan-out FROM that same mgmt host to many downstream endpoints shortly after
let fanout = DeviceNetworkEvents
    | where TimeGenerated > ago(21d)
    | where RemotePort in (445,5985,5986,3389,135)
    | summarize downstream = dcount(RemoteIP), targets = make_set(RemoteIP, 50), when = min(TimeGenerated) by DeviceName
    | where downstream >= 25;                         // broad sweep = one-to-many control point in use
anomalous_access
| join kind=inner (fanout) on DeviceName
| where when between (last .. (last + 24h))           // fan-out follows the anomalous inbound access
| project DeviceName, AccountName, src, last_access = last, downstream, fanout_started = when, targets
| order by downstream desc
```

## Triage guidance

- **Likely malicious:** a vendor/support identity authenticating to the OT-management server from an ASN/geo/host never before seen for that identity, off normal support hours, immediately followed by that server initiating WinRM/SMB/RDP to dozens of downstream operator endpoints it does not routinely administer; any interactive (type 10) or network (type 3) logon that *crosses the IT→OT-adjacent boundary* by an account not on the OT allow-list; the same jump host later staging archives or scheduled tasks (pivot to HUNT-03 and the detection-lane T1053.005/T1484.001).
- **Likely benign / expected:** scheduled vendor maintenance windows, patch/config pushes from a management platform to its managed fleet, and RMM tooling — all produce legitimate one-to-many fan-out; baseline each management host's *normal* downstream breadth and each vendor identity's *normal* source ASNs and hours before flagging. A support login from the vendor's known jump host during a ticketed window is expected; the same account from a residential/hosting ASN at 02:00 is not.
- **Pivot next:** if the anomalous access correlates with downstream fan-out, treat as a **live pre-detonation foothold** — this actor's endgame is synchronized destruction, so time is the adversary's, not yours. Escalate to incident-response-coordinator, isolate the jump host, force-rotate the trusted/vendor credential and any privileged account it can reach, and immediately run HUNT-03 (pre-detonation discovery) and the destructive-staging detection lane (T1053.005 `mstask` at 23:55, T1484.001 GPO from SYSVOL, T1105 env.cab staging). Preserve the vendor-side access path for provider-tier notification.

## References

- https://www.picussecurity.com/resource/blog/predatory-sparrow-inside-the-cyber-warfare-targeting-irans-critical-infrastructure
- https://time.com/6548680/iran-hacker-gas-station-cyberattack-israel/
- https://www.cnbc.com/2023/12/18/pro-israel-hackers-claim-cyberattack-disrupting-irans-gas-stations.html
- https://attack.mitre.org/techniques/T1199/
