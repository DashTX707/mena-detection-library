# Hunt: Imperial Kitten — stolen-VPN valid-account foothold & unsecured-credential harvesting

- **Hypothesis:** If Imperial Kitten has moved from initial access to durable operations, then a high-false-positive but high-value visibility gap opens up around **valid remote-access accounts and quietly harvested credential material**: the actor authenticates to our VPN/remote services with *legitimate stolen credentials* (so no exploit fires — the logon looks normal except for a new device/ASN, impossible travel, or off-hours pattern), and once inside, harvests credentials from files, browser stores, config files and process memory to expand access. Neither signal alerts cleanly on its own — a VPN logon is expected, and reading a config file is expected — but a VPN logon from a never-before-seen ASN/geo *followed on the same account/host by a burst of reads of credential-bearing files* (or a honeytoken trip) is the actor establishing and widening a foothold. The hunt correlates anomalous valid-account remote logons with credential-access-shaped file activity on the landing host.
- **ATT&CK:**
  - T1552 — Unsecured Credentials (credential-access) — actor harvests and reuses credentials (including VPN creds) pulled from files, configs and host stores to expand access; hunt via file-access telemetry, honeytokens, and post-logon read bursts.
  - (context) T1133 External Remote Services / T1078 Valid Accounts — the stolen-VPN entry the credential harvest both enables and feeds; the authentication-anomaly side is covered in the detection lane.

- **Actor procedure:** Imperial Kitten used **stolen VPN credentials** to authenticate to victim remote-access services for initial access, and harvested/reused credentials obtained from compromised hosts (including further VPN credentials) to expand access laterally. Credential material feeds directly into their PAExec-driven lateral movement and ProcDump-on-LSASS dumping. The harvesting from files/configs is deliberately low-signal — it blends with normal file reads and leaves little discrete artifact — which is exactly why it is a hunt candidate rather than a detection.
- **Why a hunt, not a rule:** A VPN logon with valid credentials is, by construction, indistinguishable from a legitimate one at the point of authentication — there is no exploit or failure to alert on, and blocking on "new ASN" alone is unacceptable false-positive load (travel, new home ISP, mobile). Likewise, reading a `web.config`, `.ovpn` or browser credential store is routine admin/user behavior; a standalone file-read rule drowns. The finding is only in the *correlation*: an anomalous valid-account remote logon (new device + new ASN + off-hours, or impossible travel) landing on a host that then exhibits a *bulk read of credential-bearing files* or trips a **honeytoken** credential. Deploying honeytokens and judging the fusion is hunt work. If a durable, precise observable falls out — e.g. any authentication using a planted honeytoken credential (Summiting Level 4, a canary that only an intruder touches) — hand that straight to detection-engineering as a high-fidelity alert.

## Data sources required

- VPN / remote-access authentication logs (account, source IP→ASN/geo, device, time) and identity-provider sign-in analytics (impossible travel, new-device, ASN-first-seen)
- EDR/file-access auditing (Sysmon EID 11 / 4663) for credential-bearing files: `.ovpn`, `web.config`, `unattend.xml`, `*.kdbx`, `*.pfx`, browser `Login Data`, `credentials`, `.aws/credentials`, RDP/`.rdp` files
- Honeytoken / canary-credential telemetry (planted creds in files, AD honeypot accounts) — the highest-fidelity half
- Process-access telemetry for browser/credential-store reads by non-owning processes (corroborator)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — join anomalous valid-account VPN logons to post-logon credential-file read bursts on the same identity/host

```kusto
// (a) valid-account remote logons from a never-before-seen ASN/geo (no failure = stolen-cred candidate)
let anomLogon = SigninLogs
    | where TimeGenerated > ago(30d)
    | where AppDisplayName has_any ("VPN","Remote","Gateway","AlwaysOn","GlobalProtect","AnyConnect")
    | where ResultType == 0                                   // SUCCESS with valid creds
    | extend asn = tostring(AutonomousSystemNumber), geo = tostring(LocationDetails.countryOrRegion)
    | summarize logons = count(), asns = make_set(asn), geos = make_set(geo), firstSeen = min(TimeGenerated)
        by UserPrincipalName, asn, geo
    | join kind=inner ( SigninLogs | where TimeGenerated between (ago(180d) .. ago(30d))
        | summarize knownAsns = make_set(tostring(AutonomousSystemNumber)) by UserPrincipalName ) on UserPrincipalName
    | where asn !in (knownAsns)                               // never-before-seen ASN for this user
    | project UserPrincipalName, asn, geo, firstSeen;
// (b) post-logon bulk read of credential-bearing files on that identity's host
let credReads = DeviceFileEvents
    | where TimeGenerated > ago(30d)
    | where ActionType == "FileAccessed"
    | where FileName has_any (".ovpn","web.config","unattend.xml",".kdbx",".pfx","credentials","Login Data",".rdp")
    | summarize files = dcount(FolderPath), fileset = make_set(FileName, 20), readTime = min(TimeGenerated)
        by DeviceName, acct = InitiatingProcessAccountUpn
    | where files >= 4;                                        // bulk = harvest, not one lookup
anomLogon
| join kind=inner credReads on $left.UserPrincipalName == $right.acct
| where readTime > firstSeen                                  // harvest AFTER the anomalous logon
| order by files desc
// PIVOT: overlay honeytoken trips and check for downstream PAExec/ProcDump on the same host (detection lane)
```

## Triage guidance

- **Likely malicious:** a valid-account VPN logon from an ASN/geo the account has never used, off-hours, from a new device, *followed on the same host by a bulk read of credential-bearing files*; any authentication or file-read that trips a planted honeytoken credential (near-zero benign rate — treat as confirmed intrusion); credential-store reads by a process that does not own them, on a host that just received an anomalous remote logon.
- **Likely benign / expected:** travelling staff, new home/mobile ISPs, and VPN concentrators legitimately produce new-ASN logons; admins, backup jobs, config-management (Ansible/GPO) and vulnerability scanners read `web.config`/`unattend.xml`/`.ovpn` broadly; password managers hold `.kdbx`. Baseline each user's normal ASN set and each host's normal credential-file readers, and require the *logon-anomaly + post-logon read-burst* pairing (or a honeytoken trip) rather than either half. A single new-ASN logon, or one config read, is not a finding.
- **Pivot next:** on a confirmed pair, force-rotate every credential reachable from the harvested fileset and the VPN account, hunt the same host for LSASS dumping (ProcDump/comsvcs — detection lane T1003.001), PAExec lateral movement (T1021.002) and NetScan recon (HUNT-05), and check whether the anomalous-ASN source IP intersects the actor VPS IOC set. A honeytoken trip or confirmed harvest-after-anomalous-logon is a live compromise — escalate to incident-response-coordinator. If **no honeytokens exist**, recommend seeding them as the single highest-yield improvement for this low-signal technique.

## References

- https://www.crowdstrike.com/en-us/blog/imperial-kitten-deploys-novel-malware-families/
- https://attack.mitre.org/techniques/T1552/
- https://attack.mitre.org/techniques/T1133/
- https://attack.mitre.org/techniques/T1078/
