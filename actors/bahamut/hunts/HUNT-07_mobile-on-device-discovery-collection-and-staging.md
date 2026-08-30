# Hunt: Bahamut — on-device discovery, automated collection & pre-exfil archiving (mobile)

- **Hypothesis:** If Bahamut spyware is collecting from an at-risk user's Android device, then because it **enumerates installed apps and device/owner identifiers, then automatically harvests SMS/contacts/call logs/location/files into a local database and RSA-encrypts the batch before HTTPS exfil**, the mobile-EDR/MDM tell is a **sideloaded app holding the broad read-permission set (SMS, contacts, call log, fine location, external storage, query-all-packages, read-phone-state) that a VPN/chat app has no reason for, coupled with periodic egress to a young C2 domain**. No single dangerous permission is a finding; the *aggregation* of the whole collection permission set on one masqueraded app, plus automated periodic C2 egress, is.
- **ATT&CK:**
  - T1518 — Software Discovery (discovery) — the spyware enumerates installed applications (QUERY_ALL_PACKAGES) to find which messaging/target apps are present and tailor collection.
  - T1082 — System Information Discovery (discovery) — collects IMEI, device ID, IP, SIM serial, and device accounts for fingerprinting/C2 registration.
  - T1033 — System Owner/User Discovery (discovery) — harvests device accounts and owner info to identify the victim.
  - T1005 — Data from Local System (collection) — harvests SMS, call logs, contacts, GPS location, device accounts and external-storage files, staging them locally.
  - T1119 — Automated Collection (collection) — continuous, operator-free gathering written to a local SQLite/database before batched exfil.
  - T1560 — Archive Collected Data (collection) — RSA/ECB/OAEPPadding encryption of the collected batch before exfil, also hampering analyst recovery.

- **Actor procedure:** Once active, the spyware (SecureVPN family and SafeChat/CoverIm) enumerates installed apps to locate messaging targets, fingerprints the device (IMEI, device ID, IP, SIM serial, accounts) and identifies the owner, then automatically and continuously collects SMS, call logs, contacts, GPS location and files from external storage into a local SQLite database. Before exfiltration the SafeChat/CoverIm variant encrypts the batch with RSA/ECB/OAEPPadding and sends it over a Let's Encrypt-secured HTTPS channel — SecureVPN C2 ft8hua063okwfdcu21pw[.]de, SafeChat C2 laborer-posted[.]nl on non-standard port 2053 — using a Ktor (Kotlin) client. The permission footprint required to do all this is the durable, on-device observable.
- **Why a hunt, not a rule:** Each permission (READ_SMS, READ_CONTACTS, ACCESS_FINE_LOCATION, etc.) is individually held by many legitimate apps, and on-device collection/encryption is entirely invisible to *enterprise* telemetry without mobile EDR/MDM — a structural visibility gap. There is no single event to alert on; the finding is the *aggregation anomaly* — one sideloaded, masqueraded app holding the full collection permission set that its stated function (VPN/chat) does not justify — correlated with automated periodic C2 egress, which is an analyst aggregation judgement, not a rule. If a specific package with this exact footprint + C2 is confirmed, hand the package/C2 atomics to the detection pack; the permission-aggregation heuristic stays a hunt.
- **VISIBILITY-GAP NOTE:** Unmanaged/BYOD devices give **no telemetry** for any of this — mirror HUNT-06: treat at-risk individuals on unmanaged devices as a coverage gap to remediate (MDM enrollment / managed device), not as clean.

## Data sources required

- MDM / mobile-EDR permission & app-inventory telemetry: full requested/granted permission set per app, install source & signer (shared with HUNT-05/06).
- Mobile network telemetry: periodic egress to young/C2 domains (ft8hua063okwfdcu21pw[.]de, laborer-posted[.]nl), non-standard port 2053, batched-upload volume patterns (cross-ref detection pack T1071.001/T1571/T1041).
- On-device DLP / file-access telemetry where the mobile-EDR exposes it (external-storage reads, local DB creation).
- At-risk-user → device mapping.

## Query starting point

Platform: `EDR / MDM (mobile permission aggregation on a sideloaded app + periodic C2 egress)`

```kusto
let collectionPerms = dynamic(["READ_SMS","READ_CONTACTS","READ_CALL_LOG","ACCESS_FINE_LOCATION",
        "READ_EXTERNAL_STORAGE","QUERY_ALL_PACKAGES","READ_PHONE_STATE","GET_ACCOUNTS"]);
MobilePermissionEvents
| where TimeGenerated > ago(30d)
| where PermissionName in (collectionPerms)
| summarize granted = make_set(PermissionName, 15), permCount = dcount(PermissionName)
        by DeviceName, UserPrincipalName, PackageName, AppDisplayName
| where permCount >= 5                                             // broad collection footprint
| join kind=inner (
    MobileAppInventory
    | where InstallSource != "com.android.vending"                // sideloaded masquerade
    | project PackageName, InstallSource, Signer
  ) on PackageName
// Corroborate with periodic egress to a young/C2 destination from the same device
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemoteUrl has_any ("ft8hua063okwfdcu21pw","laborer-posted") or RemotePort == 2053
    | summarize beacons = count(), dests = make_set(RemoteUrl, 5) by DeviceName
  ) on DeviceName
| project DeviceName, UserPrincipalName, AppDisplayName, PackageName, permCount, granted, Signer, beacons, dests
| order by permCount desc, beacons desc
```

## Triage guidance

- **Likely malicious:** a sideloaded VPN/chat app holding 5+ collection permissions (SMS + contacts + call log + location + storage + query-all-packages) that its function does not justify, on an at-risk user's device, *and* showing periodic egress to a young/C2 domain or port 2053; a masqueraded package from HUNT-05 that now also matches this footprint; automated/batched upload volume consistent with database exfil.
- **Likely benign / expected:** messaging apps, backup/sync tools, dialers and social apps legitimately hold many of these permissions — a *Play-store* app with the correct vendor signer and no C2 egress is expected; QUERY_ALL_PACKAGES is used by some legitimate launchers/security apps. The finding requires the sideloaded/masqueraded origin AND the aggregation AND (ideally) the C2 corroborator — not permissions alone.
- **Pivot next:** confirmed collection footprint + C2 = active espionage exfil from the individual — escalate to incident-response-coordinator, MDM-isolate/wipe, treat all SMS/contacts/calls/location/messaging on the device as exfiltrated, notify and support the at-risk individual, and pivot to HUNT-06 (input-layer capture) and HUNT-02 (infrastructure). Push the confirmed C2 domain/port and package/signer to the detection pack (T1071.001/T1571/T1041) and preserve for attribution.

## References

- https://www.welivesecurity.com/2022/11/23/bahamut-cybermercenary-group-targets-android-users-fake-vpn-apps/
- https://www.cyfirma.com/research/apt-bahamut-targets-individuals-with-android-malware-using-spear-messaging/
- https://attack.mitre.org/techniques/T1518/
- https://attack.mitre.org/techniques/T1082/
- https://attack.mitre.org/techniques/T1033/
- https://attack.mitre.org/techniques/T1005/
- https://attack.mitre.org/techniques/T1119/
- https://attack.mitre.org/techniques/T1560/
