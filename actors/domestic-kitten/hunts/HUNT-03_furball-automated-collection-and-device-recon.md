# Hunt: FurBall automated collection, device fingerprinting, app enumeration and camera capture

- **Hypothesis:** If FurBall is active on a managed Android device, then MTD/static-analysis telemetry and network egress will show a single package driving a broad automated harvest — device fingerprinting, installed-app enumeration, and on-demand camera capture — governed by a C2-tasking loop, producing an unexpected-relationship anomaly (one non-camera/non-security app touching camera, package-query, and device-ID APIs together) that no benign single-purpose app exhibits.
- **ATT&CK:**
  - T1119 — Automated Collection (collection)
  - T1082 — System Information Discovery (discovery)
  - T1518 — Software Discovery (discovery)
  - T1125 — Video Capture (collection)
- **Actor procedure:** FurBall automatically harvests device identifiers, notification text, running processes, device accounts, location and the installed-app inventory on a schedule/command, using a command protocol delimited by `===` with arguments separated by `~~~`. It collects device type, OS version and a unique device ID to fingerprint each phone (T1082), reports the full installed-app list to C2 (T1518), and can be tasked to capture photos and record video from the camera (T1125). The tasking loop drives repeated automated collection (T1119).
- **Why a hunt, not a rule:** These on-device behaviors are not exposed in standard enterprise telemetry — they surface only via MTD behavioral agents or static/dynamic APK analysis — so there is no reliable event stream to alert on, and any single capability (query installed apps, read device ID) is individually benign. The hunt value is stacking the capabilities on one masquerading package plus the FurBall tasking-protocol fingerprint, which is durable across repackaging where an API-name signature is not.

## Data sources required

- Mobile-threat-defense (MTD) behavioral telemetry (permission usage, camera/package-query API events)
- Static/dynamic APK analysis output (declared permissions, `QUERY_ALL_PACKAGES`, camera use, decompiled command protocol)
- MDM app-inventory (requested permissions per package)
- Network egress logs (POST bodies / periodic beacons carrying `===`/`~~~`-delimited data, where TLS-inspected)

## Query starting point

Platform: `Splunk SPL`

```
index=mtd OR index=apk_analysis
| eval pkg=lower(package_name)
| `comment("one package touching device-ID + installed-app query + camera together")`
| eval f_deviceid=if(match(api_calls,"(?i)(getDeviceId|ANDROID_ID|getImei|Build\.(MODEL|VERSION))"),1,0)
| eval f_applist=if(match(api_calls,"(?i)(getInstalledPackages|getInstalledApplications|QUERY_ALL_PACKAGES)"),1,0)
| eval f_camera=if(match(api_calls,"(?i)(Camera\.open|camera2|takePicture|MediaRecorder.*VIDEO)"),1,0)
| eval f_proto=if(match(strings,"(===|~~~)"),1,0)
| eval score=f_deviceid+f_applist+f_camera+f_proto
| where score>=3 AND install_source!="com.android.vending"
| stats values(app_label) as label sum(f_deviceid) as devid sum(f_applist) as applist
        sum(f_camera) as camera sum(f_proto) as proto dc(device_id) as devices by pkg
| sort - devices
```

## Triage guidance

- **Likely malicious:** A sideloaded, brand-impersonating package that enumerates all installed apps, reads persistent device identifiers, and holds camera capability, with FurBall's `===`/`~~~` command markers in strings or captured beacons; camera/video use with no user-facing camera function.
- **Likely benign:** Legitimate device-management, antivirus, or backup apps that enumerate installed packages under a declared purpose and are Play/MDM-signed; camera apps whose primary function is photography. Baseline sanctioned management tooling.
- **Pivot next:** Confirm via APK decompilation of the command protocol; correlate with HUNT-06 for the C2/exfil channel carrying the harvested data. If confirmed on a managed device, isolate and **escalate to incident-response**.

## References

- https://research.checkpoint.com/2021/domestic-kitten-an-inside-look-at-the-iranian-surveillance-operations/
- https://www.welivesecurity.com/2022/10/20/domestic-kitten-campaign-spying-iranian-citizens-furball-malware/
- https://attack.mitre.org/techniques/T1119/
- https://attack.mitre.org/techniques/T1082/
- https://attack.mitre.org/techniques/T1518/
- https://attack.mitre.org/techniques/T1125/
