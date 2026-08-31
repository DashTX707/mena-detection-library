# Hunt: On-device surveillance permissions granted to spoofed humanitarian apps

- **Hypothesis:** If a SpyNote/SpyMax RAT is live on a managed handset, then MTD/MDM permission telemetry will show a single non-store app that has been granted the full surveillance permission stack at once — camera, microphone, SMS read, contacts read, and external-storage read — an excessive-permission / path-property-mismatch anomaly where a supposed "humanitarian aid" or "cash incentive" app holds capabilities no such app needs, correlated with an enabled Accessibility service.
- **ATT&CK:**
  - T1125 — Video Capture (collection)
  - T1123 — Audio Capture (collection)
  - T1005 — Data from Local System (collection)
- **Actor procedure:** OilAlpha's SpyNote/SpyMax Android apps request excessive permissions during execution — camera (covert video/image capture), microphone (ambient audio and call recording), and SMS / contacts / WiFi-state / external-storage read-write (harvesting messages, contact lists and stored files) — all bundled into one spoofed UNICEF/UN/WFP/NRC/CARE/KSR application for surveillance of Yemen-focused humanitarian, media and government targets.
- **Why a hunt, not a rule:** These permission grants are observable only on-device via MTD/MDM and never touch server or network logs; individually, camera or contacts access is normal for countless legitimate apps, so a per-permission alert drowns in false positives. The durable hunt is the *combination on one anomalous app* — the whole surveillance stack held by a sideloaded, brand-impersonating package — which requires analyst correlation of the permission set against the app's claimed purpose and install provenance, not a single-condition rule.

## Data sources required

- Mobile Threat Defense (MTD) permission-audit telemetry (per-app granted permissions, runtime permission grants)
- MDM / EMM app inventory (package name, signer, install source, app category)
- Accessibility-service enablement logs (correlate with HUNT-01)
- Android app-ops / permission-usage logs where forwarded to SIEM

## Query starting point

Platform: `Splunk SPL`

```
index=mdm sourcetype=mtd_permissions
| eval pkg=lower(coalesce(packageName,app_package))
| eval app_label=lower(coalesce(appName,app_label))
| eval perm=lower(permission)
| eval is_cam=if(match(perm,"camera"),1,0)
| eval is_mic=if(match(perm,"record_audio|microphone"),1,0)
| eval is_sms=if(match(perm,"read_sms|receive_sms|read_mms"),1,0)
| eval is_contacts=if(match(perm,"read_contacts|get_accounts"),1,0)
| eval is_storage=if(match(perm,"read_external_storage|write_external_storage|manage_external_storage"),1,0)
| stats max(is_cam) as cam max(is_mic) as mic max(is_sms) as sms
        max(is_contacts) as contacts max(is_storage) as storage
        values(app_label) as label values(install_source) as src
        by device_id, user, pkg
| eval surveillance_score=cam+mic+sms+contacts+storage
| where surveillance_score>=4 AND src!="play_store" AND src!="managed_store"
| where NOT match(pkg,"(com\.whatsapp|com\.android|com\.google|com\.microsoft|com\.samsung)")
| sort - surveillance_score
```

## Triage guidance

- **Likely malicious:** A sideloaded, brand-impersonating app holding 4-5 of {camera, mic, SMS, contacts, storage} whose claimed purpose (aid/cash/UN) doesn't justify them; same package also holds an Accessibility grant (HUNT-01) or beacons to a DDNS host (HUNT-04); package signer is self-signed/unknown.
- **Likely benign / expected:** Mainstream messengers/social apps (WhatsApp, Signal, Telegram, Teams) that legitimately hold camera+mic+contacts from the official store; enterprise MDM agents; a genuine vendor app from a trusted signer. Baseline the known good store apps that hold the full stack per fleet and suppress them.
- **Pivot next:** For a flagged app, confirm signer/hash against intel and check whether the surveillance permissions were actively *used* (app-ops usage records) — active camera/mic invocation by a spoofed app is a confirmed surveillance finding: escalate to incident-response. Then run HUNT-04 to catch the exfiltration leg to C2.

## References

- https://assets.recordedfuture.com/insikt-report-pdfs/2024/cta-2024-0709.pdf
- https://therecord.media/pro-houthi-hackers-yemen-spyware-middle-east-militaries
- https://attack.mitre.org/techniques/T1125/
- https://attack.mitre.org/techniques/T1123/
- https://attack.mitre.org/techniques/T1005/
