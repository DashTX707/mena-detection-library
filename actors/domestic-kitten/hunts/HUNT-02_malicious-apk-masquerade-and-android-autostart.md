# Hunt: Sideloaded FurBall APKs — masqueraded package identities and boot-persistence

- **Hypothesis:** If FurBall reached a managed Android device, then the MDM/mobile-threat-defense app inventory will show a sideloaded (non-Play, unknown-installer) package whose name/label/certificate impersonates a legitimate app (masquerading + path/property-mismatch anomaly) and that requests a `RECEIVE_BOOT_COMPLETED` autostart receiver, letting the surveillanceware relaunch on every power-on.
- **ATT&CK:**
  - T1204.002 — User Execution: Malicious File (execution)
  - T1036.005 — Masquerading: Match Legitimate Resource Name or Location (defense-evasion)
  - T1547 — Boot or Logon Autostart Execution (persistence)
- **Actor procedure:** FurBall is repackaged inside, or made to imitate, a fake VIPRE Mobile Security app, the ISIS "Amaq" news app, an "Islamic Caliphate" app, a repackaged "Exotic Flowers" game, a MyKet-mimic store (`ir.mservices.market`), and a "Mohsen Restaurant" app; observed package names include `com.getdoc.freepaaper.dissertation`, `com.ssd.vipre`, `com.apps.amaq`. Infection requires the victim to sideload the APK behind a fake Google Play button. FurBall registers a `BOOT_COMPLETED` broadcast receiver for persistent relaunch.
- **Why a hunt, not a rule:** Install events on personal/BYOD devices are largely invisible to enterprise telemetry and the operators rotate package names, labels, and signing certs per campaign, so a package-name denylist is brittle IOC matching. The durable hunt is the property stack — sideloaded origin + installer-not-Play + label/cert mismatch + boot-autostart request — evaluated against the managed fleet's app-inventory baseline, which survives repackaging. Where MDM app-inventory is complete and the property stack is stable, the "sideloaded + boot-receiver + brand-mismatch" combination can graduate to a detection.

## Data sources required

- MDM / EMM app-inventory export (package name, app label, signer cert, install source, requested permissions/receivers)
- Mobile-threat-defense (MTD) agent telemetry (APK reputation, sideload flag)
- Google Play / managed-store allowlist (to separate sanctioned installs)
- Static APK analysis queue (for confirmation of `BOOT_COMPLETED` receiver)

## Query starting point

Platform: `Splunk SPL`

```
index=mdm sourcetype=app_inventory
| eval label=lower(app_label), pkg=lower(package_name)
| `comment("sideloaded, non-Play installer, brand-impersonating label, boot autostart")`
| where install_source!="com.android.vending"
   AND (like(receivers,"%BOOT_COMPLETED%") OR like(permissions,"%RECEIVE_BOOT_COMPLETED%"))
| eval brand_mismatch=if(
      (like(label,"%vipre%") OR like(label,"%amaq%") OR like(label,"%caliphate%")
       OR like(label,"%myket%") OR like(label,"%market%") OR like(label,"%vpn%")
       OR like(label,"%translate%") OR like(label,"%restaurant%") OR like(label,"%poetry%"))
      AND NOT match(signer_cert,"(?i)(google|verified_vendor_cert_thumbprints)"),1,0)
| where brand_mismatch=1 OR install_source="unknown" OR sideloaded=1
| stats values(pkg) as packages values(signer_cert) as certs
        values(permissions) as perms dc(device_id) as devices by label, install_source
| sort - devices
```

## Triage guidance

- **Likely malicious:** Sideloaded package with a boot-completed receiver whose label impersonates a security/news/store/VPN/restaurant app but whose signer cert is unknown/self-signed; requests SMS/contacts/mic/camera permissions disproportionate to its stated function; installer is a browser or file manager, not Play.
- **Likely benign:** Enterprise-signed internal apps distributed via MDM with a legitimate boot receiver (push/VoIP/MDM agents); known regional stores explicitly sanctioned by policy. Baseline the sanctioned sideload set first.
- **Pivot next:** Pull the APK for static analysis to confirm the FurBall command protocol (`===` / `~~~` delimiters, ~10s beacon). If confirmed on a managed device, isolate it and **escalate to incident-response**; pivot to HUNT-06 for the device's C2/exfil egress and HUNT-03 for its collection behavior.

## References

- https://research.checkpoint.com/2021/domestic-kitten-an-inside-look-at-the-iranian-surveillance-operations/
- https://www.welivesecurity.com/2022/10/20/domestic-kitten-campaign-spying-iranian-citizens-furball-malware/
- https://attack.mitre.org/techniques/T1204/002/
- https://attack.mitre.org/techniques/T1036/005/
- https://attack.mitre.org/techniques/T1547/
