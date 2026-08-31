# Hunt: WhatsApp-delivered APK lure and malicious app install with Accessibility abuse

- **Hypothesis:** If OilAlpha socially engineered a Yemen-focused staffer over WhatsApp into sideloading a spoofed humanitarian APK, then MDM/MTD/EMM telemetry will show a non-store (sideloaded) Android package install shortly after a shortened-link click, requesting an Accessibility service labelled "Google Services" plus camera/mic/SMS/contacts permissions — an unexpected-relationship anomaly (a "humanitarian/UN" app that is neither from the Play Store nor the real vendor, installed off a chat-app referrer) stacked with a never-before-seen package name.
- **ATT&CK:**
  - T1566.002 — Phishing: Spearphishing Link (initial-access)
  - T1204.002 — User Execution: Malicious File (execution)
- **Actor procedure:** OilAlpha engages targets directly over WhatsApp (often from Saudi Arabian phone numbers) and uses URL link shorteners to deliver links to malicious Android APKs disguised as UNICEF/UN/WFP/NRC/CARE/KSR apps. Observed files: `Cash Incentives.apk` / `المساعدات النقدية.apk`, `NRC Business.apk`, and a CARE-branded app. On launch the app prompts the victim in Arabic to enable an Accessibility service labelled "Google Services", granting the SpyNote/SpyMax RAT elevated control.
- **Why a hunt, not a rule:** The delivery and install happen off enterprise network telemetry, on personal/mobile handsets, and the lure text, sender number, shortener, and package name all rotate — so no static signature holds. The durable investigative pattern is the behavioral sequence (chat referrer → sideload of a brand-impersonating app → Accessibility grant) reconstructed from MDM/MTD logs plus user-reported lures, which needs analyst correlation and per-fleet baselining of what "normal" sideloading looks like, not an alert.

## Data sources required

- MDM / EMM / UEM app-inventory and install logs (package name, install source, signer, sideload flag) — Intune, Jamf, Workspace ONE, etc.
- Mobile Threat Defense (MTD) telemetry — Accessibility-service grants, non-Play install source, dangerous-permission grants
- User-reported phishing / abuse mailbox and helpdesk tickets (WhatsApp lures, shortened links)
- Web proxy / DNS where mobile traffic transits corporate network — URL-shortener resolution followed by APK content-type fetch

## Query starting point

Platform: `Splunk SPL`

```
index=mdm (sourcetype=intune_apps OR sourcetype=mtd_events)
| eval install_source=lower(coalesce(installSource,install_source,source))
| eval pkg=lower(coalesce(packageName,app_package,bundle_id))
| eval app_label=lower(coalesce(appName,app_label,display_name))
| where install_source!="play_store" AND install_source!="managed_store"
| where match(app_label,"(unicef|united nations|\bun\b|wfp|world food|refugee|\bnrc\b|care|king salman|\bksr\b|humanitarian|cash|incentive|مساعد)")
   OR match(pkg,"(care|nrc|ksr|unicef|wfp)")
| join type=left device_id [
    search index=mdm sourcetype=mtd_events (event="accessibility_service_enabled" OR permission="AccessibilityService")
    | eval svc_label=lower(coalesce(service_label,accessibility_label))
    | where match(svc_label,"google services")
    | stats values(svc_label) as accessibility_labels by device_id ]
| stats values(app_label) as apps values(pkg) as pkgs values(install_source) as sources
        values(accessibility_labels) as accessibility by device_id, user
| where isnotnull(accessibility) OR mvcount(pkgs)>0
```

## Triage guidance

- **Likely malicious:** A sideloaded (non-store) app impersonating UNICEF/UN/WFP/NRC/CARE/KSR that also enabled an Accessibility service named "Google Services"; install timestamp within minutes of a user-reported WhatsApp/shortened-link click; Arabic-titled "Cash Incentives"/"مساعدات" package; device then resolving a DDNS host (pivot to HUNT-04).
- **Likely benign / expected:** Legitimately signed vendor apps installed from the Play/managed store; internal enterprise line-of-business apps sideloaded through the sanctioned MDM channel; accessibility tools the user genuinely uses (screen readers) with real vendor signers. Baseline sanctioned sideload sources and known accessibility apps per fleet.
- **Pivot next:** Confirm the APK signer/SHA256 against the intel hashes; if the app is malicious, pull the device's egress DNS/flows and run HUNT-04 (C2/exfil) and HUNT-03 (collection permissions). Escalate to incident-response if the handset holds org credentials or synced mail, and route the confirmed lure sender/shortener to intel for infrastructure tracking (HUNT-02).

## References

- https://assets.recordedfuture.com/insikt-report-pdfs/2024/cta-2024-0709.pdf
- https://www.recordedfuture.com/research/oilalpha-likely-pro-houthi-group-targeting-arabian-peninsula
- https://thehackernews.com/2024/07/pro-houthi-group-targets-yemen-aid.html
- https://attack.mitre.org/techniques/T1566/002/
- https://attack.mitre.org/techniques/T1204/002/
