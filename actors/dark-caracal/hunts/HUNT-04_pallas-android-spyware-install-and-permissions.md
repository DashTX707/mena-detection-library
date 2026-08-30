# Hunt: Dark Caracal — Pallas Android spyware install via malicious link (mobile-threat-defense visibility gap)

- **Hypothesis:** Dark Caracal's Pallas implant reaches our people as a link-driven Android app install — a user taps a link (from the fake secure-messaging site or a WhatsApp/Facebook lure) and sideloads a trojanized "secure messenger" that then requests a surveillance-grade permission set (SMS, contacts, call log, location, microphone, camera, storage) and beacons over plain HTTP. If Pallas is on an enrolled device, then the tell is a sideloaded app (installed from an unknown source, not Google Play) impersonating WhatsApp/Signal/Telegram/Primo, holding far more permissions than its stated function needs, and talking to a Dark Caracal C2/HTTP endpoint. **This hunt is framed around a visibility gap first:** if we have no mobile-threat-defense (MTD) / MDM telemetry on the devices high-risk staff actually use for messaging, then "we cannot see this" is itself the primary finding and must be reported as an actionable coverage gap, not a clean result.
- **ATT&CK:**
  - T1204.001 — User Execution: Malicious Link (execution) — the target taps a link that downloads/installs the trojanized Pallas app; hunt via MTD sideload telemetry and web-filter link click-through on enrolled devices

- **Actor procedure:** Targets are induced to click links — from the watering-hole site and from social-engineering messages — that download and install trojanized Pallas Android apps impersonating popular secure-messaging and utility apps. Once installed, Pallas harvests locally stored PII (SMS, call logs, contacts, stored photos), tracks location, and records ambient audio and camera, exfiltrating over HTTP to actor infrastructure. The operation deliberately targets individuals (activists, journalists, lawyers, military/defense personnel) on their personal/mobile devices, which typically sit outside enterprise endpoint monitoring.
- **Why a hunt, not a rule:** Android surveillanceware on personal or lightly-managed phones sits almost entirely outside enterprise telemetry — there is usually no log to write an alert against, which is exactly why it is a hunt (and why the visibility gap itself is a first-class finding). Even where MTD/MDM exists, "a sideloaded app" and "an app with many permissions" are individually far too common to alert on; the signal is the *stack* — sideloaded (non-Play source) + messaging-brand impersonation + over-broad permission set + HTTP beacon to actor infra. Assembling and judging that stack, and reasoning about coverage on devices you may not fully control, is hunt work. A confirmed Pallas package name / signing cert / C2 endpoint can be handed to detection-engineering as an MTD blocklist entry.

## Data sources required

- Mobile-threat-defense (Lookout / Zimperium / Defender for Endpoint mobile) and MDM/UEM (Intune) app inventory: installed packages, install source (Play vs unknown/sideload), requested permissions, signer
- Enrolled-device web-filter / DNS (mobile): link click-through to APK/download URLs and beacons to Dark Caracal C2 domains (`ntsclouds.com`, `jtoolbox.org`, `mainsrv.top`, `olex.live`, etc.)
- **Coverage map (the visibility-gap input):** which staff use enrolled vs BYOD/unmanaged devices for messaging; where MTD is/ isn't deployed — needed to distinguish "clean" from "blind"
- User-report channel (shared with HUNT-03)

## Query starting point

Platform: `KQL / Microsoft Intune + Defender for Endpoint (mobile)` — surface sideloaded messaging-brand look-alikes with surveillance permission sets on enrolled Android devices.

```kusto
// Enrolled-Android app inventory (MDM/MTD). Adjust table/columns to your connector schema.
DeviceTvmSoftwareInventory
| where DeviceType == "Android" or OSPlatform startswith "Android"
| extend app = tolower(SoftwareName)
| where app has_any ("whatsapp","signal","telegram","primo","messenger","securechat")
// impersonation discriminator: installed from a non-Play source (sideload)
| where InstallSource !in~ ("com.android.vending","Google Play")
| join kind=leftouter (
    // permission / signer detail from MTD connector
    MobileAppPermissions
    | summarize perms = make_set(Permission) by DeviceId, PackageName
  ) on $left.DeviceId == $right.DeviceId
| extend surveillancePerms = set_intersect(perms, dynamic(
    ["READ_SMS","RECEIVE_SMS","READ_CONTACTS","READ_CALL_LOG","ACCESS_FINE_LOCATION",
     "RECORD_AUDIO","CAMERA","READ_EXTERNAL_STORAGE"]))
| extend surveillanceScore = array_length(surveillancePerms)
| where surveillanceScore >= 4          // messaging-brand look-alike hoarding surveillance perms
| project DeviceName, app, PackageName, InstallSource, Signer, surveillancePerms, surveillanceScore
| order by surveillanceScore desc
```

## Triage guidance

- **Likely malicious:** a sideloaded app impersonating WhatsApp/Signal/Telegram/Primo on an enrolled device, holding SMS+contacts+call-log+location+mic+camera permissions and installed from an unknown source; that device beaconing over HTTP to a Dark Caracal C2 domain; install timing that lines up with a HUNT-03 social-lure or watering-hole hit for the same user.
- **Likely benign / expected:** the genuine apps from Google Play (correct signer, Play install source); enterprise-sanctioned MDM-pushed apps; legitimate apps that reasonably need some of these permissions (a real messenger does use contacts/mic/camera) — the discriminators are *sideload source* + *brand impersonation* + *no Play provenance*, not the permission set alone.
- **Pivot next:** **if MTD/MDM coverage does not exist for the devices high-risk staff use, report the visibility gap as the finding** — recommend deploying MTD to those users and route the coverage requirement appropriately; this is an actionable result even with zero detections. On a confirmed Pallas install: isolate/wipe the device, preserve the APK for the sample-clustering hunt (HUNT-01), extract its C2 and add to blocklists, notify the affected individual (their SMS/contacts/audio/location are likely already exfiltrated), and escalate to incident-response-coordinator.

## References

- https://www.lookout.com/documents/reports/lookout-dark-caracal-20180118-us.pdf
- https://www.eff.org/deeplinks/2020/12/dark-caracal-you-missed-spot
- https://attack.mitre.org/groups/G0070/
- https://attack.mitre.org/techniques/T1204/001/
