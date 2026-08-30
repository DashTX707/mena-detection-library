# Hunt: Arid Viper — SpyC23 on Android: Firebase C2, call/ambient audio capture, and OEM notification suppression (mobile visibility gap)

- **Hypothesis:** If SpyC23 is running on a managed or BYOD Android device, the on-device behavior is deliberately camouflaged — Firebase Cloud Messaging C2 that blends with legitimate Google traffic, call/ambient audio recording, and suppression of the OEM's own security notifications so the user never sees the warning. Because enterprise logging is nearly blind to all three, the hypothesis is really a *visibility-gap* statement: we cannot see this today, and the hunt's first job is to prove where the blind spots are and stand up MTD/permission-audit telemetry, then correlate what little we can see (an app holding RECORD_AUDIO + notification-listener/accessibility + battery-optimization-exempt, beaconing to an attacker Firebase project or persona secondary C2) into a finding.
- **ATT&CK:**
  - T1102 — Web Service (command-and-control) — SpyC23 uses Google Firebase (skippedtestinapp.firebaseio.com) as primary FCM C2 with persona domains as secondary, and can be handed new C2 domains to rotate.
  - T1123 — Audio Capture (collection) — CallRecService records calls via libcallrecfix.so and a checkRaw service captures ambient microphone audio.
  - T1685 — Disable or Modify Tools (defense-impairment) — suppresses security notifications on Samsung/Huawei/Google/Oppo/Xiaomi devices to hide its own activity/permissions.

- **Actor procedure:** SpyC23 (S1195) uses **Google Firebase Cloud Messaging** as its primary C2 channel — e.g. `skippedtestinapp.firebaseio.com`, `lightroom-61eb2.firebaseio.com`, and Appspot projects `jolia-16e7b.appspot.com` / `yellwo-473d0.appspot.com` / `rashonal.appspot.com` — with attacker persona domains as secondary C2, and it can receive an updated C2 domain from the current C2 to switch infrastructure. It records calls via a **CallRecService** backed by the `libcallrecfix.so` native library and captures ambient audio through a **checkRaw** service, and it monitors screen content via accessibility services. Per Cisco Talos, it **disables security notifications** on Samsung, Huawei, Google, Oppo and Xiaomi devices so the victim isn't warned about its permissions or activity. Data (audio, SMS, call logs, contacts, Facebook credentials, device fingerprints, documents) is exfiltrated back over the same channel.
- **Why a hunt, not a rule:** Firebase C2 rides `*.firebaseio.com` / `*.appspot.com` — infrastructure millions of benign apps use — so a network rule on "traffic to Firebase" is unactionable; the malicious signal is the *specific attacker project ID*, which rotates and is only knowable from sample analysis. Call recording, ambient capture and OEM-notification suppression happen inside Android's app sandbox and emit no enterprise log at all — there is literally nothing to alert on without an MTD/EDR-for-mobile agent, and even then the tells (a dangerous permission combination, a notification-listener grant) are individually legitimate. The finding is the correlated permission-and-beacon profile on one app, judged against victimology — hunt work. The durable, hand-off-worthy output is (a) a documented visibility-gap finding driving MTD deployment, and (b) confirmed attacker Firebase project IDs and persona secondary-C2 FQDNs routed to detection-engineering as blocklist/analytic content.
- **Visibility-gap finding (state it explicitly):** in an estate with no mobile-threat-defense agent, T1123 and T1685 are *unobservable* and T1102 is observable only as undifferentiated Google traffic. "We cannot see this" is itself the primary result of this hunt on day one — it is an actionable gap, not a clean bill of health.

## Data sources required

- Mobile-threat-defense / EDR-for-mobile (Defender for Endpoint on Android, Lookout, Zimperium): app permission inventory, notification-listener/accessibility grants, network connections per app
- MDM (Intune) app inventory + permission report: apps holding RECORD_AUDIO, READ_PHONE_STATE, BIND_NOTIFICATION_LISTENER_SERVICE, accessibility service, battery-optimization exemption
- Network egress from the MDM/VPN tunnel: connections to `*.firebaseio.com` / `*.appspot.com` project endpoints and persona secondary domains, correlated to app
- Threat-intel: current attacker Firebase/Appspot project IDs and persona C2 list

## Query starting point

Platform: `KQL / Microsoft Defender for Endpoint (Android) + Sentinel` — apps stacking a spyware-shaped permission profile with beacons to attacker cloud C2

```kusto
// (a) Android apps holding the SpyC23-shaped dangerous-permission combo
let riskyApps = DeviceInfo
    | where OSPlatform == "Android"
    | join kind=inner (DeviceTvmSoftwareVulnerabilities
        | extend perms = tostring(AdditionalFields.RequestedPermissions)) on DeviceId
    | where perms has "RECORD_AUDIO"
        and (perms has "BIND_NOTIFICATION_LISTENER" or perms has "BIND_ACCESSIBILITY_SERVICE")
        and (perms has "READ_SMS" or perms has "READ_CONTACTS" or perms has "READ_CALL_LOG")
    | project DeviceId, DeviceName, AppName = SoftwareName, perms;
// (b) Egress to attacker cloud C2 projects or persona secondary domains, per device
let c2 = DeviceNetworkEvents
    | where RemoteUrl has_any (
        "skippedtestinapp.firebaseio.com","lightroom-61eb2.firebaseio.com",
        "jolia-16e7b.appspot.com","yellwo-473d0.appspot.com","rashonal.appspot.com")
        or RemoteUrl matches regex @"^[a-z]+-[a-z]+\.(site|icu|club|live|tech|life|info)$"
    | summarize beacons = count(), urls = make_set(RemoteUrl, 10) by DeviceId;
riskyApps
| join kind=inner (c2) on DeviceId          // permission profile AND attacker-C2 beacon on the same device
| order by beacons desc
```

## Triage guidance

- **Likely malicious:** an app holding RECORD_AUDIO + notification-listener/accessibility + SMS/contacts/call-log that also beacons to a named attacker Firebase/Appspot project or a persona secondary domain; a device whose OEM security notifications were silently disabled for a recently sideloaded app; call-recording behavior on a device belonging to a targeted-role user.
- **Likely benign / expected:** legitimate call-recorder apps, dialers, accessibility tools for disabled users, and messengers all hold subsets of these permissions and talk to Firebase — the combination *plus* attacker-owned project/domain is what discriminates; generic `*.firebaseio.com` traffic is normal and must not be flagged alone.
- **Pivot next:** if no MTD telemetry exists, the finding is the gap — recommend MTD/permission-audit deployment and re-run. If SpyC23 behavior is confirmed on a managed device, this is a live compromise: escalate to incident-response-coordinator, isolate/wipe, extract the sample to confirm current C2 project IDs (feed back to HUNT-03), rotate Facebook/SSO credentials entered on the device, and route confirmed project IDs/persona FQDNs to detection-engineering.

## References

- https://blog.talosintelligence.com/arid-viper-mobile-spyware/
- https://www.sentinelone.com/labs/arid-viper-apts-nest-of-spyc23-malware-continues-to-target-android-devices/
- https://attack.mitre.org/techniques/T1102/
- https://attack.mitre.org/techniques/T1123/
- https://attack.mitre.org/techniques/T1685/
- https://attack.mitre.org/software/S1195/
