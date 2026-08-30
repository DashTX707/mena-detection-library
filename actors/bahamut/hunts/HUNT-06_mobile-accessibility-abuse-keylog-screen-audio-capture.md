# Hunt: Bahamut — Android Accessibility-Services abuse (keylogging, screen & audio capture)

- **Hypothesis:** If Bahamut's Android spyware is live on an at-risk user's device, then because it **defeats end-to-end encryption at the input/display layer by abusing Accessibility Services** — plus records calls — the MDM/mobile-EDR tell is a **recently-installed, sideloaded app that repeatedly prompts for and holds an Accessibility Service binding, a battery-optimization exemption, and microphone/phone permissions it has no legitimate reason for, immediately after install**. A VPN or "chat" app that binds Accessibility Services and requests call-recording permission is a property mismatch: neither function needs to read every screen or keystroke. A single permission grant is normal; the *stack* — Accessibility + battery-exemption + mic/phone on a just-sideloaded app — is the finding.
- **ATT&CK:**
  - T1056.001 — Input Capture: Keylogging (credential-access) — Accessibility Services capture on-screen text and keystrokes in Signal/WhatsApp/Telegram/Viber/Messenger/WeChat/imo/Conion, defeating E2E encryption at the input layer; hunt via MDM accessibility-grant monitoring.
  - T1113 — Screen Capture (collection) — Accessibility Services scrape the content rendered on screen (messages in target chat apps); hunt via mobile EDR.
  - T1123 — Audio Capture (collection) — the spyware records phone calls and exfiltrates the audio; hunt via mobile EDR and microphone/phone-permission auditing.

- **Actor procedure:** After the victim installs the trojanized VPN (SecureVPN) or chat app (SafeChat/CoverIm) and the operator's activation key unlocks functionality, the spyware repeatedly prompts for Android Accessibility Services and a battery-optimization exemption (to survive backgrounding). With the Accessibility binding it keylogs and screen-scrapes messages from Signal, WhatsApp, Telegram, Viber, Facebook Messenger, WeChat, imo and Conion — reading the plaintext at the moment of input/display and thereby bypassing the apps' end-to-end encryption — and it records phone calls, sending the audio to C2. This is the espionage payload's core: the Accessibility grant is the single most load-bearing permission.
- **Why a hunt, not a rule:** Accessibility Services are a legitimate, heavily-used accessibility feature — screen readers, password managers, automation and keyboard apps all bind them — so a naive "Accessibility granted" alert is unworkably noisy and this signal is invisible to *enterprise* telemetry entirely without mobile EDR/MDM (a visibility gap for BYOD/unmanaged devices). The finding is the *correlation* of an anomalous grant with a suspicious install profile (sideloaded, VPN/chat app, recent, aggressive re-prompting, plus mic/phone permission) on an at-risk user — human judgement across MDM permission and inventory data. If a specific package repeatedly appears with this permission stack, hand the package/signer atomic to the detection pack; the permission-stack heuristic stays a hunt.
- **VISIBILITY-GAP NOTE:** Devices **without** MDM/mobile-EDR (BYOD, personal phones of at-risk staff) yield **no telemetry** — an acknowledged blind spot. Treat "at-risk individual on an unmanaged device" as an actionable coverage finding: enroll into MDM or provide managed devices and awareness, rather than assuming clean.

## Data sources required

- MDM / mobile-EDR permission telemetry: Accessibility Service bindings, battery-optimization exemptions, microphone/phone/record-audio grants, per app, with grant timestamps.
- Mobile app inventory + install source & signer (shared with HUNT-05) to tie the grant to a sideloaded masqueraded app.
- Mobile network telemetry (where available): egress to C2 domains (ft8hua063okwfdcu21pw[.]de, laborer-posted[.]nl) / non-standard port 2053 (cross-ref detection pack T1571/T1071.001).
- At-risk-user → device mapping.

## Query starting point

Platform: `EDR / MDM (mobile permission events — accessibility + battery-exemption + mic on a fresh sideloaded app)`

```kusto
MobilePermissionEvents
| where TimeGenerated > ago(30d)
| where PermissionName in~ ("BIND_ACCESSIBILITY_SERVICE","REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
        "RECORD_AUDIO","READ_PHONE_STATE","PROCESS_OUTGOING_CALLS")
| summarize perms = make_set(PermissionName, 10), grantTimes = make_set(TimeGenerated, 10),
            firstGrant = min(TimeGenerated)
        by DeviceName, UserPrincipalName, PackageName, AppDisplayName
// The tell: a single app holding Accessibility AND battery-exemption AND an audio/phone permission
| where set_has_element(perms, "BIND_ACCESSIBILITY_SERVICE")
    and set_has_element(perms, "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS")
    and (set_has_element(perms,"RECORD_AUDIO") or set_has_element(perms,"PROCESS_OUTGOING_CALLS"))
| join kind=leftouter (
    MobileAppInventory | project PackageName, InstallSource, Signer, InstalledAt = TimeGenerated
  ) on PackageName
| where InstallSource != "com.android.vending"                    // sideloaded
    and firstGrant - InstalledAt < 2h                             // grants right after install
| project DeviceName, UserPrincipalName, AppDisplayName, PackageName, perms, InstallSource, Signer
```

## Triage guidance

- **Likely malicious:** a sideloaded VPN/chat app that binds Accessibility Services *and* holds a battery-exemption *and* record-audio/phone permission, granted minutes after install, on an at-risk user's device — especially the known packages com.secure.vpn / com.openvpn.secure / Safe_Chat.apk (HUNT-05) or one beaconing to a C2 domain; repeated re-prompting for Accessibility after the user declined.
- **Likely benign / expected:** password managers, screen readers (TalkBack), automation apps (Tasker), keyboard apps and legitimate call-recorder apps use Accessibility and/or mic permissions by design — baseline the known-good set per fleet and exclude Play-store apps with correct signers; a VPN app requesting *only* VPN permission from Play is fine. Accessibility alone, or a Play-store app with the vendor's signer, clears it.
- **Pivot next:** confirmed Accessibility-abusing spyware → this is a live compromise of the individual: escalate to incident-response-coordinator immediately, MDM-isolate/wipe the device, treat all messaging (Signal/WhatsApp/Telegram/etc.), SMS, calls and credentials entered on that device as compromised and force credential rotation, and pivot to HUNT-07 (what was collected) and HUNT-02 (C2). Preserve the APK/signer as attribution intel.

## References

- https://www.welivesecurity.com/2022/11/23/bahamut-cybermercenary-group-targets-android-users-fake-vpn-apps/
- https://www.cyfirma.com/research/apt-bahamut-targets-individuals-with-android-malware-using-spear-messaging/
- https://attack.mitre.org/techniques/T1056/001/
- https://attack.mitre.org/techniques/T1113/
- https://attack.mitre.org/techniques/T1123/
