# Hunt: Arid Viper — fake-persona / romance social-engineering staging the first install

- **Hypothesis:** If Arid Viper (APT-C-23) is working one of our people, the earliest tell is not on any endpoint — it is an *off-victim* attacker-run persona (an attractive/romance profile, or a "helpful" contact steering the target toward a chat/dating app) that opens a conversation on a third-party service and then hands over a "new messaging app" or "update." Because the group's entire initial-access model is social — build rapport as a persona, then deliver a trojanized Telegram clone or the Skipped/APP-UPGRADE romance app over the service, not over corporate email — the finding is the *pairing* of a brand/persona-monitoring hit (a fake profile impersonating our org, staff, or a lure identity contacting named employees) with a downstream weak endpoint/MDM signal (a sideloaded chat/dating APK, or DNS to a persona domain) on that same person's device. Either half alone is thin; the pair is the finding.
- **ATT&CK:**
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development) — attacker-run romance/persona profiles built to earn trust before delivery; this hunt keys on brand/persona-monitoring intel for those accounts.
  - T1566.003 — Phishing: Spearphishing via Service (initial-access) — the lure and the app are delivered over messaging/social services (off corporate email), so the hunt correlates service-side social intel with a device-side install signal.

- **Actor procedure:** Arid Viper creates and operates fake social-media personas — frequently attractive-persona / romance profiles — to build rapport with Arabic-speaking targets (government, military/security personnel, activists, journalists) before delivering weaponized apps. Per the SentinelLabs SpyC23 reporting, targets are coaxed over messaging/social services into installing trojanized chat/dating apps: fake Telegram clones and a romance-themed messenger called **Skipped** (internal name **APP-UPGRADE**) that carries SpyC23. The apps use a lengthy in-app permission walkthrough to talk the victim into granting excessive permissions after install. Meta's April 2021 takedown documented the same persona-driven tradecraft. The whole play happens on WhatsApp/Telegram/Facebook/dating platforms — never through the enterprise mail gateway.
- **Why a hunt, not a rule:** The persona creation and the over-service grooming (T1585.001 / T1566.003) are entirely off-victim — there is no enterprise log line to alert on, and a standalone rule would have nothing to fire against. What is *weakly* observable (an MDM-visible sideloaded dating/chat APK, DNS to a persona domain, a user report of a romance contact pushing an app) is individually benign — people install dating apps. The finding exists only in the analyst fusion of an external persona/brand-monitoring hit that names our staff or org against a device-side install on that same person, plus victimology fit (Arabic-speaking, targeted role). That correlation and judgement is hunt work. If a durable observable falls out — e.g., a specific persona-domain FQDN that MDM/proxy can match every time — hand *that* indicator to detection-engineering as a blocklist/analytic; do not try to alert on "a fake profile messaged someone."

## Data sources required

- External brand / executive / persona-monitoring intel: fake social profiles impersonating our org or staff, or lure identities contacting named employees over WhatsApp/Telegram/Facebook/dating apps (the off-victim half)
- MDM / mobile-threat-defense app inventory: sideloaded (non-store) chat/dating APKs on managed/BYOD devices, install-source = unknown/sideload, package names mimicking Telegram/"Skipped"/messengers
- Proxy / DNS (corporate + MDM tunnel): resolutions to persona-style hyphenated domains (see IOC list) from user devices
- User-reported social-engineering / suspicious-contact reports (awareness program intake)

## Query starting point

Platform: `KQL / Microsoft Sentinel + Intune (Defender for Endpoint/MDM)` — fuse a persona-monitoring watchlist with sideloaded chat/dating-app inventory on the same user

```kusto
// (a) External persona / brand-monitoring hits naming our people or org (ingested as a watchlist)
let personaIntel = _GetWatchlist('av_persona_monitoring')   // cols: TargetUPN, PersonaHandle, Platform, FirstSeen
    | project TargetUPN, PersonaHandle, Platform, FirstSeen;
// (b) Device-side install of a sideloaded chat/dating app (MDM app inventory)
let sideloadedApps = DeviceTvmSoftwareInventory
    | where SoftwareName has_any ("telegram","skipped","messenger","dating","chat","upgrade")
    | join kind=inner (DeviceInfo | where OSPlatform == "Android") on DeviceId
    | project DeviceId, DeviceName, SoftwareName, SoftwareVendor, LoggedOnUser = LoggedOnUsers;
// Correlate: same user is both being groomed by a persona AND carrying a sideloaded messenger
personaIntel
| join kind=inner (sideloadedApps) on $left.TargetUPN == $right.LoggedOnUser
| order by FirstSeen asc
```

## Triage guidance

- **Likely malicious:** a persona-monitoring hit naming a targeted-role employee (activist-adjacent, security, government-liaison, journalist) that time-correlates with that person sideloading a non-store Telegram clone or a "Skipped"/dating messenger, especially followed by DNS to a persona-style hyphenated domain; a lengthy in-app permission walkthrough reported by the user; package installed from an unknown source rather than Play Store.
- **Likely benign / expected:** staff legitimately use dating and third-party chat apps installed from the official store — store-sourced installs with normal permission prompts are noise; brand-monitoring false positives on look-alike-but-unrelated profiles; a persona hit with no corresponding device signal is intel to track, not a finding yet.
- **Pivot next:** if paired, pivot the device to HUNT-04 (Firebase/persona C2, audio capture, notification suppression) to confirm SpyC23 behavior, and preserve the persona profile + conversation as attribution intel for takedown. If SpyC23 behavior is confirmed on a managed device, this is a live compromise — escalate to incident-response-coordinator, isolate/wipe the device, and rotate any credentials (Facebook/corporate SSO) entered on it.

## References

- https://www.sentinelone.com/labs/arid-viper-apts-nest-of-spyc23-malware-continues-to-target-android-devices/
- https://blog.talosintelligence.com/arid-viper-mobile-spyware/
- https://attack.mitre.org/techniques/T1585/001/
- https://attack.mitre.org/techniques/T1566/003/
- https://attack.mitre.org/groups/G1028/
