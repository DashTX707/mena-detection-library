# Hunt: Bahamut — masquerading via look-alike app package/name & portal identity reuse

- **Hypothesis:** If Bahamut has reached our mobile fleet, then because their *entire* delivery model is **masquerade-based — trojanized apps reusing the exact names, icons and package identities of real software** (SecureVPN, trojanized SoftVPN/OpenVPN at packages com.secure.vpn / com.openvpn.secure, and SafeChat/Safe_Chat.apk) — the MDM/mobile-EDR inventory will show an installed app that *matches a legitimate name/package but from the wrong source, signer, or store*. The falsifiable tell is a name/package/icon collision with a known-good app where the install source is not the official store (sideloaded), the signing certificate differs from the vendor's, or the package id is a near-twin of a real one. A matching app name alone is nothing; a matching name with a *mismatched signer or sideloaded origin* is the finding.
- **ATT&CK:**
  - T1036 — Masquerading (stealth) — fake VPN/chat apps, fake-news sites and personas, and impersonated login portals across the whole operation; hunt via mobile-app-vetting and brand monitoring.
  - T1036.005 — Masquerading: Match Legitimate Resource Name or Location (stealth) — trojanized apps reuse exact names/icons/package ids of real software (com.secure.vpn, com.openvpn.secure, SafeChat) so victims believe the install is genuine; hunt via MDM/app-reputation name-vs-signer/source mismatch.

- **Actor procedure:** Bahamut's trojanized Android apps are repackaged from legitimate SoftVPN/OpenVPN and presented as "SecureVPN" or "SafeChat," reusing the real apps' names, icons and package identifiers (com.secure.vpn, com.openvpn.secure) so the victim believes they installed a genuine privacy tool. The same masquerade logic drives the Windows/web side — fake-news sites posing as real outlets, personas posing as real journalists, and login portals impersonating real government/webmail services (covered operationally in HUNT-01). The defining property is a *property/path mismatch*: the surface identity is legitimate, but the origin, signer, or exact package string is not.
- **Why a hunt, not a rule:** A name/icon/package match to a legitimate app is, on its own, exactly what a *legitimate* install looks like — you cannot alert on "an app named SecureVPN exists" without burying the SOC in false positives from real VPN users. The finding lives in the *mismatch stack* (legitimate name/package AND non-store install source AND unexpected signer AND, ideally, aggressive Accessibility prompts from HUNT-06) evaluated against a known-good baseline — masquerading-primitive judgement that MDM inventory review and app-reputation vetting provide, not a single event. If a specific bad signer or package-hash is confirmed, hand *that* atomic to the detection pack's mobile-EDR blocklist; the name-vs-signer-mismatch *pattern* stays a hunt.

## Data sources required

- MDM / mobile-EDR app inventory: package name, install source (Play vs sideloaded), signing certificate/signer, app version, icon hash.
- Known-good app catalog / app-reputation service (to compare observed name+package against the legitimate vendor's signer and store presence).
- Managed-device population and at-risk-user mapping (executives, journalists, defense/finance BYOD in scope).

## Query starting point

Platform: `EDR / MDM (mobile app inventory — name/package match with signer or source mismatch)`

```kusto
// Mobile app inventory (Intune / mobile-EDR export)
MobileAppInventory
| where TimeGenerated > ago(30d)
| where PackageName in~ ("com.secure.vpn","com.openvpn.secure")          // known trojanized packages
    or AppDisplayName in~ ("SecureVPN","SafeChat","SoftVPN")
    or FileName =~ "Safe_Chat.apk"
| join kind=leftouter (
    // known-good catalog: legitimate signer + store presence per package
    GoodAppCatalog | project PackageName, GoodSigner = Signer, GoodStore = InstallSource
  ) on PackageName
// Flag the masquerade: legit-looking name/package BUT wrong source or wrong signer
| where InstallSource != "com.android.vending"                            // sideloaded, not Play
    or (isnotempty(GoodSigner) and Signer != GoodSigner)                  // signer mismatch
| project DeviceName, UserPrincipalName, AppDisplayName, PackageName,
          InstallSource, Signer, GoodSigner, AppVersion
| order by DeviceName asc
```
For fleets without MDM signer data, pivot to a network proxy: devices resolving thesecurevpn[.]com or the C2 domains (HUNT-02) are candidate installs to inspect manually.

## Triage guidance

- **Likely malicious:** an app named SecureVPN/SoftVPN/OpenVPN/SafeChat or package com.secure.vpn / com.openvpn.secure installed from a **non-Play source** or signed by a **certificate that is not the legitimate vendor's**; the same install on an at-risk user's device that also shows aggressive Accessibility prompts (HUNT-06) or beacons to a C2 domain (HUNT-02); a Safe_Chat.apk sideload.
- **Likely benign / expected:** the *genuine* SoftVPN/OpenVPN/SecureVPN from the Play Store with the vendor's real signer is legitimate — do not flag on name alone; enterprise-pushed VPN clients and internally-signed apps are expected (baseline your MDM's own signer); privacy-conscious staff install real VPNs. Source=Play + correct signer clears it.
- **Pivot next:** confirmed masqueraded install → HUNT-06 (accessibility keylogging/capture) and HUNT-07 (on-device collection) on the same device, MDM containment/wipe, and escalate to incident-response-coordinator; the individual is a confirmed target — treat their credentials/comms as compromised. Feed the bad signer/package-hash to the detection pack's mobile blocklist.

## References

- https://www.welivesecurity.com/2022/11/23/bahamut-cybermercenary-group-targets-android-users-fake-vpn-apps/
- https://www.cyfirma.com/research/apt-bahamut-targets-individuals-with-android-malware-using-spear-messaging/
- https://blogs.blackberry.com/en/2020/10/blackberry-uncovers-massive-hack-for-hire-group-targeting-governments-businesses-human-rights-groups-and-influential-individuals
- https://attack.mitre.org/techniques/T1036/
- https://attack.mitre.org/techniques/T1036/005/
