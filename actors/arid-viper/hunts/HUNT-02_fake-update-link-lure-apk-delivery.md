# Hunt: Arid Viper — fake-update link lures and the APK download that follows the click

- **Hypothesis:** If a target has been steered to a "download the update" link, the observable is not the click (that happens on YouTube or in a chat, off our estate) but the *retrieval*: a device resolving and hitting a persona-style hyphenated domain and pulling an `.apk` from a download path like `/abc/Update Services.apk`, `/download/<token>`, or `signal.apk` — files a legitimate app store never serves. Because Arid Viper distributes malicious APKs disguised as WhatsApp/Messenger/Instagram/Google Play/Signal updates, advertised through Arabic-language (Levantine-dialect) YouTube tutorial videos that point at attacker-hosted download URLs, the hunt looks for the *download event* to an actor-owned persona domain and the subsequent sideload on the same device — the endpoint tell of the click, not the click itself.
- **ATT&CK:**
  - T1566.002 — Phishing: Spearphishing Link (initial-access) — update-lure links (WhatsApp/Signal/Instagram "updates") pushed via YouTube tutorials and chats; hunt targets the resolution/fetch of those links.
  - T1204.001 — User Execution: Malicious Link (execution) — the victim clicking the attacker link initiates payload retrieval; the weak on-victim signal is proxy/DNS to the persona domain.
  - T1608.001 — Stage Capabilities: Upload Malware (resource-development) — payloads are staged on actor domains at specific download paths; hunt matches web telemetry against those known staging URLs.

- **Actor procedure:** Per Cisco Talos, Arid Viper disguised mobile spyware as updates for legitimate Android apps and distributed APK links via Arabic-language YouTube tutorial videos with Levantine-dialect narration. Payloads are staged on the group's own domains at fixed paths — e.g. `hxxps://orin-weimann[.]com/abc/Update%20Services.apk`, `hxxps://orin-weimann[.]com/abc/signal.apk`, `hxxps://jack-keys[.]site/download/okOqphD` — with the infrastructure managed via ALFA TEaM webshells. The victim, believing they are updating WhatsApp/Signal/Instagram/Messenger/Google Play, clicks through to the actor domain and downloads the trojanized APK, which then runs its permission walkthrough (see HUNT-01) and beacons to Firebase/persona C2 (HUNT-04).
- **Why a hunt, not a rule:** The link delivery and the click (T1566.002 / T1204.001) live on YouTube and in chat apps — off the defended endpoint — so there is nothing native to alert on. The one weak on-victim signal, a DNS/proxy hit to a persona domain or an APK GET to a staging path, is only high-confidence when matched against the *current* actor infrastructure, which rotates; a static rule on a stale domain list decays fast and a generic "downloaded an APK" rule is pure noise on BYOD. The hunt is the periodic re-matching of live persona-domain intel against web/DNS telemetry plus the sideload correlation — pivot-and-judge work. Durable, still-live persona FQDNs and staging paths that survive triage should be handed to detection-engineering as a proxy/DNS blocklist and an MDM install-source analytic; the hunt is where you decide which ones are worth that.

## Data sources required

- Web proxy / TLS SNI / DNS logs (corporate + MDM tunnel): GETs for `*.apk`, resolutions to persona-style hyphenated domains and their download paths
- MDM / mobile-threat-defense: app installs with install-source = sideload/unknown, package labelled as WhatsApp/Signal/Instagram/Messenger/Google Play but not store-signed
- Threat-intel: current Arid Viper persona-domain and staging-URL list (decays — refresh before each run)
- Optional: DFIR/OSINT sweep of Arabic-language YouTube tutorial videos linking to APK downloads (off-victim corroboration)

## Query starting point

Platform: `Splunk SPL` — APK retrievals to persona-style hyphenated domains, then joined to sideload installs

```spl
index=proxy OR index=dns sourcetype IN ("proxy","dns")
| eval url=coalesce(url,query)
(url="*.apk" OR uri_path IN ("/abc/*","/download/*"))
``` match persona-domain shape: first-last hyphenated across odd TLDs ```
| rex field=dest_host "^(?<p1>[a-z]+)-(?<p2>[a-z]+)\.(?<tld>in|com|site|info|icu|club|live|tech|life|firm\.in)$"
| where isnotnull(p1) OR dest_host IN ("luis-dubuque.in","orin-weimann.com","jack-keys.site","elizabeth-steiner.tech","baldwin-gonzalez.live","grace-fraser.site")
| stats count values(url) as urls values(dest_host) as hosts min(_time) as firstSeen by src_ip user
| join type=left user
    [ search index=mdm sourcetype=intune_apps install_source!="play_store" app_name IN ("WhatsApp*","Signal*","Instagram*","Messenger*","Google Play*")
      | stats values(app_name) as sideloaded_apps by user ]
| where isnotnull(sideloaded_apps) OR count > 0
| sort - firstSeen
```

## Triage guidance

- **Likely malicious:** an `.apk` GET to a first-last hyphenated persona domain on an odd TLD (`.in/.site/.icu/.club/.tech/.life`) at a `/abc/` or `/download/<token>` path, from a targeted-role user's device, followed by a sideloaded "update" of WhatsApp/Signal/Instagram not sourced from the Play Store; a referrer/history trail from a YouTube tutorial to the download.
- **Likely benign / expected:** developers and testers pulling legitimate APKs from known distribution (APKMirror, F-Droid, internal MDM) — baseline those hosts; store-sourced app updates; a hyphenated-domain hit that resolves to a real business with matching WHOIS/age (persona domains are young, privacy-protected, thin — see HUNT-03).
- **Pivot next:** enrich any matched domain via HUNT-03 (registration pattern, hosting, ALFA TEaM webshell fingerprint) to confirm it is actor infrastructure, and pivot the device to HUNT-04 for SpyC23 C2/collection behavior. Confirmed sideload of a trojanized update on a managed device is a live compromise — escalate to incident-response-coordinator.

## References

- https://blog.talosintelligence.com/arid-viper-mobile-spyware/
- https://www.sentinelone.com/labs/arid-viper-apts-nest-of-spyc23-malware-continues-to-target-android-devices/
- https://attack.mitre.org/techniques/T1566/002/
- https://attack.mitre.org/techniques/T1204/001/
- https://attack.mitre.org/techniques/T1608/001/
