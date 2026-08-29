# Hunt: WIRTE geo-gating & sandbox evasion — the oref.org.il connectivity check + Hebrew-locale trigger as SameCoin wiper EARLY WARNING

- **Hypothesis (EARLY WARNING):** If a SameCoin wiper is staged and about to detonate, then *before* any file is overwritten we should catch its geofence pre-flight: a non-browser process making an outbound request to the Israel-only Home Front Command site `oref.org.il` and using the response bytes as a key, and/or a system-language/locale query for Hebrew immediately preceding a drop of `MicrosoftEdge.exe`/`csrs.exe`/`image.jpg`/`video.mp4`; separately, at delivery time, an Excel-4.0 document invoking `GET.WORKSPACE` anti-analysis checks. Catching the oref.org.il check is the last clean window before destruction begins.
- **ATT&CK:**
  - T1614.001 — System Location Discovery: System Language Discovery (discovery) — Hebrew system-language check + oref.org.il Israel-only reachability gate
  - T1497.001 — Virtualization/Sandbox Evasion: System Checks (stealth) — Ferocious Excel-4.0 `GET.WORKSPACE` checks (env name/version, mouse arg 19, sound arg 42)
- **Actor procedure:** The SameCoin wiper geofences destruction to Israel — the Windows variant checks whether the system language is Hebrew before dropping/detonating, and the Oct-2024 variant additionally requires a successful response from `oref.org.il` (Israel-only), *also using that response as its XOR key* to decrypt the dropped wiper (`MicrosoftEdge.exe`), infector (`csrs.exe`), Al-Qassam wallpaper (`image.jpg`) and propaganda video (`video.mp4`). Upstream, the Ferocious Excel dropper runs three `GET.WORKSPACE` anti-sandbox checks (environment name/version vs a blocklist, mouse presence arg 19, sound-playback arg 42) and halts if any fails — so a detonation sandbox in the wrong geo/config never sees the payload.
- **Why a hunt, not a rule:** a locale query is trivially common and a single HTTP request to a government site is benign-looking, so neither is alertable in isolation, and the `GET.WORKSPACE` logic runs *inside the document before any host artifact exists* (visible only to static XLM inspection). The high-value find is *correlation and sequence*: `oref.org.il` fetched by a non-browser process → followed within seconds by decode-and-write of `MicrosoftEdge.exe`/`csrs.exe`, or a Hebrew-locale check bracketed by the same drops. Because this is the pre-wipe precursor the intel explicitly says to prioritise for early containment, the hunt's payoff is *time* — analyst correlation that buys the window a wipe-burst rule cannot.
- **Note on our environment:** for a non-Israeli MENA org, `oref.org.il` should essentially *never* be contacted by an endpoint process — its appearance is a near-binary anomaly and a very strong lead, even absent the Hebrew-locale condition (which may be false here).

## Data sources required

- Proxy / DNS / EDR network telemetry — outbound requests to `oref.org.il` (esp. by non-browser processes), and the process making them
- Sysmon EID 1 / 4104 — locale/`GetSystemDefaultUILanguage`/`Get-Culture`/`InstalledUICulture` queries; process making the oref request
- Sysmon EID 11 — drop of `MicrosoftEdge.exe`/`csrs.exe`/`image.jpg`/`video.mp4` right after the oref fetch/locale check
- Static document inspection (mail-gateway detonation / offline) for Excel-4.0 `GET.WORKSPACE` argument patterns (19, 42, env-name compares)

## Query starting point

Platform: `KQL / Sentinel`

```
// EARLY WARNING: oref.org.il contacted by a non-browser process, then a wiper-component drop
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","iexplore.exe","opera.exe","brave.exe"]);
DeviceNetworkEvents
| where RemoteUrl has "oref.org.il" or RemoteUrl has "oref"
| where InitiatingProcessFileName !in~ (browsers)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl
| join kind=leftouter (
    DeviceFileEvents
    | where FileName in~ ("MicrosoftEdge.exe","csrs.exe","image.jpg","video.mp4","Setup.exe")
    | project DropTime=TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
  ) on DeviceName
| where isnull(DropTime) or (DropTime between (TimeGenerated .. (TimeGenerated + 5m)))
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteUrl, DropTime, FileName, FolderPath
```

Companion: hunt Sysmon 4104/1 for locale/Hebrew (`he-IL`, LCID `0x040D`) checks by the same process, and submit any delivered Excel doc for static `GET.WORKSPACE(19)`/`(42)` inspection.

## Triage guidance

- **Likely malicious (act fast):** ANY endpoint process (non-browser) contacting `oref.org.il`, especially immediately before a drop of `MicrosoftEdge.exe`/`csrs.exe`/`image.jpg`/`video.mp4`; a locale/Hebrew check by a freshly-dropped binary; an Excel-4.0 doc with `GET.WORKSPACE` env/mouse/sound checks and a blocklist compare. Treat a confirmed oref.org.il pre-flight as imminent wiper detonation.
- **Likely benign / expected:** a user in Israel legitimately browsing `oref.org.il` in a real browser (hence the non-browser filter); genuine multilingual apps querying locale; legit Excel-4.0 macros (rare in most orgs — baseline and largely suppress the whole XLM class). For a non-IL org, oref.org.il from a process is essentially never expected.
- **Pivot next:** this is the flagship pre-wipe early-warning band — if the oref/locale pre-flight is confirmed, isolate the host *now*, block egress, and pivot to the drop/decode chain (HUNT-03, HUNT-05), the wallpaper/wipe impact (detection lane T1485/T1491.001) and the lateral spread (HUNT-09 collection, plus InfectAD/InfectOutlook). Confirmed SameCoin geofence pre-flight on a live host is an incident in progress — escalate to incident-response-coordinator immediately. The "oref.org.il contacted by a non-browser process" condition is precise and durable enough to hand to detection-engineering as a high-severity alert (they author it).

## References

- https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/
- https://securelist.com/wirtes-campaign-in-the-middle-east-living-off-the-land-since-at-least-2019/105044/
- https://attack.mitre.org/groups/G0090/
