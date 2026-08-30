# Hunt: StrongPity — ISP-level content-injection / MitM delivery of trojanized installers

- **Hypothesis:** If StrongPity/PROMETHIUM is delivering to us via its signature on-path capability, then a user who requested a *legitimate* installer (WinRAR, TrueCrypt, CCleaner, VLC, Opera, Skype, 7-Zip, Driver Booster, WinBox) over plain HTTP received a *different* binary than the vendor published — the tell is a **download-integrity mismatch**: the SHA-256 of the file that landed on disk does not match the vendor-published hash for that version, and/or the download chain shows an unexpected 302/redirect off the canonical vendor host to an intermediary before the bytes arrive. The redirect and the byte-rewrite happen off-victim (attacker site / ISP path) and are largely invisible to host telemetry in isolation; the finding is the *pairing* of a genuine-looking download event with a hash that betrays it. Either half alone is thin — a hash mismatch on an unknown file is noise, a redirect is normal CDN behavior — the pair on a name-brand installer is the finding.
- **ATT&CK:**
  - T1189 — Drive-by Compromise (initial-access) — user seeking legit software is redirected to a trojanized installer; hunt the download-source/redirect chain.
  - T1659 — Content Injection (initial-access) — on-path HTTP "on-the-fly" browser redirection (assessed ISP-level) rewrites the download in transit.
  - T1557 — Adversary-in-the-Middle (credential-access) — the network-path MitM that intercepts and swaps the software-download response.

- **Actor procedure:** ESET's 2017 reporting (StrongPity2) documented victims in two countries downloading legitimate apps (CCleaner v5.34, Driver Booster, Opera, Skype, VLC v2.2.6, WinRAR 5.50) being transparently redirected — most likely at the ISP level — to trojanized versions, with distribution seen from `downloading.internetdownloading[.]co`. The trojanized build installs the real app as a decoy while dropping `wmpsvn32.exe` into `%temp%\lang_be29c9f3-83we`. The redirect is plain-HTTP on-path injection; HTTPS download paths defeat it, which is why the download-integrity angle keys specifically on **HTTP** (or HTTP-then-redirect) fetches of installer binaries.
- **Why a hunt, not a rule:** The injection/MitM occurs in the network path, not on the endpoint, so there is no host event to alert on. Building a standalone alert on "installer downloaded over HTTP" would fire on the enormous volume of legitimate freeware/CDN traffic; building one on "hash not in vendor list" requires a maintained vendor-hash corpus and still mislabels every legitimately-updated or repackaged installer. The signal only becomes real when you *correlate* a brand-name installer fetch with a vendor-hash mismatch and an off-canonical redirect — a fusion + judgement task. If a durable observable falls out (e.g., a specific delivery intermediary reused across fetches, or a repeatable "HTTP fetch of vendor X installer that resolves to a non-vendor ASN"), hand that to detection-engineering as a scoped analytic — do not try to alert on "the ISP MitM'd us."

## Data sources required

- Web-proxy / secure-web-gateway logs (URL, HTTP method, status, referer, redirect chain, response content-type/length, server ASN)
- EDR file-creation telemetry for downloaded installers (`DeviceFileEvents`: FileName, SHA256, folder = Downloads/%temp%, InitiatingProcess = browser)
- A vendor-published-hash reference corpus for the targeted apps (WinRAR/rarlab, VLC/videolan, CCleaner/piriform, Opera, Skype, 7-Zip, TrueCrypt) — even a partial current-version table is enough to flag mismatches
- DNS resolution logs to attribute the download host and any redirect hop

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — pair a name-brand installer landing on disk with a vendor-hash mismatch

```kusto
// Installer binaries that landed via a browser, hashed on write
let installers = DeviceFileEvents
    | where TimeGenerated > ago(30d)
    | where ActionType == "FileCreated"
    | where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe")
    | where FileName has_any ("winrar","wrar","truecrypt","ccleaner","vlc","opera","skype","7z","7-zip","driverbooster","winbox")
    | where FileName endswith ".exe"
    | project TimeGenerated, DeviceName, FileName, SHA256, FolderPath, InitiatingProcessAccountName;
// Vendor-published good hashes (maintained watchlist); anti-join = the installer's hash is NOT known-good
let vendorGood = _GetWatchlist('vendor_installer_hashes') | project GoodSHA256 = SHA256;
installers
| join kind=leftanti (vendorGood) on $left.SHA256 == $right.GoodSHA256
// Enrich with the HTTP fetch: HTTP (not HTTPS) request and/or an off-vendor redirect hop
| join kind=leftouter (
    _Im_WebSession | where TimeGenerated > ago(30d)
    | where Url has_any ("winrar","truecrypt","ccleaner","videolan","vlc","opera","skype","7-zip","driverbooster","winbox",".exe")
    | project DeviceName = SrcDeviceName, Url, HttpMethod = NetworkProtocol, DstHost = DstDvcHostname, EventStartTime
  ) on DeviceName
| order by TimeGenerated desc
```

## Triage guidance

- **Likely malicious:** a WinRAR/VLC/CCleaner/etc. installer whose on-disk hash matches *no* published vendor version, fetched over plain HTTP or via a redirect that left the canonical vendor domain to a low-reputation/newly-seen host, that then spawns an unexpected child (`wmpsvn32.exe`, `procexp.exe`, `nvvscv.exe`) or writes to `%temp%\lang_*` — cross to HUNT-05 and the detection pack's T1204.002/T1547.001. Bonus corroboration: the download host resolves into an ASN unrelated to the vendor.
- **Likely benign / expected:** vendors legitimately rev their installers, so a hash "not in my table" is expected whenever the table lags a release — confirm against the vendor's *current* published hash before escalating. Portable-app repackagers (Ninite, Chocolatey, portableapps.com), corporate software-distribution wrappers, and enterprise CDNs all legitimately redirect and rewrap installers. Plain-HTTP installer fetches are unfortunately still common for older freeware — HTTP alone is not the finding.
- **Pivot next:** on a confirmed mismatch, capture the delivering URL/redirect chain and the intermediary host as off-victim intel (feed HUNT-02 and HUNT-03), pull the trojanized sample for the byte-level hash and diff against the vendor build, and hunt the host for the drop/persistence chain (HUNT-05, detection-pack T1204.002/T1547.001/T1685). If multiple hosts on the same egress/ISP path received swapped binaries in the same window, treat as active on-path targeting and escalate to incident-response-coordinator.

## References

- https://www.welivesecurity.com/2017/12/08/strongpity-like-spyware-replaces-finfisher/
- https://securelist.com/on-the-strongpity-waterhole-attacks-targeting-italian-and-belgian-encryption-users/76147/
- https://attack.mitre.org/techniques/T1189/
- https://attack.mitre.org/techniques/T1659/
- https://attack.mitre.org/techniques/T1557/
