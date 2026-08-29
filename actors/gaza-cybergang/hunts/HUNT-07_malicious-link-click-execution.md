# Hunt: Gaza Cybergang malicious-link user execution (geofenced link → RAR archive → embedded executable)

- **Hypothesis:** If a Gaza Cybergang phishing link succeeded, then correlated mail/URL-gateway, proxy and endpoint telemetry will show a user clicking an actor-controlled or Dropbox-hosted link, an archive (`.rar`/`.zip`) landing in the browser download path, and — shortly after — an archive tool extracting and the user launching an *embedded executable* from the download/`%TEMP%` folder, closing the loop from click to execution.
- **ATT&CK:**
  - T1204.001 — User Execution: Malicious Link (execution) — the user is tricked into opening a RAR/archive from a malicious link and running an embedded executable
- **Actor procedure:** Gaza Cybergang / TA402 sends phishing emails with malicious links — geofenced links (NimbleMamba) and Dropbox-hosted links (IronWind) that gate delivery to intended regional victims. The link fetches a RAR/ZIP; the victim opens it and runs the embedded executable, kicking off the loader/backdoor chain. The link-click is visible at the gateway/proxy, but the decisive endpoint signal only appears once the archive is opened and the executable launched.
- **Why a hunt, not a rule:** a user clicking a link and downloading an archive is completely normal high-volume behavior, and geofencing means the URL often won't detonate in the sandbox — so a link-click alert is neither precise nor reliable. The value is *reconstructing the chain across three data planes* (mail/URL click → download → extract-and-execute) on the same user/host within a short window, and judging it against normal download-and-run behavior per user role. That correlation is analyst work, not a fixed threshold.

## Data sources required

- Mail-gateway / URL-rewrite click logs (who clicked which URL, when) and proxy logs (download URL, content-type, bytes, referrer)
- Sysmon EID 11 (archive + extracted `.exe` written to Downloads/`%TEMP%`) and EID 15 (Mark-of-the-Web / Zone.Identifier on the download)
- Sysmon EID 1 / 4688 (archive tool → executable lineage; executable launched from download path)
- EDR process + network telemetry

## Query starting point

Platform: `Splunk SPL`

```
* Endpoint chain: browser/mail → archive download → extracted exe run from a download/temp path
index=endpoint source=*Sysmon* EventCode=1
| eval img=lower(Image), parent=lower(ParentImage), pcmd=lower(coalesce(ParentCommandLine,""))
| where match(img,"\.exe$")
| where match(img,"(\\\\downloads\\\\|\\\\temp\\\\|\\\\appdata\\\\local\\\\temp)")
| where match(parent,"(winrar|7z|7zfm|winzip|explorer|chrome|msedge|firefox|outlook)\.exe$")
| join type=left host [
    search index=endpoint source=*Sysmon* EventCode=11
    | eval f=lower(TargetFilename)
    | where match(f,"\.(rar|zip|7z)$") AND match(f,"(\\\\downloads\\\\|\\\\temp\\\\)")
    | stats latest(f) as archive latest(_time) as archive_time by host ]
| where isnotnull(archive)
| table _time host User parent img archive
| sort - _time
```

## Triage guidance

- **Likely malicious:** a `.rar`/`.zip` freshly downloaded (Mark-of-the-Web present) from a Dropbox link or a newly-registered/regional domain, extracted, and an embedded `.exe`/`.scr`/`.lnk` then launched from Downloads/`%TEMP%` by the same user within minutes; the executable subsequently doing discovery (HUNT-02) or cloud C2 (HUNT-01); a click on a URL the mail gateway couldn't detonate (geofenced).
- **Likely benign / expected:** users legitimately downloading and running archived software/installers for their job; IT distributing zipped tools. Baseline download-and-run per user role and allowlist known internal archive sources.
- **Pivot next:** pull the delivering email and URL for the wider recipient list; detonate the archive/link from an in-region egress point to defeat geofencing; forward the launched executable to the packing/signing (HUNT-03), victim-gating (HUNT-04) and discovery (HUNT-02) hunts. Click-to-execution confirmed with follow-on backdoor behavior is an active incident — escalate.

## References

- https://attack.mitre.org/groups/G0021/
- https://www.proofpoint.com/us/blog/threat-insight/nimblemamba-investigating-ta402-molerats-espionage-trojan
- https://www.proofpoint.com/us/blog/threat-insight/ta402-uses-complex-ironwind-infection-chain-target-middle-east
