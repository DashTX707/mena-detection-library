# Hunt: Ballistic Bobcat — in-backdoor host & process discovery blending with admin activity

- **Hypothesis:** If the Sponsor backdoor is resident on one of our hosts, then its reconnaissance is *not* a spawned command sweep an EDR would flag — it is in-process API calls the backdoor makes on check-in (locale/timezone/language via the location-discovery routine, and the `p` operator returning a process ID). Because that enumeration is indistinguishable from benign activity *in isolation*, the only viable tell is **contextual co-occurrence**: the discovery has to hang off the backdoor's own execution context. So the hunt does not chase the recon directly — it starts from the durable Sponsor host-anchors (a service named SystemNetwork/Update running an unsigned binary from a non-standard path, the config.txt/node.txt/error.txt triad on disk, or a periodic HTTP/80 beacon) and then asks: does that same process image / service also exhibit the language-and-process-context enumeration and downstream operator behavior that confirms it is a live backdoor and not a dormant artifact? A single locale query is noise; a locale/language + process-context enumeration *originating from an unsigned service-hosted image that also beacons* is the finding.
- **ATT&CK:**
  - T1614.001 — System Location Discovery: System Language Discovery (discovery) — Sponsor collects timezone and locale/language on initial check-in; hunted only in the context of the backdoor process, never as a standalone signal.
  - T1057 — Process Discovery (discovery) — Sponsor's `p` operator returns a process ID to the operator; a single PID lookup is not observable alone, so it is hunted as corroboration hanging off the backdoor anchor.
  - T1543.003 — Create or Modify System Process: Windows Service (persistence) — the SystemNetwork/Update service is the durable anchor the discovery is pinned to (detection-pack coverage exists; used here as the pivot spine).
  - T1071.001 — Application Layer Protocol: Web Protocols (command-and-control) — the HTTP/80 beacon is the second anchor that proves the backdoor is live, not dormant.

- **Actor procedure:** On check-in the Sponsor backdoor collects extensive host information via API rather than spawned commands — hostname, BIOS, processor, Windows version, domain membership, username, AC/battery status, and (T1614.001) timezone plus locale/language. Its `p` operator command (T1057) returns a process ID to the operator for basic process-context discovery. All of this runs inside the service-hosted backdoor process (persisted as SystemNetwork in v1, Update in v2-v5) and is reported back over the Base64+RC4 HTTP/80 C2 channel. The discovery is deliberately quiet — no `systeminfo.exe`, no `tasklist.exe`, no `whoami` — which is exactly why it evades command-line detection.
- **Why a hunt, not a rule:** Locale/timezone queries and a single PID lookup are in-process, extremely common in benign software, and produce no distinctive command-line — a standalone rule on "process queried locale" would be pure false positives, and the backdoor never spawns the discovery utilities that would give an EDR something to catch. The signal only exists as **correlation**: pinning otherwise-invisible enumeration to a confirmed-suspicious backdoor host-anchor (unsigned service image + config triad + HTTP/80 beacon) and judging whether the whole picture is a live Sponsor implant. That anchoring-and-judgement is hunt work. The durable anchors themselves (service name + unsigned image path, the beacon) are already handled by the detection pack; this hunt is the connective tissue that confirms an anchor is a live backdoor, not the alert on the recon.

## Data sources required

- Process-creation + image-load telemetry (Sysmon 1/7, EDR): service-hosted processes, image signature status and load path, parent = `services.exe`
- Service inventory / creation telemetry (Event ID 7045 / 4697, Sysmon 6 driver-load where relevant): services named SystemNetwork/Update and their ImagePath signature/location
- File telemetry (Sysmon 11, EDR file events): the config.txt / node.txt / error.txt triad co-located with a service binary, and staging paths (`%WINDIR%\Tasks\`, `%WINDIR%\INF\MSExchange Delivery DSN\`, `%USERPROFILE%\AppData\Local\Temp\file\`, `inetpub\wwwroot\aspnet_client\`)
- Network/proxy telemetry (Sysmon 3, netflow, proxy): periodic HTTP/80 beacons from a service-hosted image to the Sponsor C2 ranges, with Base64/high-entropy bodies
- Registry/API-context telemetry where available (locale/timezone/`GetUserDefaultLocaleName`, `GetSystemTimeZoneInformation`, `GetLocaleInfo` access) — used only as corroboration keyed to a flagged process

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — start from the durable Sponsor anchor, then confirm live-backdoor behavior (beacon + quiet enumeration) on the *same image*

```kusto
// Anchor 1: an unsigned/non-Microsoft service-hosted image from a non-standard path
let sponsorHosts = DeviceProcessEvents
    | where TimeGenerated > ago(30d)
    | where InitiatingProcessFileName =~ "services.exe"
    | where InitiatingProcessParentFileName =~ "services.exe" or InitiatingProcessFileName =~ "services.exe"
    | where isempty(FolderPath) == false
    | where not(FolderPath has @"\windows\system32\" or FolderPath has @"\windows\syswow64\")
    | where not(ProcessTokenElevation == "TokenElevationTypeDefault" and IsSigned == true and Signer has "Microsoft")
    | project DeviceId, DeviceName, ProcessImage=FolderPath, SHA1, ProcAccount=AccountName, ProcTime=TimeGenerated;
// Anchor 2 (co-location): the config.txt/node.txt/error.txt triad next to a service binary
let cfgTriad = DeviceFileEvents
    | where TimeGenerated > ago(30d)
    | where FileName in~ ("config.txt","node.txt","error.txt")
    | summarize triad = make_set(FileName) by DeviceId, FolderPath
    | where array_length(triad) >= 2;                 // 2+ of the triad co-located = strong
// Anchor 3 (live proof): HTTP/80 beacon from that same image to Sponsor C2 ranges
let beacon = DeviceNetworkEvents
    | where TimeGenerated > ago(30d)
    | where RemotePort == 80
    | where RemoteIP in ("37.120.222.168","5.255.97.172","198.144.189.74","162.55.137.20")
        or InitiatingProcessFolderPath has_any (@"\windows\tasks\", @"\msexchange delivery dsn\", @"\aspnet_client\")
    | summarize beacons=count(), c2=make_set(RemoteIP) by DeviceId, InitiatingProcessSHA1;
sponsorHosts
| join kind=leftouter (cfgTriad) on DeviceId
| join kind=leftouter (beacon) on $left.SHA1 == $right.InitiatingProcessSHA1
// Stack the anchors: unsigned service image + config triad and/or beacon = live Sponsor, not noise
| extend anchorScore = iff(isnotempty(triad),1,0) + iff(beacons > 0,1,0)
| where anchorScore >= 1
| order by beacons desc
```

Once a host clears the anchor stack, pivot to confirm the quiet enumeration hangs off that image: `DeviceEvents | where DeviceId == "<hit>" | where InitiatingProcessSHA1 == "<image sha1>" | where ActionType has_any ("GetSystemTimeZone","LocaleName","GetLocaleInfo") or AdditionalFields has_any ("Locale","TimeZone")` — corroboration only, never the entry point.

## Triage guidance

- **Likely malicious:** an unsigned/non-Microsoft service-hosted image running from `%WINDIR%\Tasks\`, `%WINDIR%\INF\MSExchange Delivery DSN\`, a Temp `\file\` path, or the Exchange web root, *and* co-located with 2+ of config.txt/node.txt/error.txt, *and/or* beaconing HTTP/80 to the Sponsor C2 ranges — with locale/timezone and process-context enumeration originating from that same image on service start. Any hit whose beacon lands on 37.120.222.168 / 5.255.97.172 / 198.144.189.74 / 162.55.137.20 is high-confidence.
- **Likely benign / expected:** locale, timezone, and language APIs are called constantly by legitimate installers, .NET apps, and localization frameworks — never treat that alone as suspicious; many signed third-party services legitimately run from ProgramData/Program Files paths — the discriminators are *unsigned + non-standard path + config triad + beacon*, not any single one. `config.txt`/`error.txt` are generic filenames — the finding requires the triad co-located with a service binary, not a lone match. Admin tools do process enumeration all day; that is why it is corroboration, never the anchor.
- **Pivot next:** a confirmed live Sponsor implant is an active compromise — escalate to incident-response-coordinator, isolate the host, capture memory before the `s`/Uninstall.bat cleanup (T1070.004) destroys the config triad and binary. From the host, pivot to the fuller post-exploit picture: credential access (ProcDump/Mimikatz T1003.001, WebBrowserPassView T1555.003), discovery/tunneling tools (Host2IP, RevSocks-as-CSRSS.EXE, GOST, Chisel, Plink), and the Exchange foothold that delivered it (HUNT-01). Preserve the config triad and beacon captures as attribution intel.

## References

- https://www.welivesecurity.com/en/eset-research/sponsor-batch-filed-whiskers-ballistic-bobcats-scan-strike-backdoor/
- https://github.com/eset/malware-ioc
- https://attack.mitre.org/techniques/T1614/001/
- https://attack.mitre.org/techniques/T1057/
- https://attack.mitre.org/techniques/T1543/003/
- https://attack.mitre.org/techniques/T1071/001/
