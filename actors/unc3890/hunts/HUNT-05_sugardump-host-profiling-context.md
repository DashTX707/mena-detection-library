# Hunt: UNC3890 — SUGARDUMP host/environment profiling within the stealer's lineage

- **Hypothesis:** SUGARDUMP branches its behavior on host context — it enumerates the **Windows version** (choosing a Win7-vs-later scheduled-task name) and the **installed browsers and their versions** to tailor which credential/cookie stores it raids and how it persists. In isolation, OS/version discovery is one of the noisiest, most benign things a process can do — un-alertable. But *within the stealer's process lineage* — a masquerading `CrashReporter.exe` (or a rundll32-launched PE) reading OS/browser version keys **immediately before** touching multiple browser profile directories — the same discovery becomes a high-signal collection tell. The hunt keys on the *unexpected relationship*: a non-browser, non-system process performing environment enumeration and browser-store access in one tight sequence, not the discovery calls on their own.
- **ATT&CK:**
  - T1082 — System Information Discovery (discovery) — SUGARDUMP gathers Windows version (branching persistence between Win7 and later) and installed-browser versions to tailor persistence and collection; the hunt surfaces that enumeration only when it sits inside the stealer's lineage next to browser-store access.

- **Actor procedure:** The SUGARDUMP stealer gathers host/environment context to tailor itself: it reads the Windows version — branching its scheduled-task name between `MicrosoftInternetExplorerCrashRepoeterTaskMachineUA` on Windows 7 and `MicrosoftEdgeCrashRepoeterTaskMachineUA` on later versions — and enumerates installed browsers and their versions to decide which of Chrome (`%AppData%\Google\Chrome\User Data`), Opera (`Opera Stable`), Edge (`Microsoft\Edge\User Data`) and Firefox (`Mozilla\Firefox\Profiles`) credential and cookie stores to harvest. The profiling process runs as the masqueraded `CrashReporter.exe` under `%AppData%\Microsoft\Internet Explorer\TabRoaming\`, delivered by the fake `3-Video-VLC.exe` or an Excel-macro→rundll32 chain.
- **Why a hunt, not a rule:** System Information Discovery is intentionally routed to the hunt lane because it is high-volume and almost entirely benign — every installer, inventory agent, telemetry client and login script reads OS and browser version. A standalone rule on that behavior is pure noise. The technique only becomes meaningful *relationally*, as the connective tissue between delivery and collection in the SUGARDUMP chain, and that correlation — "who read the version keys, was it a browser or a system process, and did the same process then open browser credential stores across multiple vendors" — is judgement work across process, registry and file-access telemetry. The crisp endpoints of that chain (the browser-store reads, the misspelled scheduled task) are already in the detection lane (T1555.003, T1053.005); this hunt exists to catch the *variant* whose exfil/hash IOCs have changed but whose profile-then-collect behavior has not.

## Data sources required

- EDR process-create telemetry with full lineage (parent/child, image path, signer) — to identify a non-system process doing the profiling
- Registry-access / EDR registry telemetry — reads of OS-version keys (`CurrentVersion`, `ProductName`) and browser install/version keys
- EDR file-access telemetry — access to Chrome/Opera/Edge `User Data` and Firefox `Profiles` (Login Data, cookies) directories
- Scheduled-task creation (Event ID 4698) — the OS-branched `CrashRepoeter...TaskMachineUA` names (pivot/corroborator)

## Query starting point

Platform: `EDR (Microsoft Defender advanced hunting / KQL)` — a non-browser process that profiles the host and then reads multiple browser stores

```kusto
let profilers =
    DeviceRegistryEvents
    | where TimeGenerated > ago(21d)
    | where RegistryKey has_any (@"\Microsoft\Windows NT\CurrentVersion",
             @"\Clients\StartMenuInternet", @"\Google\Chrome\BLBeacon",
             @"\Mozilla\Mozilla Firefox", @"\Microsoft\Edge\BLBeacon")
    | where InitiatingProcessFileName !in~ ("explorer.exe","svchost.exe","MsMpEng.exe","OfficeClickToRun.exe")
    | where not(InitiatingProcessFolderPath has @"\Program Files")   // drop signed installers/browsers
    | project DeviceName, proc=InitiatingProcessFileName, procPath=InitiatingProcessFolderPath,
              acct=InitiatingProcessAccountName, tProfile=TimeGenerated;
let browserReads =
    DeviceFileEvents
    | where TimeGenerated > ago(21d) and ActionType == "FileAccessed"
    | where FolderPath has_any (@"\Google\Chrome\User Data", @"\Opera Software\Opera Stable",
             @"\Microsoft\Edge\User Data", @"\Mozilla\Firefox\Profiles")
    | where FileName has_any ("Login Data","cookies","Cookies","logins.json","key4.db")
    | where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","opera.exe","firefox.exe")
    | summarize vendors=dcount(FolderPath), stores=make_set(FileName,20), tRead=min(TimeGenerated)
             by DeviceName, proc=InitiatingProcessFileName, acct=InitiatingProcessAccountName;
profilers
| join kind=inner (browserReads) on DeviceName, proc, acct
| where tRead between (tProfile .. tProfile + 10m)   // profile then collect, same process, tight window
| where vendors >= 2                                  // multi-browser sweep = stealer, not one app
| project DeviceName, proc, procPath, acct, stores, tProfile, tRead
```

## Triage guidance

- **Likely malicious:** a non-browser, non-system process (especially one named `CrashReporter.exe` or running from `%AppData%\...\TabRoaming\` or a temp path) that reads OS/browser version keys and then, within minutes, opens `Login Data`/cookie stores across **two or more** browser vendors; the presence alongside it of the OS-branched `CrashRepoeter...TaskMachineUA` scheduled task. The tight profile-then-multi-vendor-collect sequence by one unsigned process is the signal.
- **Likely benign / expected:** password managers and browser-sync/import utilities that legitimately read multiple browsers' stores (baseline the known ones by signer/path); enterprise inventory/telemetry agents (SCCM, asset scanners) that read OS and browser version keys but never touch credential stores — the discriminator is whether the *same* process then reads Login Data; endpoint DLP/backup tooling touching profile folders. Version enumeration with no subsequent multi-vendor store access is expected and should be dropped.
- **Pivot next:** a confirmed profile-then-collect by an unsigned/masquerading process is an active SUGARDUMP infection — escalate to incident-response-coordinator, isolate the host, and pivot to the detection pack for the collection and exfil endpoints (T1555.003, T1539, T1048 SMTP-to-webmail / T1041 HTTP-to-C2) and to HUNT-04 for the build-string confirmation. Confirm the scheduled-task persistence (T1053.005) and remove it. If a benign multi-browser reader is the culprit, add it to the baseline so the analytic still catches the stealer variant.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-actor-targeting-israeli-shipping
- https://thehackernews.com/2022/08/suspected-iranian-hackers-targeted.html
- https://attack.mitre.org/techniques/T1082/
