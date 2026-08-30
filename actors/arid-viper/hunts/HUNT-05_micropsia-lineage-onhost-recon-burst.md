# Hunt: Arid Viper — low-signal on-host recon burst inside the Micropsia / PyMicropsia lineage (individually invisible, collectively a check-in)

- **Hypothesis:** If a Micropsia / PyMicropsia / Arid Gopher implant has landed and is performing its initial check-in, then no single discovery call will look abnormal — asking for the OS version, the computer/user name, and walking the filesystem for documents are all things thousands of benign programs do every minute. The tell is the *burst*: the same short-lived, non-standard process issuing all three classes of discovery back-to-back within seconds of first execution, from a user-writable path, immediately before an outbound HTTP POST. The hunt is a lineage-and-timing correlation — stack "never-before-seen process", "unexpected relationship (discovery → beacon)" and "improper timing (compressed recon window)" on one process tree; any one primitive alone is noise, the three together are an implant profiling its victim.
- **ATT&CK:**
  - T1082 — System Information Discovery (discovery) — Arid Gopher reads OS version via `RtlGetVersion()`; Micropsia profiles the host at initial check-in.
  - T1033 — System Owner/User Discovery (discovery) — implants concatenate computer name + username + a random string to build the unique victim ID used for C2 registration.
  - T1083 — File and Directory Discovery (discovery) — implants enumerate files/directories to locate target documents by extension across local disk and removable media, feeding collection.

- **Actor procedure:** On first run the Micropsia-lineage Windows implants fingerprint the host to register with C2. **Arid Gopher** calls `RtlGetVersion()` to obtain the OS version (T1082). All variants build a **unique victim identifier** by combining the computer name, the logged-on username and a random string (T1033) — this ID keys the C2 registration and every subsequent beacon. The implant then **enumerates files and directories** (T1083), hunting documents by extension (`.doc .docx .xls .xlsx .pdf .ppt .pptx .csv .txt .rtf .odt .mdb .accdb`) across the local system and any removable media, which feeds the automated-collection / RAR-staging chain (see HUNT-covered T1005/T1119/T1560.001 in the detection pack). The whole sequence runs within the implant's own process, unattended, seconds after execution, and is followed by an HTTP POST check-in to a persona C2 domain (`/zoailloaze/sfuxmiibif/*`-style URIs).
- **Why a hunt, not a rule:** each of these three techniques is rated *low* detection feasibility for a reason — `RtlGetVersion`, `GetComputerName`/`GetUserName`, and directory walks are ubiquitous, high-volume, and overwhelmingly legitimate. A standalone rule on any of them would bury the SOC. There is no durable single observable here; the signal lives only in the *correlation of lineage + compressed timing + downstream beacon* on one anomalous process, and deciding whether a given short recon burst is an implant check-in or a benign installer requires analyst judgement against process ancestry and the persona-domain egress. That fusion is hunt work. If the hunt isolates a durable relational observable — e.g. "an unsigned image from a user-writable path issues user/host/file discovery then POSTs to a persona-pattern domain within N seconds" (a Level-4 behavioral chain) — hand *that* scoped analytic to detection-engineering; do not try to alert on system-info discovery by itself.

## Data sources required

- EDR / Sysmon process telemetry (EID 1): process creation with parent lineage, image path, signer status, command line — to anchor the burst on a single non-standard process from a user-writable path
- EDR file-access / Sysmon EID 11 + 4663 file-access auditing: rapid directory enumeration and document-extension reads clustered under one process
- Network / proxy + Sysmon EID 3: the outbound HTTP POST check-in immediately following the recon burst (persona domains, `/zoailloaze/sfuxmiibif/*` URI shape)

## Query starting point

Platform: `KQL / Microsoft Defender XDR (Advanced Hunting)` — find a single young, non-standard process that stacks host+user+file discovery then beacons

```kusto
// Anchor: recently-created, unsigned/unusual-path processes (candidate implants)
let candidates = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where InitiatingProcessFolderPath has_any (@"\users\", @"\appdata\", @"\temp\", @"\programdata\")
    | where isempty(InitiatingProcessVersionInfoCompanyName)
         or InitiatingProcessVersionInfoCompanyName !in ("Microsoft Corporation")
    | project DeviceId, DeviceName, ProcId = InitiatingProcessId,
              Proc = InitiatingProcessFileName, Acct = AccountName, t0 = Timestamp;
// (a) System-info / owner-user discovery signal (T1082 / T1033)
let disco = DeviceProcessEvents
    | where ProcessCommandLine has_any ("systeminfo","whoami","RtlGetVersion",
            "GetComputerName","GetUserName","ver","hostname")
    | project DeviceId, ProcId = InitiatingProcessId, discoTime = Timestamp, ProcessCommandLine;
// (b) File/dir enumeration hunting documents by extension (T1083)
let files = DeviceFileEvents
    | where ActionType in ("FileAccessed","FileCreated")
    | where FileName endswith_any (".doc",".docx",".xls",".xlsx",".pdf",".ppt",
            ".pptx",".csv",".txt",".rtf",".odt",".mdb",".accdb")
    | summarize docReads = count(), docSet = make_set(FolderPath, 15),
                fFirst = min(Timestamp), fLast = max(Timestamp)
             by DeviceId, ProcId = InitiatingProcessId
    | where docReads >= 20 and (fLast - fFirst) < 3m;   // bulk walk in a tight window
candidates
| join kind=inner (disco) on DeviceId, ProcId
| join kind=inner (files) on DeviceId, ProcId
// compressed recon window: discovery + doc-enumeration within ~2 min of process start
| where discoTime between (t0 .. t0 + 2m) and fFirst between (t0 .. t0 + 2m)
| order by docReads desc
// PIVOT: join DeviceNetworkEvents for an HTTP POST to a persona domain shortly after fLast
```

## Triage guidance

- **Likely malicious:** an unsigned image from `\Users\...\AppData` or `\Temp` that, within ~2 minutes of first execution, queries OS version + computer/user name AND fans out a 20+-document directory walk by target extension, then POSTs to a hyphenated persona domain — especially on a host belonging to a government / military / activist / journalist role in the targeted regions; the victim-ID-building pattern (host+user+random string) surfacing in an outbound parameter.
- **Likely benign / expected:** software installers, inventory/asset agents, backup and DLP tools, search-indexers (Windows Search, Everything), and antivirus all legitimately enumerate the disk and read host/user identity — these are signed, from `Program Files`, recurring on a schedule, and *not* followed by a persona-domain POST. A user opening a documents folder is not a 20-file programmatic walk in 3 minutes. Baseline your inventory/indexing agents and exclude them by signer + path.
- **Pivot next:** if the burst-to-beacon chain holds, pull the anchoring binary for analysis (feed HUNT-06 for obfuscation/lineage confirmation), check the same host for the Micropsia persistence and staging artifacts in the detection pack (Startup `.lnk` / `NetworkBoosterUtilities.lnk` T1547.009, HKCU Run T1547.001, `HPFusionManagerDell` staging T1074.001, `rar.exe` password-protected archives T1560.001), and if collection/staging is present treat as a live compromise and escalate to incident-response-coordinator. Route the durable burst-then-beacon behavioral chain to detection-engineering as a scoped analytic.

## References

- https://www.deepinstinct.com/blog/arid-gopher-the-newest-micropsia-malware-variant
- https://unit42.paloaltonetworks.com/pymicropsia/
- https://www.security.com/threat-intelligence/mantis-palestinian-attacks
- https://attack.mitre.org/techniques/T1082/
- https://attack.mitre.org/techniques/T1033/
- https://attack.mitre.org/techniques/T1083/
- https://attack.mitre.org/software/S0339/
