# Hunt: Volatile Cedar — obfuscation & runtime-deobfuscation tradecraft on web servers

- **Hypothesis:** If Explosive has been dropped on one of our web/app servers, then its author's core evasion discipline — static obfuscation of the implant plus *runtime* decode/decrypt of its components and C2 payloads — will not show up as a signature match (that is exactly what the obfuscation defeats), but it *will* leave behavioral residue on a host whose baseline should be near-static: a web/app-server process (java, tomcat, w3wp) or an unsigned modular binary spawning a decode/expand step, writing then immediately reading a high-entropy blob in the web root or a RAT working directory, and de-obfuscating content that never touches disk in cleartext. The finding stacks *high-entropy file artifact* + *unexpected decode/execution lineage from a server process* on the same host — because obfuscated blobs alone are common (compressed assets, minified JS) and a lone decode command is benign, but a server process that writes a high-entropy file and then runs a base64/decompress-then-execute chain over it is Explosive unpacking itself.
- **ATT&CK:**
  - T1027 — Obfuscated Files or Information (stealth/defense-evasion) — Explosive is statically obfuscated and repeatedly re-obfuscated across the main-binary/DLL split to defeat heuristic AV
  - T1140 — Deobfuscate/Decode Files or Information (stealth/defense-evasion) — the implant decodes/decrypts its obfuscated components and C2 payloads at runtime to execute

- **Actor procedure:** ClearSky and Check Point both describe Explosive as deliberately obfuscated and modular: operators re-obfuscate and patch the separately-updatable API DLL to stay ahead of signatures, and the implant decodes/decrypts its own components and encrypted C2 payloads at runtime to run functionality. This is a maintained tradecraft discipline (four RAT versions), not an accident — the group's whole survival model is "stay below static detection," which pushes the only reliable observable into behavior: entropy on disk and decode-then-execute lineage.
- **Why a hunt, not a rule:** Obfuscation by design nullifies static signatures, and runtime deobfuscation is internal to the process and hard to observe directly — there is no clean primitive to alert on. High file entropy and base64/decode commands are individually ubiquitous (every packed installer, minified bundle, and admin PowerShell one-liner trips them), so a standalone rule drowns. The signal lives in *context*: entropy + decode lineage rooted in a web/app-server process on a host that should be behaviorally static. That correlation and the entropy/lineage baselining are hunt work; YARA here is a hunting aid to *find* candidate blobs, not a production detection.

## Data sources required

- EDR process-creation + command-line telemetry (parent lineage: java/tomcat/w3wp → decode/expand utilities)
- File-creation / file-modification telemetry in web roots and temp/working directories (for entropy scoring)
- Image-load / module-load telemetry (unsigned companion DLL loaded alongside the Explosive main binary; cross-ref detection pack T1129/T1574.001)
- On-disk YARA/entropy scanning capability across web-application roots (hunting aid)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — decode/deobfuscation execution rooted in a web/app-server process, joined to a high-entropy file write on the same host.

```kusto
let decoders = dynamic(["certutil.exe","powershell.exe","cscript.exe","wscript.exe","expand.exe","tar.exe"]);
let webServerProcs = dynamic(["java.exe","tomcat9.exe","w3wp.exe","httpd.exe","php-cgi.exe"]);
let decodeExec = DeviceProcessEvents
    | where TimeGenerated > ago(14d)
    | where FileName in~ (decoders)
    | where InitiatingProcessFileName in~ (webServerProcs)
       or ProcessCommandLine has_any ("-decode","FromBase64String","::FromBase64","-decompress","gzip","GetString")
    | project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName;
let entropyWrites = DeviceFileEvents
    | where TimeGenerated > ago(14d)
    | where ActionType == "FileCreated"
    | where FolderPath has_any ("\\webapps\\","\\wwwroot\\","\\confluence\\","\\atlassian\\","\\temp\\")
    | where FileName matches regex @"(?i)\.(dat|bin|tmp|jsp|dll|cache|log)$"
    | project WriteTime=TimeGenerated, DeviceName, FolderPath, FileName;   // score entropy in the FIM/YARA pass
decodeExec
| join kind=inner (entropyWrites) on DeviceName
| where abs(datetime_diff('minute', TimeGenerated, WriteTime)) <= 10       // write then decode, tightly coupled
| project DeviceName, TimeGenerated, InitiatingProcessFileName, FileName, ProcessCommandLine, FolderPath, blob=FileName1
| order by DeviceName, TimeGenerated
```

## Triage guidance

- **Likely malicious:** a web/app-server process (java/tomcat/w3wp) spawning certutil/powershell to decode a blob it just wrote into the web root; a high-entropy `.dat`/`.bin`/`.jsp` file created in an application root followed within minutes by a decode-then-execute chain; an unsigned companion DLL loaded from the same directory as an unknown main binary (Explosive's modular design); the same host lighting up in the web-shell (T1505.003) or C2 (HUNT-03) lanes. Entropy plus decode-lineage from a server role that should never do either is the finding.
- **Likely benign / expected:** legitimate deploys and CI/CD unpacking WAR/JAR/ZIP archives into web roots (baseline release windows and pipeline service accounts); admin PowerShell using base64-encoded commands; packed installers, minified JS/CSS, and compressed caches that score high entropy normally. A decode step by a known deploy account during a scheduled release is expected; the same chain rooted in the *running* web-server process outside a deploy window is not.
- **Pivot next:** carve the decoded blob and run the Explosive/Caterpillar YARA and hash set (detection pack IOCs) against it; check module loads on the host for the unsigned companion DLL (T1129/T1574.001); if the artifact decodes to implant or web-shell code, this is a live compromise — escalate to incident-response-coordinator and pivot to the C2 hunt (HUNT-03) and staging hunt (HUNT-05). If a stable decoded-artifact path or lineage falls out, hand it to detection-engineering.

## References

- https://www.clearskysec.com/wp-content/uploads/2021/01/Lebanese-Cedar-APT.pdf
- https://blog.checkpoint.com/security/volatilecedar/
- https://attack.mitre.org/techniques/T1027/
- https://attack.mitre.org/techniques/T1140/
