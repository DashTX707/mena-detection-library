# Hunt: POLONIUM — in-memory deobfuscation / decode of C2 commands and tokens

- **Hypothesis:** The Creepy family hides its C2 commands, OAuth tokens and configuration behind ROT13, Base64 and AES, decoding them **in memory at runtime** to leave little on disk. If POLONIUM is executing here, the tell is a *decode-shaped behavior*: PowerShell script blocks that chain `FromBase64String` / `[char]` arithmetic / `-bxor` / AES `CreateDecryptor` against embedded blobs, or a .NET/InstallUtil-hosted process performing symmetric-crypto and Base64 transforms shortly before or after cloud/C2 network activity. No single decode is malicious — the finding is decode primitives *co-located in time and process with beaconing and encoded C2 tokens*.
- **ATT&CK:**
  - T1140 — Deobfuscate/Decode Files or Information (stealth) — ROT13/Base64/AES runtime decoding of commands, tokens and config; hunt decode primitives in PowerShell script-block logs and .NET crypto-API use correlated with C2.

- **Actor procedure:** POLONIUM's backdoors **decode/deobfuscate strings and payloads at runtime** using ROT13, Base64 and AES to conceal C2 commands, embedded OAuth refresh tokens and configuration. The .NET implants are additionally packed with the **AsStrongAsFuck** obfuscator. Because decoding happens in memory, the disk artifact is minimal — the observable is the decode *operation* (script-block content, crypto API calls) rather than a decoded file. This pairs directly with the Base64-encoded username/IP tokens the implants place in outbound URIs.
- **Why a hunt, not a rule:** Base64 and AES are ubiquitous in legitimate software — installers, config parsers, and admin scripts decode constantly — so alerting on `FromBase64String` or `CreateDecryptor` alone is pure noise. The signal is *contextual*: decode primitives inside an unsigned/short-lived process, or a PowerShell block that both decodes an embedded blob and reaches a cloud/C2 endpoint in the same execution. That requires reading script-block content and correlating with network telemetry — analyst judgement, not a threshold. If a specific decode chain proves stable and rare (e.g., a script-block regex that reliably fires only on CreepyDrive's loader — a Level-2 behavioral observable), hand the pattern to detection-engineering.

## Data sources required

- PowerShell script-block logging (Event ID 4104) and module logging — full block text for decode-primitive matching
- EDR / Sysmon process telemetry with command line and, where available, .NET crypto-API (AmsiScanBuffer / assembly-load) visibility
- Network telemetry to correlate the decoding process with cloud/C2 contact (join to HUNT-03)
- AMSI capture where enabled (deobfuscated content is often surfaced post-decode)

## Query starting point

Platform: `KQL / Microsoft Sentinel (PowerShell 4104 + AMSI)`

```kusto
let decodeSignals = dynamic(["FromBase64String","::UTF8.GetString","-bxor",
    "CreateDecryptor","RijndaelManaged","AesManaged","[char](","ToCharArray","ROT13","N2R"]);
DeviceEvents
| where TimeGenerated > ago(14d)
| where ActionType in ("PowerShellCommand","ScriptBlockLogged") or ActionType == "AmsiContentScanned"
| extend blk = tostring(AdditionalFields.ScriptBlockText)
| where blk has_any (decodeSignals)
// require MORE than one decode primitive, or a decode + web call in the same block
| extend primHits = array_length(set_intersect(extract_all(@"(\w+)", blk), decodeSignals))
| extend touchesCloud = blk has_any ("graph.microsoft.com","dropboxapi","mega","Invoke-WebRequest","Net.WebClient","UploadFile")
| where primHits >= 2 or (primHits >= 1 and touchesCloud)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, primHits, touchesCloud,
          snippet = substring(blk, 0, 400)
| order by touchesCloud desc, primHits desc
```

## Triage guidance

- **Likely malicious:** a PowerShell block that Base64-decodes an embedded blob and immediately makes a cloud/C2 web request in the same execution; AES `CreateDecryptor` inside a short-lived unsigned .NET process launched by InstallUtil; decode primitives running from a masqueraded binary path; a decode chain that reconstructs a `data.txt`/`response.json`-style workflow.
- **Likely benign / expected:** installers and packaging tools that Base64-decode resources; legitimate admin/DevOps scripts decoding config or secrets from a vault; endpoint-management agents using AES for their own transport (baseline signed publishers). A lone `FromBase64String` in a signed process is noise — the co-location of multiple primitives with C2 contact in an unsigned/short-lived process is the finding.
- **Pivot next:** capture the decoded content via AMSI, resolve what it decoded to (a C2 command? an OAuth token?), and pivot to the same host's cloud-C2 (HUNT-03) and network egress. If the decode reconstructs live tasking, treat as an active implant and escalate to incident-response-coordinator; preserve the script block for the loader signature.

## References

- https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/
- https://www.microsoft.com/en-us/security/blog/2022/06/02/exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/
- https://attack.mitre.org/techniques/T1140/
