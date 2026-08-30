# Hunt: Cotton Sandstorm WezRat obfuscation & legitimate-name/location masquerade

- **Hypothesis:** If ASA's WezRat toolchain is present in our environment, then because it defeats static signatures by *obfuscation* and *masquerade* rather than by hiding, the huntable evidence is the seams of that disguise: a high-entropy binary that must be handed a runtime de-obfuscation key on the command line before it decodes its config and beacons; an installer or C2 endpoint named to impersonate a trusted brand/CERT (`Google Chrome Installer.msi`, `il-cert[.]net`) whose signer/metadata or behavior contradicts the name; and lookalike/impersonation naming across artifacts and personas (Regiment GUD impersonating the real GUD). The hunt looks for name-vs-behavior and name-vs-signer mismatch, not for a known hash.
- **ATT&CK:**
  - T1027 — Obfuscated Files or Information (stealth)
  - T1036.005 — Masquerading: Match Legitimate Name or Location (stealth)

- **Actor procedure:** The WezRat / `bd.exe` RAT is heavily obfuscated and requires a runtime de-obfuscation key passed on the command line (observed value `8765`) to decode its embedded configuration — including the C2 web-server address — impeding static analysis (T1027). ASA disguises malicious artifacts and personas as legitimate: the dropper is named `Google Chrome Installer.msi` and performs a real Chrome install to appear benign; the C2 domain `il-cert[.]net` (`connect.il-cert[.]net`) mimics a security/CERT resource; and the "Regiment GUD" persona impersonates the real French far-right group "GUD" (T1036.005). Name/location masquerade defeats name-based trust, so the discriminating signal is signer/metadata/behavior mismatch, not the filename.
- **Why a hunt, not a rule:** Obfuscation is designed to break static signatures, and masquerade is designed to pass name-based trust — so a filename/hash rule is exactly what these techniques defeat, and a hash-only detection is Level-1 on the Summiting scale (the actor changes it trivially). The huntable primitives are higher and softer: file entropy, a bare-numeric command-line argument to an unsigned binary, and mismatch between a trusted-looking name and its Authenticode signer or runtime behavior — all with base rates (packers, numeric CLI args, unsigned tools) too high for a clean standalone rule. Stacking them (high-entropy + bare-numeric key + masqueraded name + decode-then-beacon) is judgement-heavy investigation. The robust core — `msiexec` spawning an unsigned child that is passed a bare numeric key and then beacons (Level-4 implementation-core) — is a candidate to hand to detection-engineering.

## Data sources required

- EDR / Sysmon EID 1 process-create with full command line and Authenticode signer status
- Sysmon EID 7 image-load / binary entropy and packing indicators; MSI package signature/integrity
- Sysmon EID 11 file-create + EID 13 registry (Startup-directory persistence of the decoded RAT)
- Proxy / DNS (post-decode beacon to `connect.il-cert[.]net`, `onlinelive[.]info/wez/*` — decode-then-beacon sequence)
- Newly-registered / lookalike-domain feeds (CERT/brand-impersonating domains; persona impersonation of real groups)

## Query starting point

Platform: `KQL / Microsoft Defender XDR` — bare-numeric de-obfuscation key to an unsigned binary, and name-vs-signer/behavior mismatch

```kusto
// (a) T1027 — unsigned/high-entropy binary handed a bare numeric key on the command line, then beacons
DeviceProcessEvents
| where ProcessCommandLine matches regex @"\b\d{3,5}\b$"        // trailing bare-numeric arg (e.g. 8765)
| where InitiatingProcessFileName =~ "msiexec.exe" or FolderPath has_any (@"\Temp\", @"AppData\Local\Temp")
| extend Signed = tostring(parse_json(AdditionalFields).IsSigned)
| where Signed == "false" or isempty(Signed)
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemoteUrl has_any ("il-cert.net","onlinelive.info","/wez/")
    | project DeviceId, beaconUrl=RemoteUrl, netTime=TimeGenerated) on DeviceId
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, Signed, beaconUrl, netTime

// (b) T1036.005 — trusted-brand filename whose signer is NOT the expected publisher
| union (
  DeviceProcessEvents
  | where FileName has_any ("chrome installer","google chrome") or ProcessVersionInfoOriginalFileName has "chrome"
  | extend Signer = tostring(parse_json(AdditionalFields).Signer)
  | where Signer !has "Google" )   // Chrome-named artifact not signed by Google = masquerade
```

Companion (intel-side): monitor lookalike-domain feeds for CERT/security-brand impersonation (`il-cert`-style) and for personas impersonating real named groups/individuals (Regiment GUD model — pivot to HUNT-02).

## Triage guidance

- **Likely malicious:** an unsigned, high-entropy binary from a Temp/AppData path launched with a bare numeric argument then beaconing to a CERT-lookalike or `/wez/` path; an MSI/installer bearing a trusted brand name (Chrome) whose Authenticode signer is not that vendor; a domain impersonating a real CERT/security brand; a persona impersonating a real activist/political group. Correlate with HUNT-04 staging and the WezRat hashes.
- **Likely benign / expected:** legitimate packers/protectors on signed vendor software; numeric CLI arguments to known tools (ports, timeouts, PIDs); genuine Google-signed Chrome installers; internal tools run from Temp during builds. Allowlist signed vendor installers and known numeric-arg tooling; a valid publisher signature clears the masquerade check.
- **Pivot next:** if a de-obfuscate-then-beacon or signer-mismatch is confirmed, isolate the host, capture the binary and its command-line key for reversing, and pivot to the WezRat detection pack (T1219/T1071.001/T1105/T1082) and Startup-directory persistence. Feed CERT-lookalike and persona-impersonation domains to HUNT-02/HUNT-03. A confirmed decoded-and-beaconing WezRat is a live intrusion → escalate to IR. Hand the `msiexec`→unsigned-child-with-numeric-key robust core to detection-engineering.

## References

- https://www.ic3.gov/CSA/2024/241030.pdf
- https://research.checkpoint.com/2024/wezrat-malware-analysis/
- https://attack.mitre.org/techniques/T1027/
- https://attack.mitre.org/techniques/T1036/005/
