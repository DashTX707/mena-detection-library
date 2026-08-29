# Hunt: Charming Kitten payload & command obfuscation / encrypted files (NICECURL / TAMECAT)

- **Hypothesis:** If NICECURL or TAMECAT has landed in our environment, then on disk and in script-block telemetry we should observe the actor's obfuscation tradecraft — high-entropy AES-encrypted payload blobs (`nconf.txt`-style) beside a small PowerShell decrypt helper, VBScript that builds `WScript.Shell` via `StrReverse('llehS.tpircsW')` and base64-decodes operator commands, and AMSI/script-block records showing decode-then-execute — even when static AV sees nothing.
- **ATT&CK:**
  - T1027.010 — Obfuscated Files or Information: Command Obfuscation (stealth)
  - T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File (stealth)

- **Actor procedure:** Payloads are stored encrypted/encoded to defeat static inspection. TAMECAT ships as an AES-encrypted backdoor inside `nconf.txt` (AES key `kNz0CXiP0wEQnhZXYbvraigXvRVYHk1B`, unique-key value `T2r0y1M1e1n1o0w1`) decrypted at runtime by a companion PowerShell, and expects Base64-encoded C2 data. NICECURL obfuscates its logic — `StrReverse` of `'llehS.tpircsW'` to construct `WScript.Shell`, base64-decoded commands. Both wrap logic in layered obfuscation to impede signature analysis; the published YARA rules key on these constants.
- **Why a hunt, not a rule:** Obfuscation and encryption exist precisely to defeat static signatures, so a byte-signature rule is exactly what the actor engineered around — and high-entropy files / base64 blobs have a large benign base rate (installers, certificates, minified JS, legitimate encrypted config). The durable approach is behavioral + YARA-for-hunting: entropy outliers *co-located with a script-host loader*, and AMSI/script-block capture of the *decrypted* stage. That is a retro-hunt / IR-sweep activity, judgement-heavy, run with YARA as a hunting tool over file collections rather than as production detection. Robust behavioral cores (script-host decode→execute, `StrReverse` construction of a COM object) can be handed to detection-engineering; the specific keys/constants are Level-1/2 pivots.

## Data sources required

- PowerShell script-block logging (EID 4104) + AMSI (decrypted/deobfuscated stage)
- Sysmon EID 11 (file create) + EID 1 (process create, command line)
- File collection / EDR file inventory for YARA-for-hunting sweeps (entropy scoring)
- Endpoint file system access to `%TEMP%`, user profile, and script drop paths

## Query starting point

Platform: `Splunk SPL` (Sysmon + PS4104) — script-host loaders next to high-entropy blobs, and the NICECURL/TAMECAT obfuscation constants

```
(index=sysmon EventCode=1 (Image="*\\wscript.exe" OR Image="*\\cscript.exe"
   OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe"))
 OR (index=powershell EventCode=4104)
| eval txt=coalesce(CommandLine, ScriptBlockText)
| search txt="*StrReverse*" OR txt="*llehS.tpircsW*" OR txt="*FromBase64String*"
      OR txt="*[Convert]::FromBase64String*" OR txt="*AesManaged*" OR txt="*CreateDecryptor*"
      OR txt="*kNz0CXiP0wEQnhZXYbvraigXvRVYHk1B*" OR txt="*T2r0y1M1e1n1o0w1*"
      OR txt="*nconf.txt*"
| stats count values(Image) AS proc values(txt) AS evidence
        min(_time) AS first by host User
| sort - count
```

YARA-for-hunting (sweep file collections, not a production sensor):
```
rule CK_NICECURL_TAMECAT_hunt {
  strings:
    $a = "llehS.tpircsW" ascii wide          // StrReverse('WScript.Shell')
    $b = "kNz0CXiP0wEQnhZXYbvraigXvRVYHk1B"  // TAMECAT AES key
    $c = "T2r0y1M1e1n1o0w1"                   // TAMECAT unique-key value
    $d = "Content-DPR" ascii wide
    $e = "--ssl-no-revoke" ascii wide
  condition: 2 of them
}
```

## Triage guidance

- **Likely malicious:** a `.vbs` containing `StrReverse('llehS.tpircsW')` + base64 command decode + curl; a high-entropy blob (`nconf.txt`) sitting beside a small PowerShell that reads it and calls `AesManaged`/`CreateDecryptor`; script-block/AMSI showing a base64/AES-decrypted stage executed immediately; any file hitting 2+ YARA constants above.
- **Likely benign / expected:** legitimate encrypted configs, DPAPI blobs, certificates, minified/packed JS, and admin scripts that use base64 for benign encoding. Entropy alone is not malicious — require the script-host-loader co-location or a constant match. Baseline known encrypted-config paths.
- **Pivot next:** decode the payload/commands, extract embedded C2 (glitch/tebi → HUNT-04, `Content-DPR` → HUNT-05), and reconstruct the delivery chain (LNK/macro → HUNT-07 masquerade). A constant/behavioral confirmation is a live implant → escalate to IR; sweep the estate with the YARA rule. Hand the robust behavioral core (script-host StrReverse-COM / decode-then-exec) to detection-engineering.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/untangling-iran-apt42-operations
- https://attack.mitre.org/groups/G0059
