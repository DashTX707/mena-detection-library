# Hunt: APT33 obfuscated / encrypted-encoded payloads (TURNEDUP / POWERTON / AutoIt droppers)

- **Hypothesis:** If an APT33 payload (TURNEDUP, POWERTON, an AutoIt dropper or a packed commodity RAT) has landed, then on disk and in script-block/AMSI telemetry we should observe its obfuscation tradecraft — high-entropy encrypted/encoded payload blobs co-located with a small script-host loader that reads and decrypts them at runtime, PowerShell/VBScript using `FromBase64String` + `AesManaged`/`CreateDecryptor` or layered string obfuscation to reconstruct and invoke a hidden stage, and AMSI/script-block records that capture the *decrypted* content even when static AV sees only an opaque blob — the encryption defeats signatures but the decode-then-execute behavior surfaces at runtime.
- **ATT&CK:**
  - T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File (stealth)

- **Actor procedure:** Per the G0064 mapping, APT33 encrypts/encodes payloads and configuration to impede static detection — consistent with its encoded `.hta`/HTML-application droppers, AutoIt stagers, packed RATs (DarkComet/NanoCore/QuasarRAT), and the PowerShell-based POWERTON backdoor. The payload lands as an opaque high-entropy artifact; a companion loader decodes/decrypts it in memory and executes, so static inspection of the file on disk reveals nothing.
- **Why a hunt, not a rule:** Encryption and encoding exist precisely to defeat static signatures — a byte-signature rule is exactly what the actor engineered around — and high-entropy files / Base64 blobs have a huge benign base rate (installers, certificates, minified JS, DPAPI blobs, legitimate encrypted config). A standalone "high entropy" or "FromBase64String" rule is unmanageable. The durable approach is behavioral + YARA-for-hunting: entropy outliers *co-located with a script-host loader that reads them*, and AMSI/script-block capture of the decrypted stage — a retro-hunt / IR-sweep run with YARA as a hunting tool over file collections, judgement-heavy → hunt. The robust behavioral core (script-host decode→immediate-execute) can go to detection-engineering; specific keys/paths are Level-1/2 pivots.

## Data sources required

- PowerShell script-block logging (EID 4104) + AMSI (the decrypted/deobfuscated stage)
- Sysmon EID 11 (file create — the blob) + EID 1 (process create, command line — the loader)
- File collection / EDR file inventory for YARA-for-hunting entropy sweeps
- Endpoint access to `%TEMP%`, `%APPDATA%`, user profile and script-drop paths

## Query starting point

Platform: `Splunk SPL` (Sysmon + PS4104) — script-host loaders reading high-entropy blobs and decode-then-exec

```
(index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
   OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe"
   OR Image="*\\AutoIt3*"))
 OR (index=powershell EventCode=4104)
| eval txt=coalesce(CommandLine, ScriptBlockText)
| search txt="*FromBase64String*" OR txt="*AesManaged*" OR txt="*CreateDecryptor*"
      OR txt="*RijndaelManaged*" OR txt="*[System.Text.Encoding]*" OR txt="*-enc *"
      OR txt="*IEX*" OR txt="*Invoke-Expression*" OR txt="*.Deflate*" OR txt="*GzipStream*"
| stats count values(Image) AS proc values(txt) AS evidence min(_time) AS first by host User
| sort - count

/* Pair with entropy: script host that read a file just before decrypting (co-location tell)
index=sysmon EventCode=11 (TargetFilename="*.txt" OR TargetFilename="*.dat" OR TargetFilename="*.bin")
| join host [ search index=sysmon EventCode=1 Image="*\\powershell.exe" ]
| table _time host Image TargetFilename  -- then YARA-entropy-score the file */
```

YARA-for-hunting (sweep file collections for entropy outliers — not a production sensor):
```
rule APT33_encoded_payload_hunt {
  meta: purpose = "hunting only; entropy + loader co-location, not standalone detection"
  strings:
    $ps1 = "FromBase64String" ascii wide
    $ps2 = "CreateDecryptor" ascii wide
    $ps3 = "AesManaged" ascii wide
    $enc = "-enc" ascii wide
    $iex = "Invoke-Expression" ascii wide
  condition:
    // high-entropy section AND a decode helper nearby
    math.entropy(0, filesize) >= 7.2 and 2 of ($ps*, $enc, $iex)
}
```

## Triage guidance

- **Likely malicious:** a high-entropy blob (`.txt`/`.dat`/`.bin`) in `%TEMP%`/`%APPDATA%` sitting beside a small PowerShell/VBScript that reads it and calls `AesManaged`/`CreateDecryptor`; script-block/AMSI showing a Base64/AES-decrypted stage `IEX`-executed immediately; an AutoIt binary dropping and running an obfuscated script; `powershell -enc` with a long encoded blob spawned from Office/mshta.
- **Likely benign / expected:** legitimate encrypted configs, DPAPI blobs, certificates, minified/packed JS, and admin scripts that use Base64 for benign encoding — entropy alone is not malicious. Require the script-host-loader co-location or a decode-then-execute sequence; baseline known encrypted-config paths and signed installers before flagging.
- **Pivot next:** decode the blob/command to recover the payload and any embedded C2, then pivot to the covert channel (HUNT-03) and delivery chain (mshta/`.hta`/macro → detection pack T1204.002/T1203) and persistence (run key/task/WMI). A confirmed decrypted implant is a live incident → escalate to IR and sweep the estate with the YARA rule; hand the decode-then-exec behavioral core to detection-engineering.

## References

- https://attack.mitre.org/techniques/T1027/013/
- https://www.mandiant.com/resources/blog/apt33-insights-into-iranian-cyber-espionage
- https://attack.mitre.org/groups/G0064
