# Hunt: UNC1860 in-memory reflective loading and packed/encrypted-at-rest payloads — OATBOAT/SASHEYAWAY shellcode execution, OBFUSLAY packing, CRYPTOSLAY encrypted files decoded only in memory

- **Hypothesis:** If UNC1860 loaders (OATBOAT, SASHEYAWAY) are staging passive backdoors (FACEFACE, SPARKLOAD, TEMPLEDOOR) on a server, then — because the design is memory-resident and the disk artifacts are packed/encrypted — the evidence is a stack of load-time anomalies: (a) a server process holding a private, executable (RX), image-less memory region running shellcode with no backing file (reflective/in-memory execution), correlated with (b) an on-disk stager/payload file with very high entropy and no valid signature (OBFUSLAY packing / CRYPTOSLAY encryption at rest), where the file is decrypted/decoded only at runtime. A high-entropy blob alone is thin (installers, compressed data); the finding is the high-entropy artifact *stacked on* a reflective in-memory load inside a web/server process with no legitimate compile source.
- **ATT&CK:**
  - T1620 — Reflective Code Loading (stealth) — OATBOAT executes shellcode payloads directly in memory; SASHEYAWAY loads passive backdoors (FACEFACE, SPARKLOAD) reflectively rather than dropping executables to disk
  - T1027.002 — Obfuscated Files or Information: Software Packing (stealth) — OBFUSLAY packs/obfuscates payloads; SASHEYAWAY-delivered implants are packed to keep static-AV detection rates low
  - T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File (stealth) — CRYPTOSLAY encrypts payloads at rest so on-disk stages (loader payloads carried by SASHEYAWAY/OATBOAT) are stored encrypted/encoded and decrypted only in memory

- **Actor procedure:** The toolset is memory-resident by design. OATBOAT is a loader that executes shellcode payloads directly in memory; SASHEYAWAY is a dropper that delivers/executes passive backdoors (FACEFACE, SPARKLOAD) with low detection by loading them reflectively rather than writing executables to disk. Payloads are protected end-to-end: OBFUSLAY obfuscates/packs them and CRYPTOSLAY encrypts them at rest, so the on-disk loader stages and implant payloads are stored encrypted/encoded and only reversed (decode-then-execute) in memory at runtime — the on-disk form defeats static AV signatures and the in-memory form leaves little host telemetry.
- **Why a hunt, not a rule:** reflective/in-memory loading avoids the file-write-then-execute chain that most host detections key on, and hides execution inside legitimate server processes; packing/encryption at rest defeats static AV, so there is no signature to match. High entropy and RX private regions are individually far too common (installers, compressed assets, JIT-compiled code, .NET dynamic compilation) for a standalone rule. The durable observable (Summiting Level 4: implementation/technique-core — the actor cannot execute a passive backdoor without loading code into memory, and cannot ship it past static AV without packing/encrypting it) is the *combination*: an image-less RX region executing in a web/server process **with no matching on-disk source or temp-compile record**, correlated to a high-entropy, unsigned artifact that is read and decoded in memory shortly before the region appears. Separating that from legitimate JIT/ASP.NET compilation and packed-but-benign software requires memory forensics and per-process baselining — analyst work.

## Data sources required

- EDR in-memory telemetry: private RX regions with no image backing, unbacked thread start addresses, and (for .NET stages) AMSI / ETW-CLR `Assembly.Load` events (`Microsoft-Windows-DotNETRuntime` / `Loader`)
- Sysmon EID 7 (image load) with CLR modules (`clr.dll`/`coreclr.dll`) loaded into an unexpected server process; EID 8 (CreateRemoteThread) for injected threads
- Sysmon EID 11 (file create) with on-disk entropy computed at ingest, or a scheduled entropy sweep of web-content / temp / ProgramData paths — flag high-entropy (> 7.2 Shannon) unsigned files
- Memory captures (process dumps of `w3wp.exe` / server host processes) for offline scanning (Volatility3 `malfind`, `ldrmodules`) and YARA of decoded in-memory content

## Query starting point

Platform: `Splunk SPL` (reflective-load anomaly + high-entropy on-disk correlate), then memory-forensics procedure

```
# (a) Image-less RX execution / CLR reflective load in a web/server worker with no source .aspx
index=endpoint source=*Sysmon* EventCode=7 (ImageLoaded="*clr.dll" OR ImageLoaded="*coreclr.dll")
| eval proc=lower(Image)
| where match(proc,"(?i)\\\\(w3wp|inetinfo|svchost)\.exe$")
| join type=left host [ search index=endpoint source=*Sysmon* EventCode=8
                        | rename SourceImage as Image | fields host Image TargetImage StartAddress ]
| table _time host proc TargetImage StartAddress

# (b) High-entropy, unsigned on-disk stager in server-writable paths, time-near a reflective load
index=endpoint source=*Sysmon* EventCode=11
| where match(TargetFilename,"(?i)\\\\(inetpub|temp|programdata|windows\\\\temp)\\\\")
| lookup file_entropy TargetFilename OUTPUT entropy, signed
| where entropy > 7.2 AND signed="false"
| stats min(_time) as first values(TargetFilename) as files by host
```

Memory-forensics procedure (the load-bearing method): dump the server process and run Volatility3 `windows.malfind` (private RX / image-less regions running shellcode), `windows.ldrmodules` (a module executed via reflective load appears in the VAD but not the 3 PEB lists), then YARA-scan the *decoded* in-memory content for the shared OBFUSLAY/CRYPTOSLAY constants and OATBOAT/SASHEYAWAY toolmarks (HUNT-06). The runtime decode-then-execute is the moment the encrypted-at-rest payload becomes readable — capture memory while the process is live.

## Triage guidance

- **Likely malicious:** a private RX (image-less) region executing shellcode in `w3wp.exe` / `inetinfo.exe` / a SYSTEM-privileged server process with no backing file; a CLR/`Assembly.Load` with no matching on-disk source or `Temporary ASP.NET Files` compile record; a high-entropy, unsigned blob in `inetpub`/`temp`/`ProgramData` that is read and reversed in memory shortly before an RX region appears; any of these on a passive-listener host (HUNT-01) or a host with a suspect driver (HUNT-03).
- **Likely benign / expected:** legitimate JIT-compiled RX regions and normal ASP.NET dynamic compilation (there *is* a source `.aspx` and a `Temporary ASP.NET Files` entry); .NET profilers/APM agents that inject legitimately; genuinely high-entropy but benign files (installers, compressed archives, media, signed packers). Signed + known-good hash + a matching compile source clears most; entropy alone is not a finding.
- **Pivot next:** attribute the host process and pivot to its passive listener (HUNT-01), the kernel driver that may have injected it (HUNT-03), and the masquerade check on any dropped image (HUNT-05); YARA-scan the dump for the encryption constants / toolmarks and cluster the sample (HUNT-06); cross-reference the detection lane for runtime decode-then-execute via AMSI (T1140). A confirmed reflective backdoor resident in a live server process is an active espionage intrusion — escalate to incident-response-coordinator. A verified in-memory YARA signature over the decoded payload is a durable pivot for detection-engineering (Summiting Level 3–4).

## References

- https://securityaffairs.com/168656/apt/unc1860-provides-iran-linked-apts-access-middle-east.html
- https://thehackernews.com/2024/09/iranian-apt-unc1860-linked-to-mois.html
- https://attack.mitre.org/techniques/T1620/
- https://attack.mitre.org/techniques/T1027/002/
- https://attack.mitre.org/techniques/T1027/013/
