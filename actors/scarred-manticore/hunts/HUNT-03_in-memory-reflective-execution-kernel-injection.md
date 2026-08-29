# Hunt: Scarred Manticore in-memory & kernel-driven execution — CLR/Assembly.Load anomalies in w3wp.exe, WINTAPIX driver load, and Donut-shellcode injection into a local-SYSTEM process

- **Hypothesis:** If LIONTAIL/SDD/WINTAPIX is executing on a server, then — because the framework runs payloads from memory, not disk — the evidence lives in reflective-load and driver telemetry: a web/worker process (`w3wp.exe`) loading the CLR and calling `System.Reflection.Assembly.Load` on a dynamically-compiled `App_Web_*.dll` it did not compile from an on-disk `.aspx`, a private/executable memory region (RX, no backing file) inside a server process running shellcode, and/or an unsigned/unfamiliar kernel driver loading and then a local-SYSTEM process suddenly exhibiting an injected thread with no legitimate parent module — the WINTAPIX driver enumerating processes and injecting Donut shellcode.
- **ATT&CK:**
  - T1620 — Reflective Code Loading (stealth) — LIONTAIL runs received shellcode in a new in-memory thread; compiled FOXSHELL loads `App_Web_*.dll` via `Reflection.Assembly.Load` and invokes `ProcessRequest`; WINTAPIX loads an encrypted .NET assembly from memory via Donut
  - T1055 — Process Injection (stealth) — the WINTAPIX kernel driver injects Donut-generated shellcode into a user-mode process running as local SYSTEM
  - T1057 — Process Discovery (stealth) — WINTAPIX enumerates user-mode processes from kernel mode to find a suitable local-SYSTEM injection target
- **Actor procedure:** The toolset is memory-resident by design. LIONTAIL creates a new thread and executes received shellcode in-memory (payload TYPE=1 runs a further shellcode; nested shellcodes end in a fingerprinting payload). The compiled FOXSHELL loads its `App_Web_*.dll` via `System.Reflection.Assembly.Load` and invokes `ProcessRequest`. The WINTAPIX kernel-mode driver (Fortinet-named; Check Point tracks it as SRVNET2) enumerates user-mode processes to find one running with local-SYSTEM privileges, then injects an embedded Donut-generated position-independent shellcode into it; that shellcode loads and executes the encrypted .NET payload combining SDD-backdoor and FOXSHELL (v1.7) functionality. Because the injection is kernel-initiated into a SYSTEM process, it is largely invisible to user-mode EDR.
- **Why a hunt, not a rule:** reflective/in-memory loading avoids disk artifacts and hides execution inside legitimate processes (`w3wp.exe`, a SYSTEM-privileged host), so there is no file-write-then-execute chain to alert on; kernel-driver-initiated injection sits below user-mode EDR's vantage point entirely. `Assembly.Load` and CLR hosting are *normal* for a .NET web server, so a naive load rule is pure noise. The durable observables (Summiting Level 4 — implementation/technique-core: the actor cannot execute without loading code into memory and, for WINTAPIX, without a driver + cross-process injection) are the *anomalous combinations*: an RX private (image-less) memory region executing in a server process; an `Assembly.Load` of an assembly with no corresponding source `.aspx`/temp-compile record; a freshly-loaded unsigned/unusual driver immediately followed by a new thread in a SYSTEM process whose start address has no backing module. Separating these from legitimate JIT, ASP.NET dynamic compilation, and signed driver updates requires memory forensics and per-fleet driver/module baselining — analyst work, not a threshold.

## Data sources required

- Sysmon EID 6 (driver load) — `ImageLoaded`, `Signature`, `SignatureStatus`, `Hashes`; cross-check against the Microsoft vulnerable/blocked-driver list and a known-good driver baseline
- Sysmon EID 7 (image load) with CLR modules (`clr.dll`/`coreclr.dll`, `System.Web.dll`) loaded into an unexpected process; EID 8 (CreateRemoteThread) and EID 10 (ProcessAccess) for cross-process thread/handle activity
- EDR in-memory telemetry: private RX regions with no image backing, unbacked thread start addresses, AMSI/ETW-CLR `Assembly.Load` events (ETW `Microsoft-Windows-DotNETRuntime` / `Loader` events)
- Memory captures (full or process dumps of `w3wp.exe` and SYSTEM processes) for offline scanning (Volatility `malfind`, `ldrmodules`, `driverscan`, `svcscan`)

## Query starting point

Platform: `Splunk SPL` (driver + CLR anomaly), then memory-forensics procedure

```
index=endpoint source=*Sysmon* EventCode=6
| eval drv=lower(ImageLoaded), sig=lower(SignatureStatus)
| where sig!="valid" OR Signature="" OR match(drv,"(?i)\\\\(temp|windows\\\\temp|users|programdata)\\\\")
| table _time host drv Signature SignatureStatus Hashes
| `enrich_known_good_drivers(Hashes)`   /* suppress fleet-baselined signed drivers */
```

```
# CLR reflective load into a web worker where no .aspx source exists
index=endpoint source=*Sysmon* EventCode=7 (ImageLoaded="*clr.dll" OR ImageLoaded="*coreclr.dll")
| eval proc=lower(Image)
| where match(proc,"(?i)\\\\w3wp\.exe$")
| join type=left host [ search index=endpoint source=*Sysmon* EventCode=8
                        | rename SourceImage as Image | fields host Image TargetImage StartAddress ]
| stats values(TargetImage) as injected values(StartAddress) as addrs count by host, proc
```

Memory-forensics procedure (the load-bearing method here): capture the web/SYSTEM process, run `volatility3 windows.malfind` (RX private regions), `windows.ldrmodules` (image-less executed modules — DLL loaded via `Assembly.Load` shows in VAD but not the 3 PEB lists), `windows.driverscan` + `windows.modules` (compare — a driver present in objects but hidden from the module list = WINTAPIX-style stealth), and YARA-scan the dump for the shared XOR/heartbeat constants (HUNT-04/07).

## Triage guidance

- **Likely malicious:** an unsigned/unknown kernel driver loaded from a temp/user path, or a signed-but-unfamiliar driver, immediately preceding an injected thread in a local-SYSTEM process; a private RX (image-less) region executing in `w3wp.exe` or `lsass`/`services.exe`; an `Assembly.Load` of an `App_Web_*.dll` with no matching on-disk `.aspx` compile source; a driver visible to `driverscan` but hidden from the loaded-module list.
- **Likely benign / expected:** legitimate JIT-compiled RX regions and normal ASP.NET dynamic compilation (there *is* a source `.aspx` and a `Temporary ASP.NET Files` entry); signed EDR/AV/hypervisor/storage drivers (baseline the fleet's driver set and suppress); .NET profilers/APM agents that legitimately inject. Signed + known-good hash + backing source clears most.
- **Pivot next:** attribute the host process and pivot to its passive listener (HUNT-01), its proxy/relay behavior (HUNT-02), and its masquerade (HUNT-05); dump and YARA-scan for the encryption constants and heartbeat strings (HUNT-04/07); if WINTAPIX is confirmed, treat the kernel as compromised and the host's own logs as untrustworthy (the FOXSHELL 1.7 EventLog-suspension bypass — detection lane). A confirmed kernel rootkit / SYSTEM injection is a severe active compromise — escalate to incident-response-coordinator immediately (per edge-case: live compromise is an incident, not backlog). A confirmed WINTAPIX driver hash/signing-cert is a durable pivot for detection-engineering (block via WDAC/driver-blocklist).

## References

- https://research.checkpoint.com/2023/from-albania-to-the-middle-east-the-scarred-manticore-is-listening/
- https://www.fortinet.com/blog/threat-research/wintapix-kernel-driver-middle-east-countries
- https://attack.mitre.org/techniques/T1620/
- https://attack.mitre.org/techniques/T1055/
- https://attack.mitre.org/techniques/T1057/
