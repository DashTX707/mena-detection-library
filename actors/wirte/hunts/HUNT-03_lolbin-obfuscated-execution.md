# Hunt: WIRTE LOLBIN & obfuscated execution — cmd.exe PDF decoys, regsvr32 proxying, native-API payload assembly and runtime XOR/Base64 decode

- **Hypothesis:** If a WIRTE loader has executed on a host, then we should find living-off-the-land execution paired with runtime deobfuscation on the same process lineage: a sideloaded/lure-host binary spawning `cmd.exe` to open a decoy PDF (making the launch look benign), `regsvr32.exe` proxy-executing an unusual/remote DLL or scriptlet (squiblydoo-style, the earliest WIRTE LotL), a loader assembling its next stage in memory via native APIs (`RtlIpv4StringToAddressA` over a long list of IP-formatted strings), and freshly-decoded/decrypted executables being written to disk right after a Base64+XOR or oref-key-derived decode — a stack that individually looks routine but co-occurs in one short chain.
- **ATT&CK:**
  - T1059.003 — Command and Scripting Interpreter: Windows Command Shell (execution) — sideload host spawns `cmd.exe` to open the lure PDF
  - T1218.010 — System Binary Proxy Execution: Regsvr32 (stealth) — earliest WIRTE LotL, regsvr32 proxy execution
  - T1106 — Native API (execution) — `propsys.dll` reassembles payload via `RtlIpv4StringToAddressA` over embedded IP-strings
  - T1027.010 — Obfuscated Files or Information: Command Obfuscation (stealth) — XOR keys (`01-01-1900`, `53`), Base64, hidden XLM formulas, HTML-tag-embedded payloads
  - T1140 — Deobfuscate/Decode Files or Information (stealth) — runtime Base64→XOR decrypt of stages; SameCoin derives XOR key from the oref.org.il response
- **Actor procedure:** WIRTE's IronWind/Havoc chains save the lure as a PDF and open it via `cmd.exe` so the user sees a document while the sideloaded DLL runs in the background; the earliest (Lab52) activity used `regsvr32.exe` as the LotL proxy. `propsys.dll` reconstructs its next stage by iterating a long embedded list of IP-formatted strings through `RtlIpv4StringToAddressA` and concatenating the bytes. Obfuscation is pervasive — XOR-encrypted strings (`01-01-1900`, IronWind key `53`), Base64, Excel-4.0 formulas hidden in secondary sheets, and payloads embedded between HTML tags — decoded at runtime, with the Oct-2024 SameCoin loader deriving its XOR key from the first bytes of the oref.org.il HTTP response before writing decrypted wiper/infector files to disk.
- **Why a hunt, not a rule:** every primitive is ubiquitous or telemetry-poor on its own — `cmd.exe` and `regsvr32.exe` fire constantly, native-API calls leave almost no discrete log, and obfuscation is *designed* to defeat static inspection. None is alertable alone. The durable find (Summiting technique-core/behavioral, Level 3–4) is the *lineage + timing*: an archive-extracted or renamed binary → `cmd.exe` opening a PDF while the same parent decodes and drops an executable, or `regsvr32` loading a DLL from a user-writable path with a network fetch. That requires baselining who normally spawns `cmd.exe`/`regsvr32` and correlating file-decode-then-write — analyst work, not a signature.

## Data sources required

- Sysmon EID 1 / Windows Security 4688 — process create with full command line + parent (`cmd.exe`, `regsvr32.exe`, PDF opens, sideload hosts)
- Sysmon EID 7 (image load) — `regsvr32`/lure-host loading DLLs from non-System32/extraction paths
- Sysmon EID 11 (file create) — freshly-decoded `.exe`/`.dll` writes right after decode
- AMSI / PowerShell 4104 script-block content (for scripted decode routines); proxy logs (oref.org.il fetch preceding decode)
- EDR API-telemetry where available (`RtlIpv4StringToAddressA` / in-memory assembly)

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint source=*Sysmon* EventCode=1
| eval img=lower(Image), pimg=lower(ParentImage), cl=lower(CommandLine)
| eval sig=case(
    img="c:\\windows\\system32\\cmd.exe" AND match(cl,"\.pdf") AND NOT match(pimg,"(explorer|winword|acrobat|acrord32)\.exe$"),"cmd_opens_pdf",
    img="c:\\windows\\system32\\regsvr32.exe" AND (match(cl,"/i:http") OR match(cl,"scrobj") OR match(cl,"\\\\(users|programdata|temp|appdata)\\\\")),"regsvr32_proxy",
    match(pimg,"(?i)(setup_wm|pinenrollmentbroker|setup)\.exe$") AND img="c:\\windows\\system32\\cmd.exe","sideloadhost_spawns_cmd",
    1=1,null())
| where isnotnull(sig)
| table _time host User img pimg cl sig
```

Intersect on the same host/window with Sysmon EID 11 writes of `.exe`/`.dll` into `%ProgramData%`/`%AppData%`/extraction dirs (decode-then-drop), and with a preceding proxy fetch to `oref.org.il` (SameCoin key derivation — ties to HUNT-06).

## Triage guidance

- **Likely malicious:** a renamed/archive-extracted binary spawning `cmd.exe` to open a PDF while a same-named DLL loads from its own directory; `regsvr32` fetching `/i:http...` or loading a DLL from `%ProgramData%`/`%AppData%`; an executable written to disk seconds after a scripted Base64/XOR decode or an oref.org.il fetch; `RtlIpv4StringToAddressA`-driven in-memory assembly if your EDR sees it.
- **Likely benign / expected:** `cmd.exe` and `regsvr32.exe` in genuine admin/installer workflows; developers Base64-decoding content; legitimate software registering COM DLLs from Program Files. Baseline the parents that normally spawn these LOLBINs and the paths COM DLLs are legitimately registered from.
- **Pivot next:** confirm the sideload host and dropped-DLL identity (HUNT-05), the C2 fetch that fed the decode (HUNT-08), and the persistence written after (HUNT-04). If the decode was keyed off oref.org.il, treat as SameCoin pre-detonation and jump to HUNT-06 immediately. A confirmed loader decoding and dropping a second stage on a live host is an active intrusion — escalate to incident-response-coordinator.

## References

- https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/
- https://securelist.com/wirtes-campaign-in-the-middle-east-living-off-the-land-since-at-least-2019/105044/
- https://attack.mitre.org/groups/G0090/
