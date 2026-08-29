# Hunt: WIRTE masquerading & archive obfuscation — system-looking payload names and RAR/ZIP sideload sets that expand to EXE + same-named DLL

- **Hypothesis:** If a WIRTE archive has been delivered and opened, then we should find two stacked tells on the same host: an emailed/downloaded RAR or ZIP that expands into a multi-file sideload set — a legitimate (often renamed) EXE plus a malicious same-named DLL (`version.dll`/`propsys.dll`) and a lure PDF — and payloads named to impersonate system/security components (`MicrosoftEdge.exe`, `csrs.exe`, `Kaspersky Update Agent.exe`, `Windows Defender Agent.exe`, `Microsoft System Manager.exe`, `Microsoft Connection Agent.jpg`) running from a non-standard path or with a PE original-filename/signer that contradicts the on-disk name.
- **ATT&CK:**
  - T1036.005 — Masquerading: Match Legitimate Name or Location (stealth) — system/security-brand payload names run from wrong paths; renamed legit EXEs host sideloads
  - T1027.015 — Obfuscated Files or Information: Compression (stealth) — RAR/ZIP bundling of the EXE + same-named DLL + lure (e.g. `ESETUnleashed_081024.zip`)
- **Actor procedure:** WIRTE packages multi-file infection sets inside RAR/ZIP archives (Arabic-titled RARs with a renamed EXE + lure PDF + malicious DLL; `ESETUnleashed_081024.zip` with legit DLLs + malicious `Setup.exe`) to bundle payloads and hinder inspection at delivery. It then relies on name/location masquerading: legitimate EXEs renamed to Arabic lure titles to host DLL sideloading, and wiper/infector/dropper components named to look like Microsoft or security-vendor binaries (`MicrosoftEdge.exe`, `csrs.exe`, `Kaspersky Update Agent.exe`). Name allow-lists are defeated because the *name* is legitimate; only the *path*, *signer* and *original-filename* betray it.
- **Why a hunt, not a rule:** name-based masquerading is built to beat name allow-lists, and archives with multi-file/nested contents slip past shallow mail-gateway scanning, so neither is reliably alertable on the string alone (Level 1 filename is worthless). The durable discriminators (Summiting Level 2–3) are *property mismatches*: `csrs.exe`/`MicrosoftEdge.exe` running from `%AppData%`/an extraction dir instead of System32, a PE `OriginalFileName`/signer that doesn't match the on-disk name, and an archive that decompresses to an EXE + a *same-named* DLL it will sideload. Judging path/metadata/signer mismatch and archive-content shape against a fleet baseline is analyst correlation, not a threshold.

## Data sources required

- Sysmon EID 1 (process create with `OriginalFileName`, `Signed`/`Signature`, `Hashes`, `Company`) — name vs metadata vs path vs signer mismatch
- Sysmon EID 7 (image load) — a renamed/legit EXE loading a same-named DLL from its own working/extraction directory rather than System32
- Sysmon EID 11 (file create) — archive extraction dropping EXE + same-named DLL + PDF into one folder
- Mail-gateway recursive-archive inspection logs (RAR/ZIP contents), download logs

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint source=*Sysmon* EventCode=1
| eval img=lower(Image), name=mvindex(split(img,"\\"),-1), orig=lower('OriginalFileName'), sig=lower(Signature)
| eval sys_name=if(name IN ("microsoftedge.exe","csrs.exe","csrss.exe","services.exe",
                            "svchost.exe","microsoft system manager.exe","windows defender agent.exe"),1,0)
| eval wrong_path=case(
    name="csrs.exe" OR name="csrss.exe" OR name="svchost.exe" OR name="services.exe",
       NOT match(img,"c:\\windows\\(system32|syswow64)\\"),
    name="microsoftedge.exe", NOT match(img,"(?i)\\\\microsoft\\\\edge\\\\"),
    1=1, 0)
| eval meta_mismatch=if(isnotnull(orig) AND orig!="" AND NOT match(name, replace(orig,"\.","\\.")."$"),1,0)
| eval brandy=if(match(name,"(?i)(kaspersky|defender|microsoft).*(agent|update|manager)\.exe"),1,0)
| where (sys_name=1 AND wrong_path=1) OR meta_mismatch=1 OR (brandy=1 AND (Signed="false" OR sig="")) 
| table _time host User img name orig sig Signed Hashes ParentImage
```

Intersect with Sysmon EID 7 (same-named DLL loaded from the process's own directory) and EID 11 (archive extraction producing EXE + same-named DLL together) on the same host/window.

## Triage guidance

- **Likely malicious:** `csrs.exe`/`MicrosoftEdge.exe`/`svchost.exe` running outside System32/its real install path; an unsigned binary named like a Microsoft/Kaspersky/Defender agent; a PE whose `OriginalFileName`/`Company` contradicts its on-disk name; an extracted folder containing a signed EXE plus a same-named DLL it then loads; a delivered RAR/ZIP whose contents are EXE + DLL + PDF.
- **Likely benign / expected:** genuine Microsoft/vendor binaries running from their correct signed paths; portable admin tools under real names; software installers that legitimately ship same-named helper DLLs in their own dir (baseline these). Signer + correct path together clears most.
- **Pivot next:** hash the DLL/EXE and confirm identity; pivot to the sideload execution and decode chain (HUNT-03), the C2 the loaded DLL beacons to (HUNT-08), and — if the masqueraded name is `csrs.exe`/`MicrosoftEdge.exe` — straight to the SameCoin wiper/infector hunts (HUNT-06, HUNT-09) as these are the wiper's own component names. Confirmed masqueraded WIRTE components on a live host are an active intrusion — escalate to incident-response-coordinator; confirmed hashes go to detection-engineering as blocks (IOC pivots).

## References

- https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/
- https://securelist.com/wirtes-campaign-in-the-middle-east-living-off-the-land-since-at-least-2019/105044/
- https://attack.mitre.org/groups/G0090/
