# Hunt: Agrius anti-forensics & masquerading — renamed tooling, embedded-payload droppers, self-deletion and timestomping around the wipe

- **Hypothesis:** If an Agrius wiper (MultiLayer / PartialWasher / BFG Agonizer) or its tooling is staged on a host, then we should find a *stack* of tradecraft tells on the same file/host: a binary whose PE VERSIONINFO original-filename or hash matches a known tool but whose on-disk name is disguised (Plink → `systems.exe`, GMER → `AGMT.sys`); a dropper that writes out an embedded assembly + batch scripts, runs them, then deletes itself and them (file-create-then-self-delete within seconds); and files whose NTFS timestamps have been stomped to implausible epoch values (`1601-01-01` NTFS / `1980-01-01` non-NTFS) — a combination that legitimate software effectively never produces together.
- **ATT&CK:**
  - T1036 — Masquerading (defense-evasion) — Plink renamed `systems.exe`, GMER renamed `AGMT.sys`
  - T1027.009 — Obfuscated Files or Information: Embedded Payloads (defense-evasion) — MultiLayer carries an embedded assembly + batch scripts written and executed at runtime
  - T1070.004 — Indicator Removal: File Deletion (defense-evasion) — MultiLayer deletes its dropped assembly, batch scripts and itself after execution
  - T1070.006 — Indicator Removal: Timestomp (defense-evasion) — MultiLayer overwrites Creation/LastWrite/LastAccess to 1601-01-01 (NTFS) / 1980-01-01 (non-NTFS)
- **Actor procedure:** Agrius disguises tooling by renaming it to blend with system files and drops vulnerable drivers under innocuous names. Its MultiLayer wiper carries embedded payloads (a dropped .NET assembly and batch scripts), writes them to disk, executes them (including the log-clearing scheduled task — see HUNT-06), then removes all files it used to hinder forensics, and timestomps files to extreme epoch values so timeline reconstruction fails. These evasions cluster tightly around the destructive routine, making them a last-chance early-warning band before/at detonation.
- **Why a hunt, not a rule:** each tell is individually noisy or invisible — renamed binaries evade name-based rules (Level 1 filename is worthless here; anchor on PE metadata/hash, Level 2–3), self-deletion overlaps with benign installer cleanup, and timestomping leaves almost no live telemetry (it surfaces in forensic MFT triage: `$STANDARD_INFORMATION` vs `$FILE_NAME` divergence). No one of them is alertable. The find is the *stack* on one entity — name/metadata mismatch **and** dropper self-deletion **and** implausible timestamps — which is analyst correlation across live EDR plus forensic artifacts, not a threshold.

## Data sources required

- Sysmon EID 1 (process create with `OriginalFileName`, `Hashes`) and EID 7 (image load) — original-filename vs on-disk-name mismatch, known-tool hash match
- Sysmon EID 11 (file create) + EID 23/26 (file delete / delete-detected) — create-then-delete of just-dropped executables/scripts
- Sysmon EID 2 (file-creation-time changed) — timestomp signal on live hosts
- Forensic triage: MFT (`$SI` vs `$FN` timestamp divergence, implausible 1601/1980 stamps), `$J` USN journal
- EDR file/process-lineage telemetry

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint source=*Sysmon* EventCode=1
| eval img=lower(Image), orig=lower('OriginalFileName')
| eval mism=case(
    orig="plink.exe" AND NOT match(img,"plink\.exe$"),"plink_renamed",
    match(orig,"gmer") AND NOT match(img,"gmer"),"gmer_renamed",
    isnotnull(orig) AND orig!="" AND NOT match(img, replace(orig,"\.","\\.")."$"),"name_meta_mismatch",
    1=1,null())
| where isnotnull(mism)
| table _time host User img orig mism Hashes ParentImage
```
Companion signals to intersect on the same `host`/file within a short window:
EID 2 (timestomp: `PreviousCreationUtcTime` normal → `CreationUtcTime` = 1601-01-01 or 1980-01-01);
EID 11→23/26 (an `.exe`/`.dll`/`.bat` created then deleted within seconds by the same or child process).

## Triage guidance

- **Likely malicious:** a binary whose PE original-filename/hash is Plink/GMER/a known tool but is on disk as `systems.exe`/`AGMT.sys`/another system-looking name; a process that drops a `.bat` + assembly, runs them, then deletes itself and them within seconds; any file with a creation/write time of `1601-01-01` or `1980-01-01`; a `.sys` written to a non-standard path then loaded (ties to BYOVD, detection lane). Any two stacked on one host is a strong pre-wipe lead.
- **Likely benign / expected:** legitimate installers that unpack helpers and clean up after themselves; portable admin tools run under their real names; software with genuinely old, but plausible, timestamps. Baseline known self-extracting installers and legitimate portable-tool usage; implausible-epoch stamps are effectively never benign.
- **Pivot next:** hash the renamed binary and confirm identity; if it is Plink/pscp pivot to exfil (detection lane), if a driver loader pivot to BYOVD/service-stop (detection lane) and the wipe tail (HUNT-06). Correlate with the staging chain (HUNT-01) and log-clear scheduled task (HUNT-06). Confirmed wiper tooling with anti-forensics staged on a live host is pre-detonation — escalate to incident-response-coordinator immediately. Confirmed renamed-tool hashes are durable enough to hand to detection-engineering as blocks (Level 1 IOC pivots, not the hunt basis).

## References

- https://unit42.paloaltonetworks.com/agonizing-serpens-targets-israeli-tech-higher-ed-sectors/
- https://www.sentinelone.com/labs/from-wiper-to-ransomware-the-evolution-of-agrius/
- https://attack.mitre.org/groups/G1030/
