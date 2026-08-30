# Hunt: Reversed-string & runtime-decode obfuscation (BiBi wiper / Karma Shell) — sample & memory hunt

- **Hypothesis:** If Void Manticore tooling is staged in our environment, the destructive commands it will run are **not present as plaintext** in the binaries: the BiBi-Windows-Wiper stores its `vssadmin`/`wmic`/`bcdedit` command strings **byte-reversed** and un-reverses them at runtime, and the Karma Shell **decodes attacker parameters in memory** (base64 then 1-byte XOR key 0x17). A plain-string sweep for `vssadmin delete shadows` will therefore miss the staged wiper. The hunt keys on high-entropy / obfuscated-content and never-before-seen anomalies detectable by content signature rather than log lines: YARA-scan file corpuses and process memory for the *reversed* command strings and BiBi's format specifiers, which are a durable content anchor the adversary cannot drop without abandoning the obfuscation.
- **ATT&CK:**
  - T1140 — Deobfuscate/Decode Files or Information (stealth) — Karma Shell runtime base64+XOR(0x17) parameter decode; BiBi runtime string-reversal
  - T1027 — Obfuscated Files or Information (stealth) — BiBi wiper stores `vssadmin`/`wmic`/`bcdedit` command strings reversed to defeat naive string scanning

- **Actor procedure:** The BiBi-Windows-Wiper holds its embedded recovery-inhibition commands in reverse-byte form (e.g. `lla/ teIuq/ swodahs eteled nimdassv c/ exe.dmc`) and un-reverses them at runtime; Karma Shell decodes its POST parameters with base64 followed by a single-byte XOR (0x17). Both defeat plaintext string scanning, so the destructive commands only exist in cleartext transiently in memory at execution time.
- **Why a hunt, not a rule:** This is explicitly a sample/content-analysis problem — the obfuscation exists precisely to leave *no plaintext log line* to alert on, so there is no execution event to write a rule against until detonation (which is too late). YARA is the right tool used the right way here — **for hunting a file/memory corpus**, not as a production execution detector. The reversed strings and BiBi format specifiers are a Summiting Level-4 implementation-core anchor (the adversary would have to re-tool the obfuscation and rewrite the wiper's command set to break them) — far more durable than any hash (Level-1). If a scan hits, the *decoded* command (`vssadmin delete shadows`, `bcdedit ... recoveryenabled no`) is the robust behavior that belongs to detection-engineering as a runtime rule (see detection pack T1490); the reversed-string content stays a hunt anchor.

## Data sources required

- File corpus for scanning: web-root uploads, `C:\ProgramData`, `%TEMP%`, staging dirs, and any newly-created executables (from HUNT-01/03 file telemetry)
- Live process memory / EDR memory-scan capability (to catch un-reversed strings and decoded Karma Shell params at runtime)
- YARA scanning capability across endpoints (hunt sweep, not resident AV signature)
- Sysmon EID 1 command-line telemetry (secondary — to catch the *decoded* commands if they reach a child cmd.exe)

## Query starting point

Platform: `YARA (hunt sweep over file + memory corpus)` — reversed BiBi command strings and Karma Shell decode markers

```yara
rule VoidManticore_BiBi_ReversedCommands_HUNT
{
    meta:
        author = "MENA Detection Library / threat-hunter"
        description = "HUNT: BiBi-Windows-Wiper reversed recovery-inhibition command strings + format specifiers"
        reference = "https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/"
        usage = "hunt sweep of file corpus AND process memory; NOT a resident detection rule"
    strings:
        // vssadmin / wmic / bcdedit commands stored byte-reversed inside the binary
        $r1 = "lla/ teIuq/ swodahs eteled nimdassv c/ exe.dmc" ascii
        $r2 = "eteled ypocwodahs cimw c/ exe.dmc" ascii
        $r3 = "seruliafllaerongi ycilopsutatstoob }tluafed{ tes / tidedcb c / exe.dmc" ascii
        $r4 = "on delbaneyrevocer }tluafed{ tes/ tidedcb c/ exe.dmc" ascii
        // BiBi format specifiers / status strings (also catch decoded-in-memory form)
        $s1 = "[+] Stats: %d | %d" ascii
        $s2 = "[!] Waiting For Queue " ascii
        $s3 = "DiskName: %s, Deleted: %d - %d" ascii
        // decoded (forward) form, likely only present in memory at runtime
        $d1 = "vssadmin delete shadows" ascii nocase
        $d2 = "bcdedit /set {default} recoveryenabled no" ascii nocase
    condition:
        (uint16(0) == 0x5A4D and (2 of ($r*) or any of ($s*)))    // PE on disk: reversed strings
        or any of ($d*)                                            // memory: decoded commands present
}
```

Secondary pivot (Sysmon) — if the decode already fired into a child shell:

```kusto
DeviceProcessEvents
| where TimeGenerated > ago(21d)
| where ProcessCommandLine has_all ("vssadmin","delete","shadows")
     or ProcessCommandLine has_all ("bcdedit","recoveryenabled","no")
| where InitiatingProcessFileName !in~ ("gpscript.exe")   // exclude known backup/policy tooling per baseline
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine
```

## Triage guidance

- **Likely malicious:** any file-corpus hit on the reversed `cmd.exe`-suffixed command strings (`...eteled nimdassv c/ exe.dmc`) — legitimate software does not store reversed shell commands; a memory-scan hit on the decoded recovery-inhibition commands inside a non-backup process; BiBi format specifiers in an unknown PE in `ProgramData`/`TEMP`. Treat a reversed-string hit as staged wiper — impact is imminent.
- **Likely benign / expected:** rare false positives where the ASCII byte sequences coincide inside compressed/packed data — verify by confirming PE structure and that the strings sit in a readable section; legitimate backup/GPO tooling issuing *forward* `vssadmin`/`bcdedit` (that is normal admin, matched by the secondary query — baseline and suppress known backup agents). The reversed form has no benign explanation.
- **Pivot next:** a wiper-sample hit → treat the host as pre-detonation; isolate, preserve the sample and memory image, block the hash fleet-wide (pivot only), and cross-reference the handoff/destruction chain (HUNT-01) and detection pack T1561.001/.002 + T1490. Hand the *decoded* command behavior to detection-engineering as a runtime recovery-inhibition rule. Confirmed staged wiper → escalate to IR immediately.

## References

- https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/
- https://attack.mitre.org/techniques/T1140/
- https://attack.mitre.org/techniques/T1027/
