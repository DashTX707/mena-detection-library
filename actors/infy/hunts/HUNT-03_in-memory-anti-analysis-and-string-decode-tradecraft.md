# Hunt: Infy (Prince of Persia) — in-memory anti-analysis (window-name checks) & string decode/encode tradecraft

- **Hypothesis:** Infy/Foudre carry a stable, decade-consistent in-memory tradecraft that survives IOC rotation: an anti-analysis / prior-infection **window-name guard** (Infy searches for keylogger window `TRON2VDLLB`; Foudre searches for a window named `foudre<version>` with class `TNRRDPKE`) and a **runtime string-decode** step (Foudre XOR-deobfuscates its strings; Infy reuses fixed string-encoding keys and ZIP-password obfuscation). If an implant is resident, then in a memory scan or behavioral trace these constants appear in a *loader-shaped* process — a `rundll32.exe` or an unsigned DLL loaded from a user-writable path (`SnailDriver` dir) that enumerates windows by name/class and holds high-entropy blobs that resolve to plaintext C2/URL strings after a single-byte XOR. No single primitive is decisive (window enumeration and XOR are everywhere); the *stack* — masquerading loader + window-name constant + high-entropy-then-decoded strings in the same process — is the finding, and it is durable because the operator would have to abandon the anti-analysis design and re-key the obfuscator to evade it.
- **ATT&CK:**
  - T1497.001 — System Checks (stealth) — window-name / environment guard (`TRON2VDLLB`, `foudre<version>`/class `TNRRDPKE`) used to detect prior infection or an analysis condition before proceeding; hunt via memory/YARA for the constants in a loader-shaped process.
  - T1010 — Application Window Discovery (discovery) — explicit enumeration of windows by name/class (`FindWindow`/`EnumWindows` on `TRON2VDLLB` / `TNRRDPKE`) to detect prior infection and to support keylogging context.
  - T1140 — Deobfuscate/Decode Files or Information (stealth) — Foudre XOR-decodes strings at runtime; Infy reuses fixed decode keys + ZIP-password obfuscation; hunt via memory/YARA for high-entropy blobs that decode to C2/URL plaintext.
  - T1132.001 — Standard Encoding (command-and-control) — consistent XOR string-encoding / ZIP-password encoding of stored strings and C2 content; the encode side of the same obfuscator, hunted as the encoded-at-rest counterpart of the runtime decode.

- **Actor procedure:** Before doing work, Infy checks the environment: it looks for a specific window as a prior-infection / analysis guard — the Infy keylogger operates under window name `TRON2VDLLB`, and Foudre searches for a window named `foudre<version>` with class `TNRRDPKE`. Foudre de-obfuscates its strings at runtime with an XOR-based routine, and Infy has reused consistent string-encoding/decryption keys and ZIP-password obfuscation across the decade-long campaign (SFX key `1qaz2wsx3edc`, document-capture ZIP password `Z8(2000_2001uI)`). These constants and the window-name guard are unusually stable across generations, which makes them a high-value memory-hunt target: the loader (Foudre's DLL run via `rundll32.exe` from `%ALLUSERSPROFILE%\AppData\SnailDriver V<ver>`) will, in memory, hold both the window-name strings and the encoded blobs.
- **Why a hunt, not a rule:** `FindWindow`/`EnumWindows` and single-byte XOR are among the most common benign operations in Windows software — a standalone alert on either produces nothing but false positives, and neither leaves reliable event-log telemetry (this is why the lane is hunt, not detect). Finding it requires targeted memory acquisition + YARA across a candidate set (loader-shaped processes) and analyst confirmation that the entropy blob decodes to real C2 strings — investigation, not alerting. The window-name and class constants (`TRON2VDLLB`, `TNRRDPKE`, `foudre<version>`) are Level-4/5 implementation-core observables on the Summiting scale: the operator cannot change them without re-architecting the anti-analysis guard. If a scan reliably ties the constant to a loader-path + rundll32 lineage, hand *that* memory-YARA signature to detection-engineering for scheduled scan-based deployment; do not attempt a real-time event alert.

## Data sources required

- Endpoint memory: on-demand memory acquisition / live-process YARA scanning (Volatility `yarascan`/`malfind`, EDR memory-scan capability) across candidate loader-shaped processes.
- Sysmon EID 7 (image-load) + EID 1 (process-create) to build the candidate set: unsigned DLLs loaded from user-writable paths (`SnailDriver`), and `rundll32.exe` launched from non-standard paths/exports.
- File telemetry for the encode-at-rest counterpart: high-entropy dropped files and password-protected/SFX archives (entropy + archive-utility telemetry).

## Query starting point

Platform: `EDR (memory-scan YARA)` + candidate-set query. Scope the YARA scan to loader-shaped processes surfaced by the pre-filter below, then scan memory for the durable constants.

```yara
rule Infy_Foudre_inmem_window_guard_and_decode_HUNT
{
    meta:
        author  = "threat-hunter / MENA Detection Library"
        purpose = "HUNT ONLY - memory/loader scan, not a production alert"
        actor   = "Infy / Prince of Persia (Foudre)"
        attck   = "T1497.001, T1010, T1140, T1132.001"
    strings:
        $win1 = "TRON2VDLLB" ascii wide            // Infy keylogger window (T1010/T1497.001)
        $win2 = "TNRRDPKE"  ascii wide             // Foudre window class     (T1010/T1497.001)
        $win3 = "foudre"    ascii nocase           // Foudre window-name prefix
        $api1 = "FindWindowA" ascii
        $api2 = "EnumWindows" ascii
        $obf1 = "1qaz2wsx3edc" ascii wide          // reused SFX/decode key   (T1140/T1132.001)
        $obf2 = "Z8(2000_2001uI)" ascii wide       // reused ZIP password     (T1132.001)
        $path = "SnailDriver" ascii wide           // loader drop path        (context)
    condition:
        // window-name guard constant AND (a window-enum API OR a reused obfuscation key OR the loader path)
        (any of ($win*)) and (1 of ($api*) or any of ($obf*) or $path)
}
```

Candidate-set pre-filter (Sentinel KQL) to decide *which* processes to memory-scan:

```kusto
DeviceImageLoadEvents
| where Timestamp > ago(14d)
| where FolderPath has_any (@"SnailDriver", @"\AppData\", @"\ProgramData\")   // user-writable loader paths
| where InitiatingProcessFileName =~ "rundll32.exe" or IsSigned == false
| summarize loads=count(), paths=make_set(FolderPath,10) by DeviceName, InitiatingProcessFileName, SHA1
| order by loads desc
```

## Triage guidance

- **Likely malicious:** a memory scan hits a window-name constant (`TRON2VDLLB` / `TNRRDPKE` / `foudre<ver>`) inside a rundll32 or unsigned-DLL process loaded from a `SnailDriver`/AppData path, *and* the same region holds high-entropy blobs that XOR-decode to C2 URLs or the reused keys — the stacked signal. Presence of the reused obfuscation constants (`1qaz2wsx3edc`, `Z8(2000_2001uI)`) in any resident process is on its own highly suspicious given they are actor-specific.
- **Likely benign / expected:** window-enumeration APIs and XOR are ubiquitous — accessibility tools, screen recorders, RDP clients, packers and legitimate installers all enumerate windows and hold obfuscated/compressed blobs. A hit on `FindWindow`/`EnumWindows` or a high-entropy region *without* an actor-specific constant is not a finding. Do not flag the entropy blob alone; require the window-name or reused-key constant alongside it.
- **Pivot next:** on a confirmed hit, dump the decoded strings for C2 domains/URLs and feed them into HUNT-01 (cert/DGA) and the detection-lane C2 hunts; identify the loader DLL + rundll32 lineage and pivot to persistence (T1547.001 / T1053.005) and the SnailDriver drop. A resident implant confirmed via memory is a live compromise — escalate to incident-response-coordinator and preserve a full memory image for forensic timeline.

## References

- https://unit42.paloaltonetworks.com/prince-of-persia-infy-malware-active-in-decade-of-targeted-attacks/
- https://unit42.paloaltonetworks.com/unit42-prince-persia-ride-lightning-infy-returns-foudre/
- https://unit42.paloaltonetworks.com/unit42-prince-of-persia-game-over/
- https://attack.mitre.org/techniques/T1497/001/
- https://attack.mitre.org/techniques/T1010/
- https://attack.mitre.org/techniques/T1140/
- https://attack.mitre.org/techniques/T1132/001/
