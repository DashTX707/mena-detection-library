# Hunt: Arid Viper — obfuscation, embedded-C2 decoding and sandbox-evasion tradecraft as a sample-analysis / YARA hunting signal

- **Hypothesis:** If an Arid Viper implant (SpyC23 APK or a Micropsia-lineage Windows binary) is present in our sample pool — quarantine, email-attachment sandbox, MDM app store, or endpoint file inventory — then its intrinsic *build tradecraft* is the durable, hard-to-change tell: heavy Base64-plus-substitution string obfuscation in native libraries (`libuoil.so` / `lib-uoil.so` / `libdalia.so`), PyInstaller-packed Windows payloads, runtime decoding of the embedded C2 server details out of those libraries, and anti-emulator/anti-VM checks that make the app malfunction under dynamic analysis. These are *sample-intrinsic* properties an analyst or YARA sweep finds by inspection, not host runtime events. The hunt is a retro-hunt over collected files with YARA/static heuristics, stacking "high-entropy / obfuscated", "path-property mismatch (packed binary masquerading as a document or a benign app)" and "known encoding scheme" primitives to surface actor-family samples the automated verdict engines missed.
- **ATT&CK:**
  - T1027 — Obfuscated Files or Information (stealth) — APKs and native libs (`libuoil.so`, `libdalia.so`, `lib-uoil.so`) carry Base64+substitution string encoding; Windows implants are PyInstaller-packed/obfuscated to defeat static analysis.
  - T1140 — Deobfuscate/Decode Files or Information (stealth) — at runtime the implant decodes the Base64/substitution-encoded C2 server details embedded in the native libraries (e.g. `lib-uoil.so`) and decodes strings/parameters before use.
  - T1497.001 — Virtualization/Sandbox Evasion: System Checks (stealth) — SpyC23 runs anti-virtualization / anti-emulation checks; the app deliberately malfunctions on emulated devices to frustrate dynamic analysis.

- **Actor procedure:** Arid Viper hardens its samples against analysis on both platforms. On **Android**, SpyC23's native libraries (`libuoil.so`, `lib-uoil.so`, `libdalia.so`) apply **Base64 plus a substitution step** (spaces/underscores swapped for hyphens) to obfuscate strings, including the **C2 server details embedded inside the library**, which the app **decodes at runtime** (T1140) before dialing home. SpyC23 also runs **anti-emulator / anti-VM checks** (T1497.001) so it misbehaves in a sandbox, denying analysts clean dynamic traces. On **Windows**, PyMicropsia is **PyInstaller-packaged** and passes **base64-encoded parameters** to its subprocesses, while Micropsia/Arid Gopher variants are packed/obfuscated to hinder static analysis. Because the string scheme and packer choices are relatively stable across the family, they make durable retro-hunt content even as hashes and C2 domains rotate.
- **Why a hunt, not a rule:** obfuscation, in-process decoding and on-device sandbox checks are, by the pack's own assessment, *low* production-detection feasibility — they are **intrinsic properties of the sample observed in analysis, not runtime host events**. There is no endpoint log that fires when a library base64-decodes a string in its own memory, and "the app checks if it's in an emulator" emits nothing to enterprise telemetry. So there is nothing to *alert* on; the value is in a **retro-hunt across the collected-file corpus** with YARA and static heuristics, followed by analyst confirmation of family lineage — classic hunt work, and exactly the sanctioned use of YARA (hunting, not production detection). Where a hunt-grade YARA rule proves precise and stable enough, it can be handed to detection-engineering / the mail-and-MDM scanning pipeline as *hunting* content — but the rule is not a standalone host alert, and the anti-sandbox and runtime-decode behaviors remain analysis-only observations.
- **Visibility note (state it explicitly):** without a malware-analysis pipeline (detonation sandbox + retained sample corpus + YARA retro-hunt capability), T1497.001 and T1140 are *entirely unobservable* in this estate and T1027 is visible only if files are retained and scannable. If that corpus/pipeline does not exist, the primary finding of this hunt is that visibility gap — an actionable input to standing up sample retention + retro-hunt, not a clean result.

## Data sources required

- Retained sample / file corpus: email-attachment and web-download quarantine, EDR collected files, MDM/managed-app-store APK inventory — the objects a YARA retro-hunt runs against
- Detonation-sandbox reports: dynamic-analysis logs showing early bail-out / malformed behavior consistent with anti-emulation, and any strings recovered post-decode
- Static-analysis metadata: file entropy, section/packer signatures (PyInstaller markers), embedded-`.so` presence and names, APK library manifest

## Query starting point

Platform: `YARA (hunting retro-scan over the sample corpus)` — family-tradecraft signatures, not a production host rule

```yara
rule ARIDVIPER_SpyC23_native_lib_obfuscation_HUNT
{
    // HUNT ONLY (T1027/T1140): flags SpyC23 native libs carrying the
    // base64+substitution-encoded embedded C2. Expect FPs — triage, don't alert.
    meta:
        author = "threat-hunter / MENA Detection Library"
        actor  = "Arid Viper / APT-C-23"
        usage  = "retro-hunt over APK/collected-file corpus; confirm by analysis"
        attack = "T1027, T1140"
    strings:
        $lib1 = "libuoil.so"  ascii
        $lib2 = "lib-uoil.so" ascii
        $lib3 = "libdalia.so" ascii
        $lib4 = "libcallrecfix.so" ascii
        // substitution artifact: hyphen-joined tokens where base64 padding/space expected
        $subst = /[A-Za-z0-9+\/]{8,}-[A-Za-z0-9+\/]{8,}-[A-Za-z0-9+\/]{8,}/ ascii
    condition:
        (2 of ($lib*)) and $subst
}

rule ARIDVIPER_PyMicropsia_pyinstaller_pack_HUNT
{
    // HUNT ONLY (T1027): PyInstaller-packed Windows implant carrying base64
    // subprocess params. Legit PyInstaller apps match $py* — corpus-scope + triage.
    meta:
        author = "threat-hunter / MENA Detection Library"
        actor  = "Arid Viper / APT-C-23"
        attack = "T1027"
    strings:
        $py1 = "PyInstaller" ascii
        $py2 = "pyi-windows-manifest-filename" ascii
        $py3 = "_MEIPASS" ascii
        $uri = "/zoailloaze/sfuxmiibif/" ascii   // PyMicropsia C2 URI shape
    condition:
        (2 of ($py*)) and $uri
}
```

Companion static triage (Splunk over sandbox/static-analysis metadata) to surface anti-emulation bail-outs (T1497.001):

```spl
index=malware_sandbox sourcetype=cape:report OR sourcetype=static:meta
| eval anti_emu=if(match(behavior,"(?i)emulator|goldfish|qemu|genymotion|build\.fingerprint|isDeviceRooted"),1,0)
| eval early_exit=if(runtime_seconds<5 AND api_calls<10,1,0)   // bailed out fast in the VM
| eval high_entropy=if(file_entropy>7.2,1,0)                    // packed/obfuscated
| where (anti_emu=1 AND early_exit=1) OR (high_entropy=1 AND embedded_so_present=1)
| stats values(sha256) values(app_package) count by verdict, anti_emu, early_exit, high_entropy
| sort - count
```

## Triage guidance

- **Likely malicious:** an APK whose native libs match the SpyC23 obfuscated-library names *and* carry the base64+substitution string pattern with an embedded (decoded-at-runtime) C2 URL; a sandbox report showing an app that fingerprints the emulator and bails out in seconds while requesting SpyC23-shaped permissions (cross-ref HUNT-04); a PyInstaller binary with the `/zoailloaze/sfuxmiibif/` URI and a document-masquerading icon/name (cross-ref detection pack T1036.007/.008).
- **Likely benign / expected:** PyInstaller is a legitimate packaging tool and high entropy is normal for any packer/installer — `$py*` alone is not a finding; many benign apps embed `.so` libraries and some legitimately check for emulators (DRM, anti-cheat, banking apps). The discriminators are the *specific actor library names*, the substitution-encoding artifact, the embedded persona/Firebase C2 recovered post-decode, and victimology — never flag on packing or an anti-emulator check in isolation.
- **Pivot next:** confirmed family samples → extract the decoded C2 (Firebase project IDs / persona FQDNs) and feed HUNT-03 (infrastructure) and HUNT-04 (mobile C2); pivot the sample hashes across the corpus and EDR file inventory to find where else it landed; if a matched sample is found *installed on a managed device* this is a live compromise — escalate to incident-response-coordinator. Where a YARA rule proves precise/stable, hand it to detection-engineering as **hunting content** for the mail/MDM scanning pipeline (not a host alert). If no sample-retention/retro-hunt pipeline exists, the finding is that visibility gap — recommend standing it up.

## References

- https://www.sentinelone.com/labs/arid-viper-apts-nest-of-spyc23-malware-continues-to-target-android-devices/
- https://blog.talosintelligence.com/arid-viper-mobile-spyware/
- https://unit42.paloaltonetworks.com/pymicropsia/
- https://attack.mitre.org/techniques/T1027/
- https://attack.mitre.org/techniques/T1140/
- https://attack.mitre.org/techniques/T1497/001/
- https://attack.mitre.org/software/S1195/
