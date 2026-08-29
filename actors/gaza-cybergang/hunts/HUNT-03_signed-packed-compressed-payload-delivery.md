# Hunt: Gaza Cybergang trust-abuse & obfuscated delivery (forged code-signing, packed backdoors, archived executables)

- **Hypothesis:** If Gaza Cybergang delivered a payload into the environment, then artifact + endpoint telemetry will show a *stack* of packaging tells on the same file/host — an executable carrying a forged or reputation-poor "Microsoft" code-signing certificate, a high-entropy packed section (Enigma-protected Spark), and/or an executable that was written to disk immediately after being extracted from a ZIP/RAR archive delivered by mail or a Dropbox link.
- **ATT&CK:**
  - T1553.002 — Subvert Trust Controls: Code Signing (defense-evasion) — forged/abused Microsoft code-signing certificates
  - T1027.002 — Obfuscated Files or Information: Software Packing (defense-evasion) — Spark packed with Enigma protector
  - T1027.015 — Obfuscated Files or Information: Compression (defense-evasion) — executables delivered inside ZIP/RAR
- **Actor procedure:** Gaza Cybergang signs malware with forged/abused Microsoft code-signing certificates to appear trusted; packs the Spark backdoor with the Enigma protector to defeat static analysis; and ships compressed executables inside ZIP/RAR archives (SneakyPastes stagers, IronWind/NimbleMamba archive delivery) to slip past content inspection, decompressing once on the victim.
- **Why a hunt, not a rule:** none of these is malicious alone — most enterprise binaries are signed, packers are common in legitimate software, and archive delivery is ubiquitous. A "packed" or "signed" or "was-in-a-zip" alert would drown in false positives. The value is *stacking* the anomalies (masquerading signer + high entropy + archive-extraction lineage) on the same entity and comparing signer thumbprints against a known-good baseline — analyst correlation, not a threshold. (Concrete malicious certificate thumbprints / sample hashes from the vendor reports go to detection-engineer as blocks.)

## Data sources required

- Sysmon EID 1 (process create with `Signed`/`Signature`/`SignatureStatus`/`Hashes`) and EID 7 (image load with signature)
- Sysmon EID 11 (file create) — executables written by `winrar.exe`/`7z.exe`/`explorer.exe`/mail-client temp extraction, and by browsers from Dropbox links
- Authenticode/certificate inventory (signer CN, thumbprint, validity) and PE entropy/packer-detection from the file-scanning pipeline
- Mail/proxy gateway archive-inspection output

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint source=*Sysmon* EventCode=1
| eval img=lower(Image), signer=lower(coalesce(Signature,'Signature'))
| eval bad_sign=case(
    'SignatureStatus'!="Valid" AND signer!="","invalid_sig",
    match(signer,"microsoft") AND 'SignatureStatus'!="Valid","forged_ms",
    1=1,null())
| join type=left host img [
    search index=endpoint source=*Sysmon* EventCode=11
    | eval img=lower(TargetFilename)
    | where match(img,"\.(exe|dll|scr)$")
    | eval creator=lower(Image)
    | where match(creator,"(winrar|7z|7zfm|explorer|outlook|winzip|chrome|msedge)\.exe$")
    | stats latest(creator) as extracted_by by host img ]
| where isnotnull(bad_sign) OR isnotnull(extracted_by)
| stats values(bad_sign) as sign_flags values(extracted_by) as extracted_by
        values('SignatureStatus') as sig_status count by host, img, signer
| where isnotnull(sign_flags) AND isnotnull(extracted_by)
| sort - count
```

## Triage guidance

- **Likely malicious:** an executable claiming a Microsoft/other well-known signer whose signature is invalid/unverified or whose thumbprint is not on the known-good list (masquerading signer); a high-entropy/packed PE that was just extracted from a RAR/ZIP by WinRAR/Outlook/browser and then executed from `%AppData%`/`%TEMP%`; a signed binary running from a user-writable path. Any two of these stacked is a strong lead.
- **Likely benign / expected:** validly signed vendor software; legitimately packed installers (game/DRM/protected apps); archives users routinely download and run for their job. Baseline signer thumbprints and self-extracting installers per environment.
- **Pivot next:** submit the sample for unpacking/detonation; compare the certificate thumbprint against the vendor-reported forged certs and hand confirmed thumbprints/hashes to detection-engineering (Summiting Level 1 IOCs — blocks, not the hunt basis); tie the extraction event back to the delivering mail/link (HUNT-07) and forward to the post-execution discovery burst (HUNT-02).

## References

- https://attack.mitre.org/groups/G0021/
- https://attack.mitre.org/software/S0543/
- https://unit42.paloaltonetworks.com/molerats-delivers-spark-backdoor/
