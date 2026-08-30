# Hunt: Cavern Manticore — ransom/extortion & financial-theft coordination (off-victim)

- **Hypothesis:** If Cavern Manticore has moved to the extortion phase, then the *financial-theft act itself* (ransom demand, negotiation, payment) happens off-victim over email/Tox/actor infrastructure and is not endpoint-observable — but it leaves two correlatable tells: (a) on-victim ransom-messaging staging that precedes the demand (ransom notes written to disk, ransom text planted under `HKLM\SOFTWARE\Policies`, changed logon banners) time-clustered with BitLocker/DiskCryptor encryption, and (b) an *external* corroborator — a low-dollar (~USD 8,000) extortion demand, a ransom note or victim listing naming our org, or cryptocurrency wallet/contact addresses matching this cluster surfacing in intel. The finding is the pairing of an internal encryption+note-planting burst with an off-victim demand keyed to us; either half alone is thin.
- **ATT&CK:**
  - T1657 — Financial Theft (impact) — the extortion/ransom demand and payment for a decryption key; the whole hunt fuses this off-victim act with its on-victim staging tells.
  - T1486 — Data Encrypted for Impact (impact) — cross-referenced: BitLocker/DiskCryptor encryption is the leverage the financial theft monetizes; the note-planting rides on the encryption event.
  - T1490 — Inhibit System Recovery (impact) — cross-referenced: withholding the BitLocker recovery key is what makes the demand payable; recovery-key/protector changes co-occur with the note.

- **Actor procedure:** Cavern Manticore's Cluster A opportunistically encrypts with native **BitLocker** on servers (via `setup.bat` / `Enable-BitLocker` / `manage-bde`) and **DiskCryptor** on workstations (dropped over RDP), then withholds the key and demands a comparatively small ransom — Microsoft observed demands around **USD 8,000**. Ransom messaging is planted on-host, including under `HKLM\SOFTWARE\Policies`, and the negotiation/payment occurs entirely off-victim. This is assessed as financially-motivated activity likely *not* fully state-sanctioned, running alongside the espionage-aligned intrusion set. The low, flat demand and BitLocker-native tradecraft are the distinguishing fingerprints versus big-game ransomware crews.
- **Why a hunt, not a rule:** You cannot alert on "a ransom was demanded" — the demand lives in an attacker's inbox/Tox chat and on their leak/payment infrastructure, entirely off your telemetry (T1657 is inherently off-victim). The on-victim encryption *is* alertable and belongs to the detection pack (T1486). What this hunt adds is the *fusion*: correlating that encryption burst with external extortion intel (a demand or listing naming us, wallet/contact reuse across this cluster's victims) to confirm attribution and motive, and to catch the note-planting/recovery-key-withholding that turns encryption into extortion. That correlation and attribution judgement is hunt work, not a rule. If encryption fires without any external corroborator, it's still an incident — route to the T1486 detection and IR — but the *actor-attribution* piece is the hunt's value.

## Data sources required

- BitLocker operational log (Microsoft-Windows-BitLocker-API/Management) + `manage-bde`/`Enable-BitLocker` process command lines — protector adds, recovery-key changes, volume-encryption starts on non-baselined hosts
- Registry-modification telemetry (Sysmon EID 13 / 4657) on `HKLM\SOFTWARE\Policies` and logon-banner keys; file-write telemetry for ransom-note filenames (readme/decrypt/how-to-recover text files)
- Windows Security 4663 file-create on volume roots and shares (mass note-drop fan-out)
- External / dark-web & extortion intel: ransom demands (~USD 8k), victim listings, ransom-note text, crypto wallet / Tox / email contact reuse keyed to this cluster and to our org/brand/domains (the off-victim half)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — fuse an on-host encryption+note-planting burst with external extortion intel naming us

```kusto
// (a) On-victim: encryption event clustered with ransom-note / policy-key planting on the same host
let encryptStage = union DeviceProcessEvents, DeviceRegistryEvents, DeviceFileEvents
    | where TimeGenerated > ago(30d)
    | where (ProcessCommandLine has_any ("manage-bde","Enable-BitLocker","-EncryptionMethod","dcrypt","DiskCryptor"))
         or (RegistryKey has @"\SOFTWARE\Policies" and RegistryValueData has_any ("ransom","decrypt","bitcoin","contact","recover"))
         or (ActionType == "FileCreated" and FileName matches regex @"(?i)(readme|decrypt|how[-_ ]?to|recover|restore).*\.(txt|hta|html)")
    | summarize signals = make_set(strcat(ActionType,":",coalesce(FileName,RegistryKey,ProcessCommandLine)), 25),
                firstSeen = min(TimeGenerated), lastSeen = max(TimeGenerated), kinds = dcount(ActionType)
             by DeviceName
    | where kinds >= 2;                       // encryption AND note/policy planting = extortion staging, not admin
// (b) Off-victim: external extortion intel keyed to our estate
let extortIntel = ThreatIntelIndicator
    | where Description has_any ("ransom","extortion","BitLocker","8000","8,000","decrypt key","leak")
    | where DomainName in (_GetWatchlist('our_domains')) or Description has_any (_GetWatchlist('our_brand_terms'))
    | project intelTime = TimeGenerated, DomainName, Description;
encryptStage
| extend joinKey = 1 | join kind=leftouter (extortIntel | extend joinKey = 1) on joinKey
| order by lastSeen desc
```

## Triage guidance

- **Likely malicious:** BitLocker/DiskCryptor encryption on a host that was never enrolled in your disk-encryption baseline, co-occurring with ransom-text files and `HKLM\SOFTWARE\Policies` string changes; a recovery-key/protector change you did not initiate immediately before the host goes unreachable; an external extortion demand around the USD-8k mark, or a wallet/Tox/email contact that matches other victims of this cluster, naming our org. The pairing of internal encryption-staging + external demand is a confirmed active extortion.
- **Likely benign / expected:** legitimate BitLocker rollout via MDM/Intune/GPO on *enrolled* hosts is expected — baseline which devices and service accounts encrypt on a normal cadence; IT-authored "how to recover your password" self-service docs and legitimate logon banners will hit note-filename regex; security-tool policy writes under `HKLM\SOFTWARE\Policies` are routine. A protector change through your enrollment tooling by a known admin is not the hunt; an unenrolled server self-encrypting at 3am is.
- **Pivot next:** if encryption + note-planting is confirmed on any host, this is a live ransomware incident — **escalate to incident-response-coordinator immediately**, isolate affected hosts, capture and preserve the ransom note / wallet / contact as attribution intel, and back-hunt the intrusion chain (edge exploit T1190, web shell T1505.003, LSASS dump T1003.001, backdoor accounts T1136.001, FRPC tunneling — HUNT-04). Cross-reference the external demand against this cluster's known extortion contacts to firm attribution.

## References

- https://www.microsoft.com/en-us/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
- https://www.secureworks.com/blog/cobalt-mirage-conducts-ransomware-operations-in-us
- https://attack.mitre.org/techniques/T1657/
- https://attack.mitre.org/techniques/T1486/
- https://attack.mitre.org/techniques/T1490/
