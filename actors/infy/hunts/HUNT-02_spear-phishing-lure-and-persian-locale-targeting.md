# Hunt: Infy (Prince of Persia) — spear-phishing document delivery, social lures & Persian-locale target selection

- **Hypothesis:** Infy is a dissident-surveillance operation that hand-picks victims, so if a weaponized lure has landed and run, the on-victim tell is not just the macro drop but a *target-selection* pattern: shortly after an Office document or self-extracting archive spawns a child process, the implant queries system/keyboard **language and locale** (Persian/Farsi, Iranian timezone) — consistent with an operator confirming they hit a Persian-speaking dissident/diaspora/embassy target before committing higher-value tooling. The falsifiable pair is *document-lineage execution* → *immediate locale/language enumeration by the same process tree*, on a host that received an inbound Office/archive attachment from an external, low-history sender bearing politically-themed Persian filenames (e.g. ISAAR-themed, `Biranvand`, Dorud-governor lure content). A locale query alone is benign OS behavior; a locale query fired by a just-dropped child of `WINWORD.EXE`/an `ins*.exe` SFX is not.
- **ATT&CK:**
  - T1614.001 — System Language Discovery (discovery) — implant/keylogger performs language identification of the host (locale, keyboard layout) to confirm a Persian-speaking target before proceeding; hunt by correlating the locale query with immediately-preceding lure execution.
  - T1566.001 — Spearphishing Attachment (initial-access) — *context* for the delivery: politically-themed Persian Word/PowerPoint + SFX attachments from low-history external senders that precede the locale check. (Detection-lane technique; cited as the delivery half of the correlation.)
  - T1204.002 — Malicious File (execution) — *context* for the user-execution event (document open / SFX double-click) that fathers the locale-discovery process. (Detection-lane technique; cited as the execution pivot.)

- **Actor procedure:** Across all generations Infy's initial access is spear-phishing carrying a weaponized Word/PowerPoint or a self-extracting archive, tailored to Iranian dissidents, expatriates, Persian-language media and Middle Eastern/European diplomats. Tonnerre lures used politically-themed Word documents (a photo of Dorud city governor Mojtaba Biranvand; ISAAR-themed content). Infy SFX archives (`ins*.exe`) present a fake video-player UI with decoy `readme.txt`/image/video to socially engineer a "Run" click. Once running, the Infy keylogger performs **language identification** of captured keystrokes and the operation collects locale/timezone context — the operator's way of confirming they landed on the intended Persian-speaking target population before escalating to the higher-value Tonnerre implant on "machines of interest."
- **Why a hunt, not a rule:** A `GetUserDefaultUILanguage` / `GetKeyboardLayoutList` / locale-registry read is one of the highest-frequency benign calls on Windows — alerting on it would bury the SOC. It is *only* meaningful in the tight lineage window right after a lure executes, fused with the mail-side context (external low-history sender, Persian politically-themed attachment name). That correlation, and the "is this a targeted Persian-language lure or a normal localized app checking its UI language" judgement, is analyst work. If a durable sub-pattern emerges — e.g. a freshly-dropped child of an Office/SFX process reading the locale then writing a keystroke-log file — route that lineage to detection-engineering (Summiting: process-lineage relational observable), not the raw locale API.

## Data sources required

- Mail-gateway / Defender for Office 365 logs: inbound attachments (file type, name, external sender reputation/first-seen), for the Persian politically-themed lure half.
- EDR / Sysmon process-creation (EID 1) with full command line and parent lineage — to catch `WINWORD.EXE`/`POWERPNT.EXE`/`ins*.exe` fathering a child that then queries locale.
- EDR API/registry telemetry (Sysmon EID 12/13 on locale keys, e.g. `HKCU\Keyboard Layout\Preload`, `HKCU\Control Panel\International`) or EDR API-call events for language/keyboard enumeration.

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — chain lure delivery → user execution → locale enumeration in one lineage.

```kusto
let lure = EmailAttachmentInfo
    | where Timestamp > ago(30d)
    | where FileType in~ ("doc","docx","docm","ppt","pptx","ppsx","exe","zip","rar","7z")
    | where FileName matches regex @"(?i)(isaar|biranvand|dorud|\.exe$|ins.*\.exe)"   // politically-themed / SFX
    | join kind=inner (EmailEvents | where SenderFromDomain !endswith "ourcompany.com") on NetworkMessageId
    | project lureTime=Timestamp, RecipientEmailAddress, FileName, SenderFromDomain;
let execAndLocale = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("winword.exe","powerpnt.exe") or InitiatingProcessFileName matches regex @"(?i)^ins.*\.exe$"
    | project execTime=Timestamp, DeviceName, AccountUpn, InitiatingProcessFileName, ChildProc=FileName, ChildCmd=ProcessCommandLine
    | join kind=inner (
        DeviceRegistryEvents
        | where RegistryKey has_any (@"Keyboard Layout\Preload", @"Control Panel\International", "NlsLang", "InstallLanguage")
        | project locTime=Timestamp, DeviceName, AccountUpn, RegistryKey, RegistryValueData
      ) on DeviceName, AccountUpn
    | where locTime between (execTime .. execTime + 5m);      // locale query in the lineage window after exec
execAndLocale
| join kind=leftouter (lure) on $left.AccountUpn == $right.RecipientEmailAddress
| project execTime, DeviceName, AccountUpn, InitiatingProcessFileName, ChildProc, RegistryKey, RegistryValueData, FileName, SenderFromDomain
| order by execTime desc
```

## Triage guidance

- **Likely malicious:** a child process spawned by `WINWORD/POWERPNT` or an `ins*.exe` SFX reads locale/keyboard-language keys within minutes of execution, on a host whose user received an external, low-history Persian politically-themed attachment (ISAAR/Biranvand/Dorud-themed, or a fake-video-player SFX); the same host subsequently drops `%TEMP%\fwupdate.temp` or writes a keystroke-log file (cross-ref detection-lane T1137.001/T1056.001). Persian/Farsi (`fa-IR`) locale on an otherwise English-configured estate paired with lure lineage is a strong corroborator.
- **Likely benign / expected:** localized/multilingual applications and installers legitimately query UI language and keyboard layout at startup; genuinely Persian-speaking staff will have `fa-IR` locale as a baseline, not an anomaly — the signal is the *lure-lineage timing*, not the locale value. Newsletters and shared documents from known external partners are not lures. A locale read with no document/SFX parent is out of scope for this hunt.
- **Pivot next:** on a match, preserve the original mail + attachment, extract sender infra and attachment hash for a phishing-campaign sweep across all recipients, and follow the same process tree forward into persistence (T1547.001 Run key, T1053.005 helper.exe task) and the anti-analysis/decode behavior in HUNT-03. If a second-stage implant is confirmed, escalate to incident-response-coordinator — a landed Infy lure on a dissident/diplomatic user is a live targeted-surveillance incident.

## References

- https://unit42.paloaltonetworks.com/prince-of-persia-infy-malware-active-in-decade-of-targeted-attacks/
- https://research.checkpoint.com/2021/after-lightning-comes-thunder/
- https://attack.mitre.org/techniques/T1614/001/
- https://attack.mitre.org/techniques/T1566/001/
- https://attack.mitre.org/techniques/T1204/002/
