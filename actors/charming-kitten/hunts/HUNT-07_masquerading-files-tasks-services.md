# Hunt: Charming Kitten masquerading — files, tasks & services

- **Hypothesis:** If Charming Kitten has executed on our hosts, then in file, process and scheduled-task/service telemetry we should observe name/location masquerade — double-extension droppers like `onedrive-form.pdf.lnk` disguised as PDFs, files/paths posing as Google/OneDrive/Drive artifacts, and scheduled tasks or services whose *names* imply a legitimate function while their *actions* invoke a script host, curl or an odd path — the actor blending delivery and persistence into trusted-looking names.
- **ATT&CK:**
  - T1036.005 — Masquerading: Match Legitimate Name or Location (stealth)
  - T1036.004 — Masquerading: Masquerade Task or Service (stealth)

- **Actor procedure:** The actor disguises malicious files and infrastructure as legitimate: an LNK named `onedrive-form.pdf.lnk` to look like a PDF (paired with a Harvard T.H. Chan interview-feedback decoy), domains/paths masquerading as Google/OneDrive/Drive services, and an attacker OneDrive/mailbox masquerading as the victim org. For persistence it names scheduled tasks/services to resemble legitimate ones (e.g. update/telemetry-sounding names) so name-based review passes them over, while the task action actually launches wscript/cscript/powershell/cmd/curl or points at a user-writable path.
- **Why a hunt, not a rule:** The whole point of masquerade is to defeat *name-based* trust, so a name allow/deny-list is the exact control being evaded — you cannot alert on "a task called Update" without burying the SOC. The reliable signal is an *inconsistency*: name-vs-action mismatch, publisher/metadata mismatch, or an extension-vs-true-type mismatch — a property-mismatch anomaly that needs contextual judgement against a baseline of legitimate tasks/services and file types. That is a hunt. Individually strong, robust inconsistency checks (LNK spawning a script host; task action pointing at `%TEMP%`\curl) can graduate to detection-engineering; the specific names cannot.

## Data sources required

- Sysmon EID 1 (process create, incl. LNK-spawned children) + EID 11 (file create, true extension)
- Windows Security 4698 / Sysmon EID for scheduled-task creation; Service-install (7045) and task/service definitions
- EDR file metadata (signer, original filename vs. on-disk name, magic-byte true type)
- File-share / download telemetry (double-extension drops)

## Query starting point

Platform: `Splunk SPL` (Sysmon) — (a) double-extension / masqueraded droppers spawning interpreters, (b) task/service name-vs-action mismatch

```
/* (a) Match-legitimate-name/location: LNK or double-extension launching a script host (T1036.005) */
index=sysmon EventCode=1
| where (like(ParentImage,"%\\explorer.exe") OR like(CommandLine,"%.lnk%"))
    AND (like(Image,"%\\wscript.exe") OR like(Image,"%\\cscript.exe")
      OR like(Image,"%\\powershell.exe") OR like(Image,"%\\cmd.exe") OR like(Image,"%\\curl.exe"))
| regex CommandLine="(?i)\.(pdf|docx?|xlsx?|jpe?g|png)\.(lnk|js|vbs|bat|cmd|exe|scr)"
   OR search CommandLine="*onedrive*" OR CommandLine="*drive-file*" OR CommandLine="*form.pdf*"
| table _time host User ParentImage Image CommandLine

/* (b) Masquerade task/service: benign-sounding name, suspicious action (T1036.004) */
| append [ search index=sysmon (EventCode=1 Image="*\\schtasks.exe") OR (index=wineventlog EventCode=4698)
  | eval action=coalesce(CommandLine, TaskContent)
  | where match(TaskName,"(?i)(update|telemetry|sync|onedrive|health|defender|edge)")
      AND match(action,"(?i)(wscript|cscript|powershell|cmd|curl|\\\\temp\\\\|\\\\appdata\\\\|-enc|start /min)")
  | table _time host TaskName action ]
```

## Triage guidance

- **Likely malicious:** an LNK/JS/VBS whose name embeds a fake document extension (`*.pdf.lnk`) and which spawns a script host or curl; a scheduled task/service with an update/telemetry/OneDrive-sounding name whose action launches an interpreter, uses `-enc`/`start /min`, or points at `%TEMP%`/`%APPDATA%`; a file whose true magic bytes disagree with its extension.
- **Likely benign / expected:** genuine vendor updater tasks (verify signed binary + expected install path), legitimate OneDrive/Edge/Defender tasks from Microsoft-signed binaries in Program Files, real installers. Baseline your standard task/service inventory and signed-updater set, then hunt the residue.
- **Pivot next:** on a masqueraded dropper, follow the child chain to the NICECURL/TAMECAT loader and its C2 (HUNT-06/04); on a masqueraded task, pull the target script and check for the obfuscation constants and persistence siblings (Run keys, registry — detection pack). Confirmed masqueraded persistence on a live host → escalate to IR. Graduate robust inconsistency checks to detection-engineering.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/untangling-iran-apt42-operations
- https://attack.mitre.org/groups/G0059
