# Hunt: MarkiRAT file discovery and sensitive-data collection (KeePass/PGP keystores, messaging dirs)

- **Hypothesis:** If MarkiRAT is staging documents for exfiltration, then a single unsigned/user-path process will sweep the user's Desktop, Documents, Pictures, Downloads and messaging-app directories (`ViberPC`, `Skype`, `Telegram`/`tdata`) in a short burst — a `smart dir`/`fulldir` enumeration — and then read files of specific target extensions, notably `.kdbx` (KeePass), `.gpg`/`.pkr`/`.key` (PGP keyrings) alongside Office docs and `.txt` — so a non-interactive process touching many directories then opening a password store or PGP keyring is an unexpected-relationship + volume-outlier anomaly distinct from a human browsing their own files.
- **ATT&CK:**
  - T1083 — File and Directory Discovery (discovery)
  - T1005 — Data from Local System (collection)
- **Actor procedure:** MarkiRAT's `smart dir` / `upload` / `fulldir` commands perform intelligent file discovery across Desktop, Documents, Pictures, Downloads and messaging-app folders (ViberPC, Skype, Telegram) to locate documents of interest, then collect files of targeted extensions via `upload`/`uploads`/`uploadsf`: `.rtf .doc .docx .xls .xlsx .ppt .pptx .pps .ppsx .txt .gpg .pkr .kdbx .key .jpg` — deliberately including KeePass databases and PGP keyring material, i.e. the victim's encryption keys and password store.
- **Why a hunt, not a rule:** Directory enumeration and document reads resemble ordinary user activity and are far too noisy to alert on directly. The hunt sharpens on the least-benign slice — a *non-interactive* process (no foreground UI, unsigned, user-writable path) accessing `.kdbx`/`.gpg`/`.pkr`/`.key` within the implant's process-lineage window, ideally corroborated by honeytoken files. That demands baselining of who normally reads those extensions rather than a precise rule.

## Data sources required

- Sysmon EID 1 / 4688 (process image, signer, parent) to identify the enumerating process
- File-access / file-open auditing or EDR file-read telemetry for target extensions (`.kdbx`, `.gpg`, `.pkr`, `.key`, Office docs) attributed to a process
- Optional: honeytoken files (decoy `.kdbx`/`.gpg`) seeded in user profiles with object-access auditing (EID 4663)

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (EventCode=4663 OR sourcetype=edr_file_read)
    (Object_File_Name="*.kdbx" OR Object_File_Name="*.gpg" OR Object_File_Name="*.pkr"
     OR Object_File_Name="*.key" OR file_path="*.kdbx" OR file_path="*.gpg"
     OR file_path="*.pkr" OR file_path="*.key")
| eval img=lower(coalesce(Process_Name,Image,process))
| join type=inner img [
    search index=endpoint (EventCode=4663 OR sourcetype=edr_file_read)
    | eval dir=replace(coalesce(Object_File_Name,file_path),"[^\\\\]+$","")
    | stats dc(dir) as dirs_touched values(dir) as dir_list by img, host, process_guid ]
| where dirs_touched>=5
| eval suspect=if(match(img,"\\\\(users\\\\public|appdata|temp)\\\\"),"user_path","other")
| stats values(Object_File_Name) as sensitive_files values(dir_list) as dirs
        by host img suspect process_guid
| where suspect="user_path"
```

## Triage guidance

- **Likely malicious:** An unsigned process from `\Users\Public\`, `\AppData\Windows`, or a Telegram/Chrome data dir that fans out across 5+ user directories then reads `.kdbx`/`.gpg`/`.pkr`/`.key`; access to a seeded honeytoken keystore; the same `process_guid` also seen keylogging (HUNT-02) or fingerprinting AV (HUNT-01); parent traceable to `svehost.exe` or a hijacked shortcut.
- **Likely benign / expected:** KeePass/GPG/Kleopatra themselves reading their own stores; backup agents and search-indexers (`SearchIndexer.exe`) legitimately enumerate broadly — these are signed, from Program Files, and consistent per host. Users opening their own documents interactively will have a foreground session. Baseline signed apps that read these extensions and suppress them.
- **Pivot next:** If confirmed, hunt outbound staging/exfil to `/up/uploadx.php` and the beacon URIs (`/i.php`, `/ech/echo.php?req=rr`) on the C2 domains — detection lane. A non-interactive process harvesting KeePass/PGP material is a live credential-theft compromise — **escalate to incident-response**, rotate the affected keystores/keys, and preserve the `%PUBLIC%\AppData\Windows` repository.

## References

- https://securelist.com/ferocious-kitten-6-years-of-covert-surveillance-in-iran/102806/
- https://www.picussecurity.com/resource/blog/ferocious-kitten-apt-exposed-inside-the-iran-focused-espionage-campaign
- https://attack.mitre.org/techniques/T1083/
- https://attack.mitre.org/techniques/T1005/
