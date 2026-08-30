# Hunt: Dark Caracal — second-stage payload staging on legitimate cloud hosting (egress after Office/PowerShell)

- **Hypothesis:** Dark Caracal stages its second-stage payload ZIP on *legitimate* cloud services (Dropbox, Bitbucket, Amazon S3) precisely because that egress blends into normal business traffic and carries valid TLS and good reputation. If the actor is mid-chain here, then the tell is not the destination (Dropbox is fine) but the *relationship*: a `winword.exe → powershell.exe` lineage, or a freshly-spawned PowerShell/loader process, reaching out to a raw-file cloud-hosting URL (`dl.dropboxusercontent.com`, `bitbucket.org/.../downloads/`, `*.s3.amazonaws.com`) and pulling a ZIP/PNG archive within seconds of the macro firing — on a host that has no business relationship with that cloud tenant. A single office user syncing Dropbox is benign; `powershell.exe` whose parent is Office fetching a `.zip` of `.png` files from a never-before-seen S3 bucket is not.
- **ATT&CK:**
  - T1608.001 — Stage Capabilities: Upload Malware (resource-development) — the actor uploads the `a.png`/`b.png` RC4 payload, the Invoke-PSImage `untitled.png`, and decoy `draft.docx` to Dropbox/Bitbucket/S3; on-victim we hunt the retrieval egress that this staging necessitates

- **Actor procedure:** After the trojanized Word document's remote VBA macro drops the PowerShell loader (`fmx.ps1` + base64 image `sdmc.jpg`), the loader downloads a four-file ZIP from Dropbox, Bitbucket or Amazon S3. The ZIP contains `a.png` and `b.png` (an RC4-encrypted executable split across two files and concatenated), `untitled.png` (a valid PNG carrying a hidden RC4 routine embedded with Invoke-PSImage), and `draft.docx` (a benign decoy shown to the user). The loader RC4-decrypts and reconstructs the Delphi loader, which then process-hollows into `iexplore.exe`. The staging services are legitimate and are deliberately *not* on the IOC domain list — the hunt is behavioral, keyed on who fetches and when.
- **Why a hunt, not a rule:** You cannot block or alert on Dropbox/Bitbucket/S3 — they are load-bearing for the business, and the reputation/TLS is genuinely good. A destination-based rule is all false positives. The signal only exists in the correlated context — Office-parented or newly-spawned PowerShell, a raw-file download URL (not the web app UI), an archive of image files, and a host with no prior sync relationship to that tenant — stacked together. Assembling and weighing that context across proxy + process + file telemetry is hunt work. If the chain resolves to a durable, precise observable (e.g. `powershell.exe` with an Office grandparent fetching an archive from a cloud-hosting raw-file path — a robust behavioral relationship), hand *that* scoped analytic to detection-engineering; do not alert on "someone downloaded from Dropbox."

## Data sources required

- Web-proxy / TLS-inspection or SASE logs: full URL or SNI + URI path to `dropbox`/`dropboxusercontent`, `bitbucket.org/*/downloads`, `*.s3*.amazonaws.com`, with the requesting process where available
- EDR process-creation + network events (Sysmon EID 1/3, DeviceNetworkEvents): parent/child lineage so PowerShell/loader can be tied to the cloud fetch and to an Office ancestor
- EDR file-creation events (Sysmon EID 11 / DeviceFileEvents): `.zip`, `a.png`, `b.png`, `untitled.png`, `draft.docx`, `sdmc.jpg`, `fmx.ps1` written to `C:\Users\Public\` or user temp shortly after the fetch
- DNS logs (fallback where proxy lacks process attribution)

## Query starting point

Platform: `KQL / Microsoft Defender XDR` — tie a cloud-hosting download to a PowerShell/loader process with a recent Office ancestor.

```kusto
let cloudHosts = dynamic(["dropboxusercontent.com","dl.dropbox.com","bitbucket.org",
                          "s3.amazonaws.com","amazonaws.com"]);
let officeParents = dynamic(["winword.exe","excel.exe","powerpnt.exe","outlook.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (cloudHosts) or RemoteUrl has ".s3."
| where InitiatingProcessFileName in~ ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")
       or InitiatingProcessParentFileName in~ (officeParents)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessCommandLine, RemoteUrl, InitiatingProcessAccountName
// Corroborate: did an archive / png staging set land on disk on the same host right after?
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FileName has_any ("a.png","b.png","untitled.png","draft.docx","sdmc.jpg","fmx.ps1")
          or (FileName endswith ".zip" and FolderPath has @"\Public\")
    | project DeviceName, DropFile = FileName, DropPath = FolderPath, DropTime = Timestamp
  ) on DeviceName
| where isempty(DropTime) or abs(datetime_diff('second', DropTime, Timestamp)) < 120
| order by Timestamp asc
```

## Triage guidance

- **Likely malicious:** `powershell.exe` (especially with an Office grandparent) fetching a `.zip`/raw file from an S3 bucket or Dropbox/Bitbucket raw-file path, immediately followed by `a.png`/`b.png`/`untitled.png`/`draft.docx` written to `C:\Users\Public\`; the loader deleting those staging files minutes later (correlate with detection pack T1070.004); the reconstructed loader hollowing `iexplore.exe` (T1055.012).
- **Likely benign / expected:** interactive Dropbox/OneDrive desktop-client sync, browser-driven downloads by the user, CI/CD agents pulling from Bitbucket `downloads`, and DevOps tooling hitting S3 — baseline these processes and tenants; a marketing user opening a shared Dropbox link in a browser is not this. The discriminators are *scripting-engine* initiator, *raw-file* path, *image-archive* content, and *no prior relationship* with the tenant.
- **Pivot next:** if the fetch→drop→delete chain confirms, this is live Bandook staging — pull the parent document, extract the remote-template URL and shortener (feeds detection T1221/T1566.002), hash the reconstructed payload against the Bandook fingerprint (AES-IV, opcodes → HUNT-01), sweep for Run-key persistence (T1547.001) and the `iexplore.exe` hollow (T1055.012), and escalate to incident-response-coordinator as an active infection.

## References

- https://research.checkpoint.com/2020/bandook-signed-delivered/
- https://attack.mitre.org/groups/G0070/
- https://attack.mitre.org/techniques/T1608/001/
