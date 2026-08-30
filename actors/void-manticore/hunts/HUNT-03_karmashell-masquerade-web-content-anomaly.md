# Hunt: Karma Shell masquerade — web shell disguised as an HTTP error page

- **Hypothesis:** If Void Manticore has established access on one of our internet-facing servers, then a homebrew web shell ("Karma Shell") is present in the web root, deliberately **masquerading as a benign HTTP error page** (its title/served content mimic a stock error), while actually exposing directory-listing, process-creation, file-upload, and service start/stop/list functions. The hunt keys on path/property mismatch and never-before-seen files: a file in the web root whose *served content looks like an error page* but which was **recently created/modified out of band with the application's deploy baseline** and is reachable as a live URL — a benign error template is static and ships with the app; an error-page-shaped file that appeared after last deploy and accepts POST parameters is not.
- **ATT&CK:**
  - T1036 — Masquerading (stealth) — Karma Shell poses as an HTTP error page (title + content) to evade casual review of the web directory

- **Actor procedure:** Void Manticore's homebrew Karma Shell masquerades as an error page via its page title and content, so a glance at the served page or a directory listing does not reveal a web shell. It supports listing directories, creating processes, uploading files, and start/stop/list of services, and decodes its POST parameters at runtime (base64 + 1-byte XOR 0x17) — so the malicious capability is hidden both visually and in transit.
- **Why a hunt, not a rule:** Web roots legitimately contain error pages, and file-integrity alerts on the web directory fire constantly during normal deploys, patching, and CMS activity — a naive "new file in web root" rule drowns in change noise. The discriminating signal is a *stack of mismatches* on the same file: served content shaped like an error page **and** creation/modification timestamp off the app's deploy cadence **and** the file being an executable server-side handler (.aspx/.ashx/.php/.jsp) **and** live reachability. Judging "does this error page actually behave like a web shell" against a per-app known-good baseline is investigative → hunt. The robust anchor to escalate once confirmed: a server-side script file in the web root that is **not in the application's source-of-truth manifest** (Summiting Level-4 path/property observable — the adversary must place the file *somewhere servable*) is a candidate for a file-integrity detection handed to detection-engineering.

## Data sources required

- File-integrity / EDR file-create-modify telemetry on web-root paths (IIS `C:\inetpub`, `wwwroot`, app deploy dirs) — path, hash, create/modify time, writing process
- Application deploy manifest / source-of-truth file list (baseline of legitimate web files + their hashes)
- IIS / web-server access logs (URL, method, status, response size) — to spot POSTs to error-page-named URLs
- Optional: served-content capture / crawl comparing live pages against the known-good template set (title/body diff)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — web-root file not in the deploy manifest, written out of cadence, then reached by live POSTs

```kusto
let manifest = _GetWatchlist("WebAppManifest") | project rel = tolower(tostring(SearchKey)); // known-good files
let webroots = dynamic([@"c:\inetpub\wwwroot", @"c:\inetpub", @"\wwwroot\", @"\app_deploy\"]);
// 1) Server-side handler files appearing in the web root, NOT in the manifest, written by a web/worker process
let suspiciousFiles =
    DeviceFileEvents
    | where TimeGenerated > ago(30d)
    | where ActionType in ("FileCreated","FileModified")
    | where tolower(FolderPath) has_any (webroots)
    | where FileName endswith ".aspx" or FileName endswith ".ashx" or FileName endswith ".asmx"
         or FileName endswith ".php" or FileName endswith ".jsp"
    | extend rel = tolower(strcat(FolderPath, @"\", FileName))
    | where rel !in (manifest)                                   // never-before-seen / off-manifest
    | where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","php-cgi.exe","tomcat.exe","java.exe")
         or InitiatingProcessParentFileName in~ ("w3wp.exe","httpd.exe")
    | project FileTime = TimeGenerated, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName;
// 2) That same URL then reached by POSTs (error-page-shaped name but live handler)
suspiciousFiles
| join kind=inner (
    W3CIISLog
    | where TimeGenerated > ago(30d) and csMethod == "POST"
    | project ReqTime = TimeGenerated, DeviceName = Computer, uriStem = tolower(csUriStem),
              status = scStatus, bytes = scBytes, clientIp = cIP)
    on DeviceName
| where tolower(strcat("/", FileName)) == tostring(extract(@"([^/]+)$", 1, uriStem)) or uriStem has tolower(FileName)
| where ReqTime >= FileTime
| summarize posts = count(), clients = dcount(clientIp), firstPost = min(ReqTime)
        by DeviceName, FileName, SHA256, FileTime, InitiatingProcessFileName
| order by FileTime desc
```

## Triage guidance

- **Likely malicious:** a `.aspx`/`.ashx`/`.php` file in the web root that is absent from the deploy manifest, was written by the web-worker process out of the deploy cadence, whose served content mimics an HTTP error page yet accepts POST bodies, and which subsequently receives POST traffic from few external clients; base64+XOR-looking POST parameters; the file co-located with `do.exe`/`do.zip` staging or followed by `w3wp.exe`→`cmd.exe`. Treat as an active web shell (Karma Shell / reGeorge).
- **Likely benign / expected:** legitimate error/handler pages that ARE in the manifest and were written by the deploy pipeline on a change ticket; CMS/plugin updates that add handlers via the app's own updater; developer hotfixes with a corresponding change record. Reconcile against the manifest and deploy logs — a manifest-listed, pipeline-written file is expected.
- **Pivot next:** confirmed web shell → pull the file for analysis (YARA/reversed-string check, HUNT-04), enumerate its POST-source IPs against HUNT-02's inbound-ASN hunt, and pivot to web-shell-parented recon (HUNT-05) and the handoff/destruction chain (HUNT-01). Preserve the file and IIS logs before remediation. Live web shell on an internet-facing server with any downstream activity → escalate to IR.

## References

- https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/
- https://blog.checkpoint.com/research/unveiling-void-manticore-structured-collaboration-between-espionage-and-destruction-in-mois/
- https://attack.mitre.org/techniques/T1036/
