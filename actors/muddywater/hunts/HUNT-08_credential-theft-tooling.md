# Hunt: Credential theft via LaZagne / browser & email credential stores

- **Hypothesis:** If MuddyWater is harvesting credentials on this host, then we should see access to browser login-data files, email/credential files, and cached/LSA secrets — driven by LaZagne/Browser64-style tooling — where the *accessing process is not the owning application*, an unexpected-relationship anomaly (something other than Chrome reading Chrome's `Login Data`).
- **ATT&CK:**
  - T1003.005 — OS Credential Dumping: Cached Domain Credentials (credential-access)
  - T1552.001 — Unsecured Credentials: Credentials In Files (credential-access)
  - T1555 — Credentials from Password Stores (credential-access)
  - T1555.003 — Credentials from Password Stores: Credentials from Web Browsers (credential-access)
  - *Context/pivot (detection-lane):* T1003.001 (LSASS), T1003.004 (LSA Secrets)
- **Actor procedure:** MuddyWater has performed credential dumping with **LaZagne** (cached domain credentials, LSA secrets, password stores), run **Browser64** to steal passwords saved in **web browsers**, and run a tool that **steals passwords saved in victim email**.
- **Why a hunt, not a rule:** Known-tool signatures (LaZagne/Browser64 hashes/names) belong to detection-engineer, but MuddyWater renames tooling and adopts commodity binaries, so the durable signal is the *behavior*: a non-browser process opening browser `Login Data`/`Local State`/`key4.db`, or a non-mail process reading Outlook/Thunderbird credential stores, or unexpected registry access to cached-secret/LSA keys. That access-relationship anomaly needs baselining of which processes legitimately touch these files.

## Data sources required

- Sysmon EID 11 / EDR file-read telemetry on browser & mail credential stores
- Sysmon EID 1 / 4688 (process + command line)
- Sysmon EID 13 / registry access to `SECURITY\Cache` and `SECURITY\Policy\Secrets` (LSA/cached creds)

## Query starting point

Platform: `KQL/Sentinel`

```kql
let credFiles = dynamic([
    "Login Data","Local State","key4.db","logins.json","cookies.sqlite","Web Data",
    "signons.sqlite","credentials","vault.db"]);
let owners = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe",
    "outlook.exe","thunderbird.exe"]);
DeviceFileEvents
| where ActionType in ("FileAccessed","FileModified","FileCreated") 
     or isnotempty(PreviousFileName)
| where FileName in~ (credFiles)
     or FolderPath has_any (@"\User Data\",@"\Mozilla\Firefox\Profiles\",@"\Microsoft\Credentials\")
| where InitiatingProcessFileName !in~ (owners)                 // unexpected-relationship anomaly
| where InitiatingProcessFileName !in~ ("backup.exe","MsMpEng.exe","explorer.exe")
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| join kind=leftouter (
    // corroborate with LaZagne-like breadth: one process hitting many stores fast
    DeviceFileEvents | where FileName in~ (credFiles)
    | summarize storesTouched=dcount(FileName) by DeviceName, InitiatingProcessFileName
    | where storesTouched >= 3
) on DeviceName, InitiatingProcessFileName
```

## Triage guidance

- **Likely malicious:** A single non-browser/non-mail process reading 3+ distinct credential stores in quick succession (LaZagne breadth); a script interpreter or temp-path binary opening `Login Data`/`key4.db`; unexpected reads of LSA `Secrets`/`Cache` registry hives; access immediately preceded by a discovery burst (HUNT-01).
- **Likely benign / expected:** The browsers/mail clients themselves; endpoint backup and DLP agents; password-manager sync; migration/profile tools. Baseline these accessors and suppress.
- **Pivot next:** Where do stolen creds go (→ HUNT-05/06)? Any lateral movement or new logons with the harvested accounts (detection lane, Security 4624/4648)? Confirmed dumping → **escalate to incident-response**.

## References

- https://attack.mitre.org/groups/G0069/
