# Hunt: Phishing & social engineering (external, internal, link, ClickFix)

- **Hypothesis:** If MuddyWater is running a phishing operation against us, then mail-flow and endpoint telemetry will show (a) inbound spearphishing with malicious attachments/links from brand-spoofing or compromised third-party senders, (b) *internal* spearphishing from our own compromised mailboxes, and/or (c) ClickFix-style lures that end with a user pasting attacker PowerShell into a Run box — a chain from message to user execution.
- **ATT&CK:**
  - T1566 — Phishing (initial-access)
  - T1566.001 — Phishing: Spearphishing Attachment (initial-access)
  - T1566.002 — Phishing: Spearphishing Link (initial-access)
  - T1534 — Internal Spearphishing (lateral-movement)
  - T1204.001 — User Execution: Malicious Link (execution)
  - T1204.004 — User Execution: Malicious Copy and Paste / ClickFix (execution)
- **Actor procedure:** MuddyWater sends phishing from **`support@microsoftonlines[.]com`** posing as Microsoft security updates, uses **compromised third parties and compromised accounts** to send spearphishing with attachments (e.g. **`Cybersecurity.doc`**) and malicious **links**, sends **internal spearphishing from compromised mailboxes inside the target org**, and leverages **ClickFix** lures enticing victims to copy-paste malicious PowerShell.
- **Why a hunt, not a rule:** Individual URL/attachment blocks and sender IOCs belong to the email gateway and detection-engineer. What needs hunting is the *pattern*: internal-origin phishing (a trusted mailbox suddenly blasting lookalike links), brand-spoof sender clusters, and the ClickFix behavioral tail (PowerShell launched from `explorer.exe`/RunMRU shortly after a web visit). Those need mail-flow baselining and cross-domain correlation, not a static signature.

## Data sources required

- Email gateway / M365 message-trace logs (sender, display name, auth results, URLs, attachment names/types)
- Proxy / URL-detonation logs (clicked links)
- Endpoint: Sysmon EID 1 (PowerShell parented by `explorer.exe`), RunMRU registry (`...\Explorer\RunMRU`), PowerShell 4104

## Query starting point

Platform: `KQL/Sentinel`

```kql
// A. ClickFix tail: PowerShell / mshta launched from explorer (Run box) with download/encoded args
DeviceProcessEvents
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe")
| where ProcessCommandLine has_any ("-enc","-e ","frombase64","iwr","invoke-webrequest",
        "downloadstring","curl ","http://","https://","hidden")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
// B. (run separately over mail) internal spearphishing + brand spoof
// EmailEvents
// | where SenderFromDomain has_any ("microsoftonlines","microsoft-online") 
//     or (SenderFromDomain in (internal_domains) and UrlCount > 0 and DeliveryAction=="Delivered"
//         and RecipientCount > 15)
// | project Timestamp, SenderFromAddress, Subject, RecipientEmailAddress, Urls, AttachmentCount
```

## Triage guidance

- **Likely malicious:** Mail from Microsoft/brand lookalike domains (`microsoftonlines[.]com`) with security-update themed subjects; a normally low-volume internal mailbox suddenly sending many link-bearing messages (internal spearphishing); attachment named like `Cybersecurity.doc`; `powershell.exe`/`mshta.exe` spawned by `explorer.exe` with encoded/download args right after a web browse (ClickFix); RunMRU containing PowerShell one-liners.
- **Likely benign / expected:** Legitimate bulk internal mail (HR, IT comms) — baseline normal sender volumes; users pasting benign admin commands into Run; SharePoint/OneDrive share notifications.
- **Pivot next:** Any recipient who clicked/opened → endpoint review (HUNT-01/02); if an internal mailbox is the source, treat the *sending* account as compromised and **escalate to IR**; feed confirmed sender/URL IOCs to detection-engineer and the gateway.

## References

- https://attack.mitre.org/groups/G0069/
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a
