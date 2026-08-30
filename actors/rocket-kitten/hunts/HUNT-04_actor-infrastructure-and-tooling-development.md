# Hunt: Rocket Kitten — actor infrastructure, cloud staging and tooling development

- **Hypothesis:** If Rocket Kitten is standing up infrastructure to hit us, then off-victim we should be able to catch the *staging* footprint before or as delivery happens: newly-registered look-alike domains spoofing our webmail/portal/institution names (their phishing server and fake-login hosts), malicious payloads staged on abused legitimate cloud (OneDrive/SharePoint links) delivered to our staff, and — when a sample is recovered — build/authorship artifacts of their custom tooling (CWoolger PDB paths, the GHOLE Core-Impact lineage). Any one signal is thin; the finding is a look-alike domain or cloud-staged payload that *time-correlates with delivery to a targeted user*, and/or a recovered sample carrying the actor's development fingerprints.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — registered phishing / look-alike domains and a phishing server hosting fake-login pages.
  - T1583.006 — Acquire Infrastructure: Web Services (resource-development) — abuse of OneDrive to host payloads and use of `av.zerodays.ir` to pre-test detection.
  - T1608.001 — Stage Capabilities: Upload Malware (resource-development) — payloads (e.g. `Iran's Missiles Program.ppt.exe`) staged on OneDrive links for delivery.
  - T1587.001 — Develop Capabilities: Malware (resource-development) — custom CWoolger keylogger; leaked PDB paths (`C:\Users\Wool3n.H4t\...\CWoolger\Release\CWoolger.pdb`, `D:\Yaser Logers\...`).
  - T1588.002 — Obtain Capabilities: Tool (resource-development) — GHOLE built from a modified commercial Core Impact Pro pentest agent.

- **Actor procedure:** Per Trend Micro (*Woolen-GoldFish*, *Spy Kittens*) and Check Point (*9 Lives*), Rocket Kitten registers phishing/look-alike domains and runs a dedicated phishing server, changing them only minimally even after public exposure. They abuse Microsoft OneDrive to host payloads (bypassing attachment scanning) and pre-tested samples on the free Iranian multiscanner `av.zerodays.ir`. Their tooling is custom-but-amateur: CWoolger/TSPY_WOOLERG keylogger (authorship leaked via PDB paths tying it to operator handles Wool3n.H4t and Yaser) and GHOLE, a *modified Core Impact Pro* agent whose DLL renames its telltale `gholee` export to a benign `function`. Staged payload example: an archive with `Iran's Missiles Program.ppt.exe` (PowerPoint icon, double extension) on a OneDrive link.

- **Why a hunt, not a rule:** Domain registration, cloud staging and malware development all happen on the actor's side of the wire — nothing to alert on until a link or sample reaches us, and even then a OneDrive link or a new domain is, by itself, indistinguishable from legitimate traffic (OneDrive is ubiquitous; new domains resolve constantly). The finding requires correlation and enrichment — pairing a newly-registered look-alike host or a cloud-staged executable with *delivery to a targeted user*, or pairing a recovered sample with actor-specific build artifacts — which is analyst pivot-and-attribute work across DNS/WHOIS, proxy, mail and reversing outputs. Where a durable, high-fidelity artifact falls out (the fixed `/index.php?c=&r=&u=&t=` GHOLE beacon or the CWoolger PDB string in a sample), that belongs to the *detection* lane already; this hunt's job is to find the staging early and attribute it.

## Data sources required

- Newly-registered-domain / WHOIS and passive-DNS feeds, plus certificate-transparency logs — look-alike domains echoing our webmail/portal/institution names and their hosting pivots.
- Web proxy / mail-URL logs — outbound to OneDrive/SharePoint share links delivering executables or archives, especially reached from spear-phishing to targeted users.
- File-download and endpoint file-creation telemetry — executables/archives pulled from cloud storage (double-extension `*.ppt.exe`, `.zip` containing PE).
- Malware sample repository / reversing output (strings, PDB paths, export names, imphash) — for recovered GHOLE/CWoolger samples and their authorship fingerprints.

## Query starting point

Platform: `KQL / Microsoft Sentinel` — surface cloud-staged executable delivery to targeted users, joined to look-alike-domain intel.

```kusto
let lookalikeDomains =
    ThreatIntelIndicator                              // NRD/CT-log/lookalike feed ingested as TI
    | where TimeGenerated > ago(60d)
    | where DomainName has_any ("ourinstitute","ourcompany","webmail","portal","sso","login")
    | project DomainName, ConfidenceScore, Description;
let cloudStagedPayloads =
    EmailUrlInfo
    | where TimeGenerated > ago(45d)
    | where Url has_any ("1drv.ms","onedrive.live.com","sharepoint.com","dropbox","drive.google")
    | join kind=inner (
        EmailAttachmentInfo                            // link-delivered payloads land as downloads later
        | project NetworkMessageId, FileName, FileType )
      on NetworkMessageId
    | join kind=leftouter (EmailEvents | project NetworkMessageId, RecipientEmailAddress, SenderMailFromAddress)
      on NetworkMessageId
    | project TimeGenerated, RecipientEmailAddress, SenderMailFromAddress, Url, FileName, FileType;
// endpoint: executable pulled from cloud, or double-extension document-icon PE
let cloudDownloadExec =
    DeviceFileEvents
    | where TimeGenerated > ago(45d)
    | where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","onedrive.exe")
    | where FileName matches regex @"(?i)\.(ppt|pdf|doc|xls)\.exe$" or FileName endswith ".exe"
    | where FolderPath has_any ("\\Downloads\\","\\Temp\\")
    | project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA1;
union cloudStagedPayloads, (cloudDownloadExec | extend RecipientEmailAddress = InitiatingProcessAccountName)
| order by TimeGenerated asc
// then enrich SHA1 against sample repo for GHOLE/CWoolger PDB/export fingerprints, and hosts against lookalikeDomains
```

## Triage guidance

- **Likely malicious:** a newly-registered domain closely spoofing our webmail/portal that hosts a login page and correlates with a spear-phish click (join to HUNT-01); a OneDrive/SharePoint link delivered to a targeted user that resolves to a double-extension document-icon executable or an archive containing a PE; a recovered sample whose strings carry a `CWoolger.pdb` / `Yaser Logers` PDB path, a renamed `function` export over Core-Impact scaffolding, or the fixed GHOLE beacon.
- **Likely benign / expected:** OneDrive/SharePoint links are pervasive in legitimate business — do not treat cloud-share links as suspicious without an executable/archive payload and a targeted recipient; new domains resolve constantly, so require *look-alike similarity to our brand* plus a hosted login page or delivery correlation; pentest teams legitimately run Core Impact — scope sample attribution to the renamed-export/PDB fingerprints, not Core Impact presence alone.
- **Pivot next:** submit look-alike domains for takedown and add to blocklists once confirmed; if a staged payload reached and executed on a host, hand to the detection lane's macro/dropper analytics (T1204.002/T1137.001) and treat as live intrusion → escalate to incident-response-coordinator; enrich sample fingerprints (PDB, imphash, export names) back into intel to catch reuse across campaigns; watch for pre-attack detection-testing via `av.zerodays.ir` in any recovered actor infrastructure notes.

## References

- https://documents.trendmicro.com/assets/wp/wp-operation-woolen-goldfish.pdf
- https://documents.trendmicro.com/assets/wp/wp-the-spy-kittens-are-back.pdf
- https://blog.checkpoint.com/research/rocket-kitten-a-campaign-with-9-lives/
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1583/006/
- https://attack.mitre.org/techniques/T1608/001/
- https://attack.mitre.org/techniques/T1587/001/
- https://attack.mitre.org/techniques/T1588/002/
