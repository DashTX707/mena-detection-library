# Hunt: APT39 off-victim tool acquisition — downstream use of the public toolkit

- **Hypothesis:** APT39's tool *acquisition* happens off our endpoints and cannot be observed directly — so the hunt assumes it already occurred and looks for the *downstream footprint* of the actor's known public toolkit landing and executing: Mimikatz, ProcDump, Windows Credential Editor (WCE), PsExec, and PLINK appearing on hosts where they have no legitimate business, arriving via ingress transfer (certutil/BITS) and often renamed/relocated to masquerade. The signal is a *known-actor tool by behavior/lineage* — original filename, embedded signer, characteristic command-line, or import/section fingerprint — surviving even when the operator renames the binary or swaps the hash.
- **ATT&CK:**
  - T1588.002 — Obtain Capabilities: Tool (resource-development) — hunted via its on-endpoint downstream use

- **Actor procedure:** APT39 obtains and reuses publicly available tooling — Mimikatz and WCE (credential theft), ProcDump (LSASS dumping), PsExec (lateral movement/service exec), and PLINK (SSH tunneling) — acquired off-victim, then transferred in (certutil/BITS), frequently renamed and dropped into plausible-looking paths to blend in, and executed hands-on. Because acquisition is invisible to the defender, catching the *first execution* of these tools on a host is the earliest on-endpoint signal of the actor's tradecraft.
- **Why a hunt, not a rule:** The technique itself (obtaining a tool) generates zero endpoint telemetry, and its downstream tools are dual-use — ProcDump, PsExec, and PLINK are legitimate SysInternals/PuTTY utilities that admins run, so a hash- or name-only rule is both evadable (rename/repack) and noisy (admin use). The durable signal is *behavioral/metadata*: original-filename and signer in the PE header (Summiting Level 4–5 — the operator can rename the file but not cheaply strip these), characteristic command-lines (`procdump -ma lsass`, `psexec \\host`, `plink -R`), and first-seen-on-this-host context. Distinguishing actor use from sanctioned admin use needs environment judgement → hunt. A confirmed never-before-seen credential/tunneling tool on a non-admin host is a candidate to hand to detection-engineering.

## Data sources required

- Sysmon EID 1 (process create) with `OriginalFileName` + `Hashes` + full command line + parent lineage
- Sysmon EID 7 (image load) / PE metadata — `OriginalFileName` and signer even when the file is renamed
- Sysmon EID 11 + BITS-Client / certutil command-line (`-urlcache`, `-decode`) — ingress transfer of the tool (cross-ref T1105/T1140 detection pack)
- Host/role baseline (which hosts and accounts legitimately run SysInternals/PuTTY tooling)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — known-actor toolkit by PE OriginalFileName / command-line, renamed-aware, first-seen-on-host

```kusto
let toolMeta = dynamic(["mimikatz.exe","procdump","procdump64.exe","wce.exe","psexec","psexec64.exe","plink.exe"]);
let toolCmd = dynamic(["-ma lsass","sekurlsa","logonpasswords","psexesvc","-accepteula \\\\","plink","-R ","-L ","-pw "]);
DeviceProcessEvents
| where TimeGenerated > ago(14d)
| extend OFN = tolower(tostring(parse_json(AdditionalFields).OriginalFileName))
| where OFN has_any (toolMeta)                          // PE identity survives file rename (Level-4 observable)
      or ProcessCommandLine has_any (toolCmd)
| join kind=leftanti (                                  // first-seen-on-host: exclude prior 60d baseline
    DeviceProcessEvents
    | where TimeGenerated between (ago(74d)..ago(14d))
    | extend OFN2 = tolower(tostring(parse_json(AdditionalFields).OriginalFileName))
    | project DeviceName, OFN2
) on $left.DeviceName == $right.DeviceName and $left.OFN == $right.OFN2
| project TimeGenerated, DeviceName, AccountName, FileName, OFN, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, SHA1
// Flag renamed: FileName (on-disk) != OFN (PE metadata) = masquerading
| extend renamed = tostring(FileName) !contains extract(@"([a-z0-9]+)\.exe", 1, OFN)
| order by TimeGenerated asc
// Exclude sanctioned admin/IR hosts + accounts that legitimately run SysInternals/PuTTY (wiki baseline)
```

## Triage guidance

- **Likely malicious:** a binary whose PE `OriginalFileName`/signer identifies it as Mimikatz/ProcDump/WCE/PsExec/PLINK but which is renamed and dropped in `%TEMP%`/`%APPDATA%`/a web root; first-ever appearance on that host; arrival via certutil/BITS just beforehand; execution with tell-tale args (`procdump -ma lsass`, `sekurlsa::logonpasswords`, `plink -R`) under a non-admin or service account. Masquerading (on-disk name != PE identity) plus ingress-transfer plus first-seen stacks into a strong actor signal.
- **Likely benign / expected:** IT admins and IR/forensics teams legitimately run ProcDump, PsExec, and PLINK from known jump hosts and admin accounts; SysInternals suites and PuTTY are common — allowlist by host, account, and known deployment path. Mimikatz/WCE, by contrast, have essentially no benign enterprise use and warrant investigation almost anywhere. Signed PsExec from an admin jump box is expected; a renamed `plink` in a user temp path is not.
- **Pivot next:** confirm the ingress vector (certutil/BITS/web shell) and preserve the binary for hashing/analysis; correlate credential tools with LSASS access (T1003.001 detection pack) and PsExec/PLINK with lateral movement (T1021/T1569.002) and the proxy chains (HUNT-02); scope where else the same PE identity landed fleet-wide. Confirmed actor toolkit executing hands-on is an active intrusion → escalate to IR.

## References

- https://attack.mitre.org/groups/G0087/
- https://attack.mitre.org/techniques/T1588/002/
- https://www.cisa.gov/news-events/analysis-reports/ar20-259a
- https://www.mandiant.com/resources/blog/apt39-iranian-cyber-espionage-group-focused-on-personal-information
