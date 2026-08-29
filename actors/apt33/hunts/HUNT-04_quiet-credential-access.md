# Hunt: APT33 quiet credential access — cached domain creds, credentials-in-files, network sniffing

- **Hypothesis:** If APT33 is harvesting credentials quietly on-host (avoiding noisy LSASS dumping), then we should observe its low-telemetry tradecraft — access to the SECURITY/SYSTEM registry hives or `reg save` of them to extract cached domain credentials (MSCACHE/DCC) for offline cracking, mass/recursive file reads and content searches hitting known credential-file locations (`*.config`, `unattend.xml`, `*.kdbx`, `id_rsa`, `web.config`, `credentials`, `*.ps1` with secrets), and enablement of promiscuous-mode / execution of a packet-sniffer to capture credentials in transit — behaviors that individually resemble normal admin/file activity but stack into a credential-collection pattern.
- **ATT&CK:**
  - T1003.005 — OS Credential Dumping: Cached Domain Credentials (credential-access)
  - T1552.001 — Unsecured Credentials: Credentials In Files (credential-access)
  - T1040 — Network Sniffing (credential-access)

- **Actor procedure:** Per the G0064 mapping, APT33 harvests cached domain credentials (MSCACHE/DCC) from compromised hosts to authenticate as domain users, searches for credentials stored in files, and uses network sniffing to capture credentials and other traffic on compromised networks — quiet, on-host credential access that feeds lateral movement (RDP/valid accounts) and, in the destructive nexus, worm-like propagation.
- **Why a hunt, not a rule:** Each of these is deliberately quiet and high-base-rate: registry hive access happens during legitimate backup/GPO/AV activity; recursive file reads look identical to indexing, DLP scans and normal user browsing; passive sniffing generates almost no host telemetry at all. Alerting on any one drowns the SOC or is simply blind. The signal is *stacked and relational* — hive access **by an unexpected process**, then a burst of reads across credential-bearing paths by that same process/user, or promiscuous-mode enablement co-located with a known sniffer binary — and it requires per-host/per-account baselining and judgement → hunt. Robust cores (`reg save HKLM\SECURITY`/`SYSTEM` by a non-admin-tool process; promiscuous-mode enable) are candidates for detection-engineering once baselined.

## Data sources required

- Sysmon EID 1 (process + command line: `reg save`, `reg.exe`, sniffer/`Get-*Credential` tooling) + EID 13 (registry) + EID 11 (file access to dumped hives)
- Windows Security 4663/4656 (object access) auditing on SECURITY/SYSTEM hives and SYSVOL/file shares
- PowerShell script-block (EID 4104) — mass file enumeration, `Select-String password`, DCC/hive parsing
- Host NIC state / EDR promiscuous-mode telemetry; driver load (Sysmon EID 6) for WinPcap/Npcap
- File-share access auditing (5140/5145) for remote credential-file harvesting

## Query starting point

Platform: `Splunk SPL` (Sysmon + Security + PS4104) — hive extraction, credential-file sweeps, and sniffer enablement

```
(index=sysmon EventCode=1
   (CommandLine="*reg* save*HKLM\\SECURITY*" OR CommandLine="*reg* save*HKLM\\SYSTEM*"
    OR CommandLine="*reg* save*HKLM\\SAM*"
    OR CommandLine="*windump*" OR CommandLine="*tcpdump*" OR CommandLine="*WinPcap*"
    OR CommandLine="*Npcap*" OR CommandLine="*Set-NetAdapter*Promiscuous*"))
OR (index=powershell EventCode=4104
   (ScriptBlockText="*Select-String*password*" OR ScriptBlockText="*-Recurse*Include*.config*"
    OR ScriptBlockText="*unattend.xml*" OR ScriptBlockText="*.kdbx*" OR ScriptBlockText="*Get-ChildItem*id_rsa*"
    OR ScriptBlockText="*MSCACHE*" OR ScriptBlockText="*DCC2*"))
| eval evidence=coalesce(CommandLine, ScriptBlockText)
| stats count values(Image) AS proc values(evidence) AS what min(_time) AS first by host User
| sort - count

/* Credential-file read burst: one process touching many credential-bearing paths in a short window
index=sysmon EventCode=11 (TargetFilename="*\\web.config" OR TargetFilename="*\\unattend.xml"
   OR TargetFilename="*.kdbx" OR TargetFilename="*id_rsa*" OR TargetFilename="*credentials*")
| stats dc(TargetFilename) AS files values(TargetFilename) AS paths by host Image User
| where files >= 10 */
```

## Triage guidance

- **Likely malicious:** `reg save` of the SECURITY/SYSTEM/SAM hives by a process that is not a known backup/AV tool, especially followed by the hive files being staged or copied off-host; a single process/user reading 10+ credential-bearing files across directories in minutes; promiscuous-mode enablement or a WinPcap/Npcap driver load co-located with a sniffer binary on a server with no monitoring role; any of these on a host that also shows APT33 execution/persistence.
- **Likely benign / expected:** backup agents and GPO/AV tooling read protected hives legitimately; developers and DLP scanners read `.config`/`.xml` broadly; network/monitoring appliances and Wireshark on an analyst workstation use promiscuous mode. Baseline which processes/accounts legitimately touch hives and which hosts run capture tools; a single expected tool is not a finding — the *unexpected process* or the *stacked burst* is.
- **Pivot next:** if hive extraction is confirmed, assume offline DCC/MSCACHE cracking is underway — force password resets on exposed accounts, and pivot to lateral-movement (RDP/valid accounts — detection pack T1021.001/T1078) and to where the creds are used. Correlate sniffing hits with the covert-channel egress in HUNT-03. Confirmed credential theft feeding active use is a live incident → escalate to IR.

## References

- https://attack.mitre.org/techniques/T1003/005/
- https://attack.mitre.org/techniques/T1552/001/
- https://attack.mitre.org/techniques/T1040/
- https://attack.mitre.org/groups/G0064
