# Hunt: Tortoiseshell / Imperial Kitten IMAPLoader mail-based C2 (IMAP polling, encrypted channel, proxy relay)

- **Hypothesis:** If IMAPLoader is present, then a non-mail-client process on a workstation or server is speaking IMAP (TCP 143/993) — or SMTP submission — to a *non-corporate* webmail/hosting provider on a regular, beacon-like cadence, retrieving encrypted command bodies from a drafts/inbox folder and returning results by mail, optionally relayed through an intermediary proxy. The evidence is a relationship anomaly (process�”protocol mismatch: a .NET host, side-loaded DLL host, or `mshta`-spawned child rather than Outlook/Thunderbird initiating mail) stacked with a timing anomaly (fixed-interval mailbox polling) and a destination anomaly (a mailbox provider no other corporate host authenticates to).
- **ATT&CK:**
  - T1071.003 — Application Layer Protocol: Mail Protocols (command-and-control)
  - T1573.001 — Encrypted Channel: Symmetric Cryptography (command-and-control)
  - T1090 — Proxy (command-and-control)

- **Actor procedure:** In the Yellow Liderc / Imperial Kitten intrusions, the .NET IMAPLoader implant abuses IMAP email as its C2 channel: it authenticates to an attacker-controlled mailbox, polls for commands stored as mail items, executes them, and returns output by email. Command and result bodies are symmetric-encrypted so content inspection yields nothing, and C2 is frequently routed through intermediary infrastructure to hide true endpoints. The loader is delivered/loaded via HTA (`mshta`) and DLL side-loading, so the process actually opening the mail socket is a hijacked signed host, not a mail client.
- **Why a hunt, not a rule:** Mail traffic to webmail providers is enormous and legitimate, and the payload is encrypted, so no content signature fires. A blanket "process speaking IMAP" alert drowns in mail clients, sync agents, and mobile-device middleware. The discriminating signal is *relational and behavioral* — which process, to which never-before-seen provider, on what interval — and requires per-environment baselining of who legitimately does mail. That judgement is a hunt. The robust core (a process not on the mail-client allowlist establishing IMAP/993 to an external provider — Summiting Level 4 implementation-core, protocol+relationship) is a candidate to hand to detection-engineering once the mail-client and provider allowlists exist.

## Data sources required

- Network/proxy/firewall flow logs with process attribution: outbound TCP 143 (IMAP), 993 (IMAPS), 587/465 (SMTP submission) — src host, dst IP/FQDN, bytes, timestamps
- EDR/Sysmon EID 3 (network connection) joined to EID 1 (process create) — Image, ParentImage, signed status
- Sysmon EID 7 (image load) for side-loaded DLL host correlation (cross-ref HUNT on DLL side-loading in detection pack)
- Mailbox/identity logs (M365/Google Workspace sign-in) for anomalous IMAP-protocol auth to external tenants

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — non-mail-client process opening IMAP/IMAPS to an external provider, with beacon-cadence scoring

```kusto
let mailClients = dynamic(["outlook.exe","hxoutlook.exe","hxtsr.exe","thunderbird.exe",
    "mailclient.exe","emclient.exe","postbox.exe","em_executable.exe"]);
let lookback = 14d;
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where RemotePort in (143, 993)
| extend proc = tolower(InitiatingProcessFileName)
| where proc !in (mailClients)                              // process↔protocol mismatch
| where not(ipv4_is_private(RemoteIP))                      // external mailbox provider
| summarize conns = count(), firstSeen = min(TimeGenerated), lastSeen = max(TimeGenerated),
            intervals = make_list(TimeGenerated, 500),
            hosts = dcount(DeviceName), hostset = make_set(DeviceName, 20)
        by proc, InitiatingProcessFolderPath, RemoteIP, RemotePort
// beacon score: low stdev of inter-connection deltas over many connections = periodic polling
| extend spanHrs = datetime_diff('hour', lastSeen, firstSeen)
| where conns >= 12 and spanHrs >= 6                        // sustained polling, not a one-off sync
| order by conns desc
// Pivot: is InitiatingProcessFolderPath a temp/user-writable path or a side-load host? (HUNT DLL side-load)
// Pivot: does any corporate mail client EVER reach this RemoteIP? If not → never-before-seen provider.
```

Platform: `SPL / Splunk` — provider never touched by a real mail client + fixed-interval polling

```spl
index=edr sourcetype=sysmon EventCode=3 dest_port IN (143,993)
| eval proc=lower(process_name)
| search NOT proc IN ("outlook.exe","thunderbird.exe","hxoutlook.exe","emclient.exe","em_client.exe")
| where NOT cidrmatch("10.0.0.0/8",dest_ip) AND NOT cidrmatch("192.168.0.0/16",dest_ip)
| streamstats current=f window=1 last(_time) as prev by host,proc,dest_ip
| eval delta=_time-prev
| stats count as conns stdev(delta) as jitter avg(delta) as cadence
        values(host) as hosts by proc,parent_process_name,dest_ip
| where conns>=12 AND jitter<60        `# near-constant interval = beaconing`
| sort - conns
```

## Triage guidance

- **Likely malicious:** a .NET binary, a signed process side-loading a DLL from a writable path, or an `mshta`/script-spawned child opening IMAPS/993 to a consumer webmail or bulletproof-hosting provider no mail client uses; near-constant poll interval (low jitter) sustained for hours/days; small symmetric-looking payloads out, small in; the same process/provider pair on several hosts; C2 reaching one of the Symantec-reported IPs 64.235.60.123 / 64.235.39.45 or through a single relay hop that then fans to an external mailbox.
- **Likely benign / expected:** approved corporate mail clients, ActiveSync/mobile middleware, backup-to-mail or ticketing connectors, and IMAP-based migration/archival tools — allowlist their process names, hosts, and the corporate mail tenants. Human mail sync is bursty and irregular, not fixed-interval; a real client reaching your own M365/Workspace tenant is expected.
- **Pivot next:** confirm the initiating process lineage (mshta→HTA? side-loaded DLL host?) and pull the binary for triage; enumerate the external mailbox/provider and block it; check whether the same host shows the low-signal collection suite (HUNT-06/07) feeding the mail channel. An active encrypted mail-C2 beacon on a corporate host is a live intrusion → escalate to incident-response-coordinator and preserve the process image + netflow before remediation.

## References

- https://www.crowdstrike.com/en-us/adversaries/imperial-kitten/
- https://www.pwc.com/gx/en/issues/cyber-security/cyber-threat-intelligence/yellow-liderc-ships-its-scripts-delivers-imaploader-malware.html
- https://attack.mitre.org/techniques/T1071/003/
- https://attack.mitre.org/techniques/T1573/001/
- https://attack.mitre.org/techniques/T1090/
