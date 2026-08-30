# Hunt: APT39 exfiltration over C2 channel (outbound-volume + long-session anomalies)

- **Hypothesis:** If APT39 is pulling its collected surveillance data (keystroke logs, screenshots, PII/travel records, archives) back over the *same* channel it uses for C2, then — because the actor tracks individuals over long periods and steadily accumulates data — we should see, on hosts already showing collection/staging behavior, an outbound-volume anomaly relative to that host's own baseline: an upload-heavy byte ratio, unusually long-lived sessions to the C2 destination, and periodic bursts that align with the staging file's growth, without a matching business reason.
- **ATT&CK:**
  - T1041 — Exfiltration Over C2 Channel (exfiltration)

- **Actor procedure:** Rather than opening a separate exfil channel, APT39 sends stolen data back through its established C2 (web-shell interaction, Remexi HTTP C2, or the web-service/proxy paths in HUNT-02/HUNT-03). Harvested surveillance data — often first archived with WinRAR and lightly encoded — is trickled or bursted out over that channel, keeping the network footprint consistent with the existing beacon so a separate large upload never appears.
- **Why a hunt, not a rule:** Outbound data movement is normal everywhere (cloud sync, uploads, backups, updates), and exfil that rides the C2 channel is specifically engineered to look like ordinary beacon traffic, so a static byte-threshold rule is both noisy and evadable (the actor throttles). The signal is a *per-host, per-destination deviation* — this host is sending far more than it ever has, to a destination that isn't a sanctioned upload target, in sessions longer than its norm — which requires baselining each host against itself. That's judgement-heavy → hunt. When paired with a confirmed collection host (HUNT-01), a durable "upload-ratio + long-session to non-sanctioned destination" signal can be handed to detection-engineering.

## Data sources required

- Network flow / Zeek `conn.log` — per-session bytes-sent vs bytes-received, duration, dst (14–30d for baseline)
- Proxy / firewall egress logs (destination, bytes, session length)
- Sysmon EID 3 + EID 1 — process owning the outbound session (tie to collection/archiver lineage)
- Sysmon EID 11 (file create) — WinRAR/archive staging as a pre-exfil trigger (cross-ref T1560.001/T1074.001 detection pack)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — per-host outbound-volume deviation + upload-heavy long sessions to non-sanctioned dst

```kusto
// Build 21d per-host outbound baseline, flag hosts deviating >3 stdev with upload-heavy ratio
let base = DeviceNetworkEvents
| where TimeGenerated between (ago(21d)..ago(1d)) and ActionType == "ConnectionSuccess"
| summarize avgOut = avg(tolong(SentBytes)), sdOut = stdev(tolong(SentBytes)) by DeviceName;
DeviceNetworkEvents
| where TimeGenerated > ago(1d) and ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| summarize sent = sum(tolong(SentBytes)), recv = sum(tolong(ReceivedBytes)),
            maxDur = max(tolong(parse_json(AdditionalFields).DurationSeconds)),
            sessions = count()
        by DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessFolderPath
| extend upRatio = todouble(sent) / (recv + 1)
| join kind=inner base on DeviceName
| where sent > avgOut + 3 * sdOut                       // volume outlier vs host's own baseline
| where upRatio > 2.0 or maxDur > 3600                  // upload-heavy OR long-lived session
// exclude sanctioned upload destinations (backup/cloud/CDN) by dst allowlist (wiki baseline)
| order by sent desc
// Enrich: was a WinRAR/7z archive written on this host in the prior 24h? (staging->exfil pairing)
```

## Triage guidance

- **Likely malicious:** a host sending far above its own 21-day baseline, upload-heavy (bytes-out >> bytes-in) and/or in unusually long sessions, to a public destination that is not a sanctioned upload target — especially when the owning process is the same one flagged for collection (HUNT-01) or an archive was staged just beforehand, and the host belongs to a targeted user (telecom/travel/HR/legal). Trickle-exfil that tracks staging-file growth over days is a strong APT39 tell.
- **Likely benign / expected:** cloud backup and file-sync (OneDrive/Dropbox/Google Drive), video calls and screen-sharing, large legitimate uploads to sanctioned SaaS, OS/app update check-ins, and CI/artifact pushes produce high outbound volume — allowlist sanctioned destinations and known apps, and account for role (a designer uploading assets differs from an HR laptop). A one-off large upload to a corporate destination is expected.
- **Pivot next:** identify the destination and cross-ref HUNT-02/HUNT-03 (is this the C2/proxy/web-service path?); confirm what was staged (archive contents, encoding — T1027.013/T1140); scope which user's data left and over what window; assess sensitivity (PII/travel records). Confirmed data leaving to attacker infrastructure is an active exfiltration incident → escalate to IR immediately and begin impact/notification assessment.

## References

- https://attack.mitre.org/groups/G0087/
- https://attack.mitre.org/techniques/T1041/
- https://www.mandiant.com/resources/blog/apt39-iranian-cyber-espionage-group-focused-on-personal-information
