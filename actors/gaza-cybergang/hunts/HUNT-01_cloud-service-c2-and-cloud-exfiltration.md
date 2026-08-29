# Hunt: Gaza Cybergang cloud-service C2 & exfiltration over trusted SaaS (Dropbox / Google Drive / Facebook / Simplenote)

- **Hypothesis:** If a Gaza Cybergang implant (DropBook, SharpStage, NimbleMamba) is active on a host, then endpoint + egress telemetry will show a *non-browser process* (a PyInstaller-bundled binary, a .NET backdoor in `%AppData%`, or a scheduled-task-launched executable) making direct API calls to a trusted SaaS endpoint — `api.dropboxapi.com`, `content.dropboxapi.com`, `graph.facebook.com`, Google Drive or Simplenote APIs — with a *bidirectional* task-poll/response rhythm and, on the upload leg, an outbound byte volume that is anomalous for that host and unaccompanied by any interactive browser session.
- **ATT&CK:**
  - T1102 — Web Service (command-and-control)
  - T1102.002 — Web Service: Bidirectional Communication (command-and-control)
  - T1567 — Exfiltration Over Web Service (exfiltration)
  - T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage (exfiltration)
- **Actor procedure:** This is the *signature* Gaza Cybergang tradecraft. DropBook (Python/PyInstaller) and SharpStage (.NET) use Dropbox, Google Drive, Facebook, Simplenote and Quora as the C2 medium — polling actor-controlled accounts for tasks, posting host data back, and pulling follow-on stages. DropBook receives commands and NimbleMamba tasks/returns data through the Dropbox/Facebook/Simplenote APIs (full bidirectional C2). DropBook and NimbleMamba exfiltrate collected files to attacker-controlled Dropbox storage rather than dedicated C2. The whole point is to blend malicious traffic into sanctioned cloud use over TLS.
- **Why a hunt, not a rule:** the destinations are *trusted* SaaS domains reached over TLS, so domain reputation, TLS inspection and blocklists all fail by design — the traffic is indistinguishable from an employee using Dropbox. The signal only emerges by correlating *which local process* is talking to the API (non-browser, unsigned, `%AppData%`/`%TEMP%` path) against a per-host baseline of normal cloud volume and cadence. That correlation and baselining is analyst work, not a fixed threshold. (Concrete actor account handles / staging URLs from the Cybereason and Proofpoint reports are handed to detection-engineer as blocks; the process-to-SaaS behavioral shape stays here.)

## Data sources required

- CASB / cloud-app API logs (app, action, bytes up/down, OAuth token/app id) and DLP upload events
- Proxy / web-gateway / TLS-metadata logs (SNI/host, bytes in/out, user-agent, JA3) and NetFlow/Zeek `conn.log`
- Sysmon EID 3 (network connection with `Image`) + EID 1 (process lineage) — the load-bearing join between the flow and the process
- EDR process-to-network telemetry

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint source=*Sysmon* EventCode=3
| eval img=lower(Image), dst=lower(DestinationHostname)
| where match(dst,"(dropboxapi|dropbox|googleapis|drive\.google|graph\.facebook|simple-note|simplenote|quora)\.com$")
| where NOT match(img,"\\\\(chrome|msedge|firefox|iexplore|opera|brave|onedrive|googledrivefs|dropbox)\.exe$")
| eval susp_path=if(match(img,"(appdata|\\\\temp\\\\|\\\\_mei|\\\\programdata\\\\)"),1,0)
| stats count sum(coalesce(bytes_out,0)) as bytes_out dc(dst) as dst_hosts
        values(img) as images values(dst) as saas by host, User, img
| where susp_path=1 OR count > 30 OR bytes_out > 5000000
| sort - bytes_out
```

## Triage guidance

- **Likely malicious:** a process outside the browser/OneDrive/official-Dropbox allowlist reaching a cloud-storage or social API — especially one running from `%AppData%`, `%TEMP%`, a `_MEIxxxxx` PyInstaller extraction folder, or launched by a scheduled task; steady low-jitter poll intervals to `graph.facebook.com`/Simplenote (task polling) paired with a large one-directional upload burst; cloud API activity on a host with no concurrent interactive browser session or logged-on-user cloud sign-in.
- **Likely benign / expected:** the official Dropbox/OneDrive/Google Drive sync clients, backup agents, and browsers doing user-driven uploads; SaaS integrations on developer/marketing hosts. Baseline and allowlist by process + signer + host role.
- **Pivot next:** resolve the process on the endpoint → tie back to Office/XLL/.accdb or link-click initial access and the discovery burst (HUNT-02); check for PyInstaller `_MEI` artifacts and scheduled-task/Run-key persistence; if a confirmed backdoor is exfiltrating, this is a live compromise — escalate to incident-response-coordinator. Durable process-to-SaaS-API + non-browser + suspicious-path logic is Summiting Level 4 (technique implementation) and can be handed to detection-engineering as a CASB/EDR analytic.

## References

- https://www.cybereason.com/blog/new-malware-arsenal-abusing-cloud-services-in-middle-east-espionage-campaign
- https://www.proofpoint.com/us/blog/threat-insight/nimblemamba-investigating-ta402-molerats-espionage-trojan
- https://attack.mitre.org/groups/G0021/
