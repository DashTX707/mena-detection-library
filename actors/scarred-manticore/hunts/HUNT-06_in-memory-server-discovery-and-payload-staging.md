# Hunt: Scarred Manticore in-memory host fingerprinting, IIS site enumeration, and operator payload staging on a compromised server

- **Hypothesis:** If a LIONTAIL/SDD implant is resident on an IIS/Exchange server, then its host-profiling, site-enumeration, and tool-staging will surface not as discrete discovery commands (there are none — the work happens in-memory inside `w3wp.exe`/the loader) but as *second-order* artifacts: registry reads of `SecureBoot\State` / `System\Bios` / `CurrentVersion` and `System\CurrentControlSet\Services\HTTP` from a web-worker context, a web process programmatically reading IIS site/binding configuration (`ServerManager` / `%windir%\System32\inetsrv\config\applicationHost.config`), and new files or freshly-loaded .NET assemblies appearing on the server with **no** corresponding inbound download in proxy/EDR file-write logs (delivered straight through the passive listener).
- **ATT&CK:**
  - T1082 — System Information Discovery (discovery) — LIONTAIL nested-shellcode fingerprinting payload (GetComputerNameW, GetNativeSystemInfo, GetPhysicallyInstalledSystemMemory; registry reads of `CurrentVersion`, `SecureBoot\State`, `System\Bios`)
  - T1518 — Software Discovery (discovery) — SDD backdoor using the .NET `ServerManager` (IIS) class to list sites/bindings and build its listen-prefix set
  - T1105 — Ingress Tool Transfer (command-and-control) — SDD `Upload` (write operator file to a path) / `Rundll` (load & run an operator-delivered .NET assembly); LIONTAIL receiving arbitrary shellcode from operators
- **Actor procedure:** After the passive implant is live, the operators profile the host with an in-memory fingerprinting payload (computer/domain name, 64-bit flag, processor count, RAM, and `SecureBoot`/`Bios`/`CurrentVersion` registry values), enumerate the IIS sites/bindings via `ServerManager` so the rogue listener can blend into legitimate URL prefixes, and stage further tooling by pushing files or .NET assemblies straight through the listener (`Upload`/`Rundll`) rather than pulling them from an external URL. None of this generates a normal `whoami`/`systeminfo` process or a clean download-then-execute chain.
- **Why a hunt, not a rule:** each individual signal is either invisible or ubiquitous (Level 1). Registry reads of `CurrentVersion` happen constantly; reading `applicationHost.config` is what IIS management legitimately does; a file appearing on a server is normal. The durable, actor-forced discriminators (Summiting Level 2–3) are *the anomalous actor and the missing provenance*: the reads/enumeration are performed **by `w3wp.exe` or the loader process** (not by an admin console, `IISReset`, or `Get-Website` run interactively), the `SecureBoot\State`/`System\Bios` combination is an unusual profiling set for a web worker, and a new server-side executable/assembly has **no** preceding inbound transfer because it arrived through the passive channel. Correlating "in-memory discovery by the web worker" + "site-config read by that same process" + "file/assembly materialised with no download" against a per-server baseline is analyst work, not a threshold.

## Data sources required

- Sysmon EID 12/13 (registry) for reads/writes to `HKLM\...\CurrentVersion`, `SecureBoot\State`, `HARDWARE\...\System\Bios`, and `Services\HTTP` — attributed to a process image
- Sysmon EID 1/7 (process create / image load) to attribute the reads and the `ServerManager`/`Microsoft.Web.Administration` assembly load to `w3wp.exe` or the loader
- File access/open telemetry for `%windir%\System32\inetsrv\config\applicationHost.config` by non-management processes
- Sysmon EID 11 (file create) on IIS content roots, `%TEMP%`, and service paths + EDR assembly/CLR-load events — cross-referenced against proxy/EDR **inbound file-transfer** logs to spot files that appear with no download
- IIS request logs (to correlate staging with listener activity — see HUNT-01)

## Query starting point

Platform: `Splunk SPL`

```
/* A: web worker performing host/site profiling reads */
index=endpoint source=*Sysmon* EventCode IN (12,13)
| eval proc=lower(Image), key=lower(TargetObject)
| where match(proc,"\\\\(w3wp|inetinfo)\.exe$") OR match(proc,"\\\\temp\\\\")
| where match(key,"secureboot\\\\state|hardware\\\\description\\\\system\\\\bios|currentversion$|services\\\\http")
| stats values(key) as keys count by host proc
| where count>=2
| eval stage="A_inmemory_profiling"
| append [
  /* B: server-side executable/assembly materialised with NO inbound download */
  search index=endpoint source=*Sysmon* EventCode=11
  | eval f=lower(TargetFilename)
  | where match(f,"\.(aspx|dll|exe|ashx)$") AND match(f,"inetpub|inetsrv|\\\\temp\\\\|system32")
  | join type=left host [ search index=proxy OR index=edr_filetransfer direction=inbound | eval f=lower(saved_path) | fields host f _time ]
  | where isnull(direction)
  | eval stage="B_no_download_provenance"
  | table _time host TargetFilename Image stage ]
| table _time host proc keys TargetFilename stage
```

Also run periodically as a procedure: on suspect servers, dump loaded modules of `w3wp.exe` and compare to a golden module list; a `Microsoft.Web.Administration` (ServerManager) load inside a worker that isn't running IIS management tooling is high-signal.

## Triage guidance

- **Likely malicious:** `w3wp.exe` (or a loader in `%TEMP%`/a service path) reading the `SecureBoot\State` + `System\Bios` + `CurrentVersion` profiling set; a web-worker process programmatically enumerating IIS sites/bindings outside any admin session; a new `.aspx`/`.dll`/`.exe` on the server with no matching inbound transfer and no install/patch event. Any of these on the **same host** as a HUNT-01 listener finding is a confirmed intrusion.
- **Likely benign / expected:** IIS Manager, `appcmd`, `Get-Website`/WebAdministration run interactively by a known admin; patch/deploy pipelines writing assemblies (they have a corresponding package/download and a signed installer); monitoring agents reading `CurrentVersion`. Attribute the activity to a *human admin session or a known deployment job* and it clears.
- **Pivot next:** a confirmed staged file → hash it and hand to HUNT-05 (masquerade check) and HUNT-07 (code-similarity). The profiling activity confirms an active operator — pivot to the passive listener (HUNT-01), in-memory execution (HUNT-03), and EWS exfil (detection lane T1114.002/T1041). A confirmed live implant on a production server is an active intrusion — escalate to incident-response-coordinator.

## References

- https://research.checkpoint.com/2023/from-albania-to-the-middle-east-the-scarred-manticore-is-listening/
- https://attack.mitre.org/techniques/T1082/
- https://attack.mitre.org/techniques/T1518/
- https://attack.mitre.org/techniques/T1105/
