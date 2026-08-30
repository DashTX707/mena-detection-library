# Hunt: Tropic Trooper — in-memory decode & native-API loader tradecraft that blends with signed binaries

- **Hypothesis:** If the Crowdoor loader is resident, then the runtime decode/execute chain leaves almost nothing discrete on disk — the signal is *relational and behavioral*: a legitimate signed host binary (`inst.exe` / `WinStore.exe`) side-loads an unsigned DLL from an odd path, that DLL resolves native Windows APIs directly (rather than via normal high-level imports) to RC4-decrypt shellcode in memory (`fYTUdr643$3u`) and inject it, and `colorcpl.exe` — a benign color-management applet — is launched with argument `"2"`, holds an injected/RWX region, and then makes outbound HTTPS. No single step alarms; the *chain* (side-load -> in-memory decode via native API -> injection into `colorcpl.exe` -> beacon) on one host is the finding. This hunt stitches the low-signal decode/native-API steps (T1140/T1106) onto the higher-signal side-load and injection anchors so they're not lost in the noise.
- **ATT&CK:**
  - T1140 — Deobfuscate/Decode Files or Information (stealth) — loader RC4-decrypts embedded shellcode and the web shell performs multi-layer Base64 decode at runtime; hunted as the in-memory step between a side-load and an injection, not standalone.
  - T1106 — Native API (execution) — Crowdoor resolves/calls native Windows APIs directly to decrypt and inject shellcode, minimizing on-disk footprint; hunted via dynamic API resolution (`GetProcAddress`/`LdrGetProcedureAddress` bursts, `VirtualAlloc`+RWX, `WriteProcessMemory`/`CreateRemoteThread`) correlated with the side-load event.

- **Actor procedure:** From the Kaspersky pack: signed `inst.exe`/`WinStore.exe` are dropped alongside malicious `VERSION.dll` / `datast.dll` / `datastate.dll` in `c:\Windows\branding\data` or `c:\Users\Public\Music\data`; DLL search-order hijack makes the trusted EXE load the attacker DLL, which RC4-decrypts (key `fYTUdr643$3u`) the Crowdoor shellcode and injects it into `colorcpl.exe` launched with command-line `"2"`. The loader resolves and calls native APIs to do the decrypt/execute/inject in memory, keeping the shellcode off disk. `datast.dll` exports `InitCore` (older) or `Ldf`/`rcd` (updated); `datastate.dll` exports `Clear`/`Server`. Injected `colorcpl.exe` then beacons HTTPS to `blog.techmersion[.]com:443`. The web shell's own multi-layer Base64 decode-before-execute is the same "decode at runtime, leave little on disk" pattern on the IIS side.
- **Why a hunt, not a rule:** Native-API use (T1106) and in-memory decode (T1140) are, in isolation, ubiquitous and generic — every packer, installer and legitimate loader resolves APIs dynamically and decodes data; a standalone alert on `VirtualAlloc`+RWX or `GetProcAddress` volume would bury the SOC. The signal only exists when these low-fidelity steps are *chained* to the actor's higher-fidelity anchors (side-load of a named DLL from an odd path; injection into `colorcpl.exe` with arg `"2"`) on the same host in the same window. Assembling and judging that multi-event chain across EDR module-load, image-load, memory and network telemetry is correlation work. If the tight chain proves reliably observable end-to-end (e.g., `colorcpl.exe` arg `"2"` + injected thread + outbound 443), hand that specific sequence to detection-engineering as a scoped analytic; the generic decode/native-API steps stay in the hunt.

## Data sources required

- EDR / Sysmon image-load (EID 7): unsigned/odd-path DLL loaded by a signed process; signature-mismatch on `VERSION.dll`/`datast.dll`/`datastate.dll`
- EDR / Sysmon cross-process access & injection (EID 8 CreateRemoteThread, EID 10 ProcessAccess) targeting `colorcpl.exe`; memory-region telemetry (RWX private/committed regions, unbacked executable memory)
- Process creation (EID 1) with full command line — `colorcpl.exe` launched with arg `"2"`, and its parent lineage
- Process-to-network (EID 3) — outbound 443 from `colorcpl.exe` / injected process
- (Where available) API-monitoring / ETW for dynamic resolution bursts (`LdrGetProcedureAddress`) — the native-API tell

## Query starting point

Platform: `Microsoft Defender XDR (KQL)` — anchor on the injection/network step and walk back to the side-load and decode on the same host

```kusto
// (a) colorcpl.exe launched oddly and/or talking to the network = injection anchor
let colorAnom = union DeviceProcessEvents, DeviceNetworkEvents
    | where TimeGenerated > ago(30d)
    | where FileName =~ "colorcpl.exe" or InitiatingProcessFileName =~ "colorcpl.exe"
    | where (ProcessCommandLine has_cs " 2" and FileName =~ "colorcpl.exe")
         or (RemotePort == 443 and InitiatingProcessFileName =~ "colorcpl.exe")
    | project TimeGenerated, DeviceId, DeviceName,
              why=strcat("colorcpl:", coalesce(ProcessCommandLine, tostring(RemoteUrl)));
// (b) signed host binary side-loading a DLL from an unusual data path = side-load anchor
let sideLoad = DeviceImageLoadEvents
    | where TimeGenerated > ago(30d)
    | where InitiatingProcessFileName in~ ("inst.exe","winstore.exe")
    | where FolderPath has @"\branding\data" or FolderPath has @"\public\music\data"
         or FileName in~ ("version.dll","datast.dll","datastate.dll")
    | where isempty(SHA1) or InitiatingProcessFileName != FileName   // module vs host mismatch
    | project TimeGenerated, DeviceId, DeviceName, LoadedDll=FileName, FolderPath, HostBin=InitiatingProcessFileName;
// (c) fuse the two anchors on the same device within a short window
sideLoad
| join kind=inner (colorAnom) on DeviceId
| where abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)) <= 60
| project DeviceName, LoadedDll, FolderPath, HostBin, why, sideLoadTime=TimeGenerated, colorTime=TimeGenerated1
// Same-host side-load + colorcpl anomaly in one hour = Crowdoor chain, investigate for in-memory RC4 decode
```

## Triage guidance

- **Likely malicious:** `inst.exe`/`WinStore.exe` loading an unsigned `VERSION.dll`/`datast.dll`/`datastate.dll` from `\branding\data` or `\Public\Music\data`, followed within the hour by `colorcpl.exe` (arg `"2"`) holding an RWX/unbacked region and beaconing 443; memory scan of `colorcpl.exe` yielding the RC4 key `fYTUdr643$3u` or `datast.dll`'s `InitCore`/`Ldf`/`rcd` exports; a burst of dynamic API resolution in the side-loaded module immediately preceding an injection.
- **Likely benign / expected:** legitimate `colorcpl.exe` run interactively from Control Panel (no odd arg, no network, no injected region); signed installers and updaters that resolve APIs dynamically and decode compressed resources; DLLs legitimately loaded by their real host from Program Files. Native-API use and in-memory decode alone are normal — require the side-load path anomaly *and* the injection/network step before calling it.
- **Pivot next:** on a confirmed chain, capture a memory image of `colorcpl.exe` and the side-loaded DLL (recover RC4 key/exports for attribution), pivot to persistence (detection pack T1543.003 `WinStore` service / T1547.001 Run-key) and C2 (T1071.001 `blog.techmersion[.]com`), and check HUNT-04 for the staging directory that fed the DLLs. A live Crowdoor loader is an active compromise — escalate to incident-response-coordinator.

## References

- https://securelist.com/new-tropic-trooper-web-shell-infection/113737/
- https://attack.mitre.org/groups/G0081/
- https://attack.mitre.org/techniques/T1140/
- https://attack.mitre.org/techniques/T1106/
