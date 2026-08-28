# Hunt: Defender masquerading & local proxy / tool tampering

- **Hypothesis:** If MuddyWater is evading defenses on this host, then we should find (a) executables, filenames or registry keys **masquerading as Windows Defender** but living in non-standard paths / created by the wrong parent, and/or (b) tampering with the system's **local proxy settings** (disabling `ProxyEnable`/clearing `ProxyServer`) to reroute or blind traffic — a masquerading + property-mismatch anomaly and an unexpected configuration change.
- **ATT&CK:**
  - T1036.005 — Masquerading: Match Legitimate Resource Name or Location (defense-evasion)
  - T1685 — Disable or Modify Tools (defense-evasion)
- **Actor procedure:** MuddyWater has **disguised malicious executables and used filenames and Registry key names associated with Windows Defender**, and can **disable the system's local proxy settings**.
- **Why a hunt, not a rule:** Defender-themed names and paths are also produced by the real Defender, and proxy-setting changes are made routinely by GPO, VPN clients and admins — so a fixed alert misfires constantly. The signal is contextual: a "Defender" file/key in the *wrong location* or created by a script interpreter, or a proxy change made by a non-management process. That requires baselining the legitimate owners of these names/keys.

## Data sources required

- Sysmon EID 11 (file create) + EID 1 (process) for Defender-named binaries outside canonical paths
- Sysmon EID 13 (registry set) on `...\Internet Settings\ProxyEnable` / `ProxyServer` and Defender-named Run/service keys
- EDR process-lineage (which process made the change)

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (EventCode=11 OR EventCode=13 OR EventCode=1)
| eval tgt=lower(coalesce(TargetFilename,TargetObject,Image))
| eval proc=lower(coalesce(Image,SourceImage))
| eval defender_masq=if( (like(tgt,"%defender%") OR like(tgt,"%msmpeng%") OR like(tgt,"%windows defender%"))
        AND NOT match(tgt,"(program files\\windows defender|programdata\\microsoft\\windows defender|system32)"),1,0)
| eval proxy_tamper=if(match(tgt,"internet settings\\(proxyenable|proxyserver)"),1,0)
| where defender_masq=1 OR proxy_tamper=1
| eval mgmt=if(match(proc,"(gpscript|svchost|mpcmdrun|msmpeng|wuauclt|setup|vpnagent)\.exe"),1,0)
| where mgmt=0
| stats count values(tgt) as target values(proc) as by_process
        values(Details) as value by host, user, defender_masq, proxy_tamper
| sort - count
```

## Triage guidance

- **Likely malicious:** A "WindowsDefender"/`MsMpEng`-named file under `%appdata%`/`%temp%`/user path; a Defender-themed Run key or service pointing at a non-Defender binary; `ProxyEnable` set to 0 or `ProxyServer` altered by a script interpreter (`powershell.exe`/`wscript.exe`) or unknown binary rather than GPO/VPN client.
- **Likely benign / expected:** Genuine Defender under `C:\Program Files\Windows Defender` / `ProgramData\Microsoft\Windows Defender`; proxy changes from GPO (`gpscript.exe`), corporate VPN clients, or admin scripts; PAC-file rollouts. Baseline the legitimate proxy-change agents.
- **Pivot next:** If proxy was disabled, correlate immediately with new outbound C2 (→ HUNT-05) that may now bypass the proxy; reputation-check the masquerading binary; check autostart/persistence tied to it.

## References

- https://attack.mitre.org/groups/G0069/
