# Hunt: UNC1860 kernel-mode rootkit — TOFUDRV/WINTAPIX injection, driver-based privilege escalation, and TEMPLEDROP (repurposed Sheed-AV filter driver) anti-tamper file protection

- **Hypothesis:** If UNC1860 has established kernel-mode presence on a server, then — because the drivers give privileged, largely user-mode-invisible execution — the evidence is a stack of driver-provenance and kernel-behavior anomalies: (a) a loaded kernel driver that injects/executes code inside a privileged (local-SYSTEM) user-mode process with no legitimate parent module (TOFUDRV / WINTAPIX-overlap kernel-assisted injection), (b) that driver being the vehicle for reaching SYSTEM on a server where no legitimate driver install occurred (privilege escalation via signed/repurposed drivers), and (c) files deployed by the actor that **resist modification or deletion** because a kernel filesystem filter driver is protecting them — specifically the legitimate signed Iranian *Sheed antivirus* filter driver (TEMPLEDROP) present on a host that **does not run that AV product**. A single unknown driver is thin; the finding is the driver *stacked on* SYSTEM-process injection and/or undeletable actor files.
- **ATT&CK:**
  - T1055 — Process Injection (stealth) — kernel drivers (TOFUDRV / WINTAPIX-overlap) inject and execute payloads inside privileged host processes, running passive-backdoor logic inside legitimate processes rather than standalone executables; kernel-initiated injection is largely invisible to user-mode EDR
  - T1068 — Exploitation for Privilege Escalation (privilege-escalation) — loading malicious/repurposed drivers (TOFUDRV, TEMPLEDROP) to obtain kernel-mode local-SYSTEM execution, reflecting deep Windows kernel-internals reverse engineering
  - T1211 — Exploitation for Defense Evasion (stealth) — TEMPLEDROP repurposes a legitimate signed AV filesystem filter driver to run in kernel mode and shield deployed files from AV/EDR and analyst remediation
  - T1685 — Impair Defenses (defense-impairment) — toolset-wide defense degradation via kernel-mode file protection (TEMPLEDROP) and AV/EDR tamper resistance rather than noisy tool-killing

- **Actor procedure:** UNC1860 operates from kernel mode using malicious Windows drivers — TOFUDRV (overlapping the WINTAPIX driver family) — for privileged code execution and cross-process injection into local-SYSTEM processes, and the repurposed *Sheed AV* filesystem filter driver (TEMPLEDROP) for anti-tamper file protection. TEMPLEDROP takes a legitimate, correctly-signed third-party AV driver and weaponizes it as the actor's own defensive tooling: it runs in kernel mode and protects UNC1860's deployed files from modification or deletion, defeating both AV/EDR cleanup and analyst remediation. Driver loads blend with legitimate admin activity, and once a kernel rootkit is resident it can subvert the very host telemetry a defender would use to see it.
- **Why a hunt, not a rule:** kernel-driver-initiated injection sits *below* user-mode EDR's vantage point entirely, and driver-enforced file protection resists user-mode inspection — so the highest-fidelity artifacts are the ones the actor's own kernel code is designed to hide, and simple driver-load rules drown in legitimate signed driver churn. Critically, TEMPLEDROP's driver is *validly signed* (it is a real AV driver), so a signature-status rule passes it. The durable observable (Summiting Level 4: implementation-core — the actor cannot get kernel execution / file protection without loading a driver and, for injection, without cross-process thread creation) is *contextual*: a known-good AV filter driver present on a host with no matching AV installation; a driver load immediately followed by an unbacked thread in a SYSTEM process; actor files that survive deletion attempts. Distinguishing these from legitimate AV/backup/hypervisor drivers requires per-fleet driver baselining plus memory forensics — analyst work, not a threshold.

## Data sources required

- Sysmon EID 6 (driver load) — `ImageLoaded`, `Signature`, `SignatureStatus`, `Hashes`; cross-check against the Microsoft vulnerable/blocked-driver list, a known-good fleet driver baseline, and — critically — the installed-AV inventory per host
- Sysmon EID 8 (CreateRemoteThread) / EID 10 (ProcessAccess) for cross-process thread/handle activity into local-SYSTEM processes; EDR unbacked-thread-start-address telemetry
- Installed-software / AV-product inventory per host (to flag a *Sheed AV* filter driver where the product is not installed)
- File-operation telemetry / IR remediation feedback — files that return access-denied on delete/modify despite SYSTEM rights; memory captures for offline `driverscan`/`modules` comparison

## Query starting point

Platform: `Splunk SPL` (driver provenance + AV-inventory mismatch), then memory-forensics procedure

```
# (a) Known-good AV / third-party filter driver present on a host that does NOT run that product
index=endpoint source=*Sysmon* EventCode=6
| eval drv=lower(ImageLoaded)
| search drv IN ("*sheed*","*fltmgr-attached minifilter not in baseline*")
| join type=left host [ search index=inventory sourcetype=installed_av | fields host av_product ]
| where isnull(av_product) OR NOT match(av_product,"(?i)sheed")
| table _time host drv Signature SignatureStatus Hashes av_product

# (b) Any driver load followed within 5 min by a remote thread into a SYSTEM process
index=endpoint source=*Sysmon* EventCode=6
| eval drvload=_time | fields host drvload ImageLoaded Hashes
| join type=inner host [ search index=endpoint source=*Sysmon* EventCode=8
      | search TargetImage IN ("*\\lsass.exe","*\\services.exe","*\\svchost.exe","*\\winlogon.exe")
      | rename _time as injtime | fields host injtime SourceImage TargetImage StartAddress ]
| where injtime>=drvload AND injtime<=drvload+300
| table host ImageLoaded Hashes SourceImage TargetImage StartAddress
```

Memory-forensics procedure (the load-bearing method here): capture the server and run Volatility3 `windows.driverscan` + `windows.modules` (a driver present in objects but hidden from the module list = rootkit stealth), `windows.malfind` (RX private regions in SYSTEM processes = injected shellcode), `windows.ssdt`/`windows.callbacks` (hooked callbacks), and enumerate registered minifilter altitudes (a filter driver protecting actor paths). YARA-scan the dump for TOFUDRV/WINTAPIX and TEMPLEDROP toolmarks (HUNT-06).

## Triage guidance

- **Likely malicious:** a *Sheed AV* (or any third-party AV) filesystem filter driver loaded on a host with no corresponding AV product installed; a driver load immediately preceding an unbacked thread / injected RX region in `lsass.exe`/`services.exe`/`svchost.exe`; actor-deployed files that resist deletion/modification even from SYSTEM; a driver visible to `driverscan` but hidden from the loaded-module list; any of these on a passive-listener host (HUNT-01) or MENA gov/telecom server.
- **Likely benign / expected:** legitimate signed AV/EDR/backup/hypervisor/storage minifilters on hosts that *do* run those products (baseline the fleet's driver set + AV inventory and suppress); genuine AV file-protection (self-protection) on a host where that AV is installed; signed driver updates during patch windows. Validly-signed + known-good hash + *matching installed product* clears most — the discriminator for TEMPLEDROP is the product-vs-driver mismatch, not the signature.
- **Pivot next:** if a kernel rootkit is confirmed, treat the host's own logs and user-mode telemetry as untrustworthy, and pivot to the passive listener it protects (HUNT-01), the in-memory loaders it injects (HUNT-04), the EventLog-suspension anti-forensics (detection lane T1685.001 TEMPLELOCK), and the masquerade on the driver image (HUNT-05); extract the driver hash/signing-cert as a durable pivot for a WDAC/driver-blocklist rule (detection lane T1014/T1543.003/T1588.002). A confirmed kernel rootkit / SYSTEM injection is a severe active compromise — escalate to incident-response-coordinator immediately (live compromise is an incident, not backlog).

## References

- https://securityaffairs.com/168656/apt/unc1860-provides-iran-linked-apts-access-middle-east.html
- https://thehackernews.com/2024/09/iranian-apt-unc1860-linked-to-mois.html
- https://www.fortinet.com/blog/threat-research/wintapix-kernel-driver-middle-east-countries
- https://attack.mitre.org/techniques/T1055/
- https://attack.mitre.org/techniques/T1068/
- https://attack.mitre.org/techniques/T1211/
- https://attack.mitre.org/techniques/T1685/
