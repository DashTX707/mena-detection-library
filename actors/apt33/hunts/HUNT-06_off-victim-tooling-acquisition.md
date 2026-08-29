# Hunt: APT33 off-victim tooling acquisition — on-victim traces of obtained capabilities

- **Hypothesis:** Tool acquisition (T1588.002) happens off-victim and is invisible to our sensors — so, assuming APT33 has already obtained its known toolset, we hunt the *on-victim footprint* of those acquired capabilities: execution or presence of the commodity/open-source tools APT33 is documented to obtain and field (DarkComet, NanoCore, QuasarRAT, NetWire, PoshC2, AutoIt, AzureHound, Roadtools, AnyDesk) and its custom implants (TURNEDUP, POWERTON, FalseFont, EagleRelay) — surfaced as never-before-seen binaries in the fleet, tools running from user-writable paths, and RMM/enumeration utilities appearing on hosts/identities where they are not sanctioned.
- **ATT&CK:**
  - T1588.002 — Obtain Capabilities: Tool (resource-development) — hunted via on-victim execution traces; the acquisition itself is off-victim

- **Actor procedure:** APT33 obtains and fields a mix of commodity and open-source tooling — DarkComet, NanoCore, QuasarRAT, NetWire, PoshC2, AutoIt, and later AzureHound/Roadtools/AnyDesk — alongside its custom TURNEDUP/POWERTON/FalseFont/EagleRelay, reducing reliance on wholly custom malware. The purchase/download of these tools occurs on infrastructure we cannot see; our only visibility is when an acquired tool executes or is staged inside our environment.
- **Why a hunt, not a rule:** This technique is explicitly off-victim — there is no acquisition event to alert on, so it can never be a rule; it is a threat-intel-awareness and fleet-baselining hunt. The on-victim traces are also base-rate-heavy: many of these tools have legitimate uses (AnyDesk is a sanctioned RMM somewhere, AutoIt and PowerShell frameworks appear in benign automation, red teams run QuasarRAT/PoshC2). The durable signal is *never-before-seen software in the fleet* (a long-tail/software-discovery anomaly) plus *unsanctioned-location/identity* context, which needs a per-environment software-inventory baseline and judgement → hunt. Where a tool is categorically unsanctioned (e.g. AzureHound in a production tenant), that is a clean observable to hand to detection-engineering / RMM-allowlisting.

## Data sources required

- EDR / software inventory (least-frequently-seen binaries across the fleet — long-tail analysis)
- Sysmon EID 1 (process create, command line, hashes, signer) + EID 7 (image load) + EID 11 (drop path)
- Entra ID / MSGraph audit (AzureHound/Roadtools enumeration bursts — cross-ref detection pack T1087.004/T1526)
- Network / proxy (AnyDesk, RMM and known-RAT C2 destinations); RMM allow-list
- Threat-intel enrichment (hashes/names of the documented APT33 toolset as *hunt pivots*, not the basis)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — least-frequently-seen executables + named APT33 tooling in unsanctioned context

```kusto
// (a) Long-tail / never-before-seen binary in the fleet (software-discovery anomaly)
let seen = DeviceProcessEvents
    | where TimeGenerated between (ago(90d)..ago(3d))
    | summarize by SHA256;
DeviceProcessEvents
| where TimeGenerated > ago(3d)
| where SHA256 !in (seen)                                   // never-before-seen in 90d
| where FolderPath has_any (@"\Users\", @"\Temp\", @"\AppData\", @"\ProgramData\")  // user-writable
| summarize hosts = dcount(DeviceName), first = min(TimeGenerated),
            paths = make_set(FolderPath, 10) by FileName, SHA256, Signer = tostring(Signer)
| where hosts <= 3                                          // rare = worth a look
| order by first desc

// (b) Named APT33 toolset as hunt pivots (low-fidelity on their own — corroborate with (a))
// DeviceProcessEvents
// | where FileName has_any ("AnyDesk","AzureHound","roadrecon","roadtx","AutoIt3","Quasar" ,"nanocore","darkcomet","netwire","posh")
// | where DeviceName !in (sanctioned RMM/admin hosts) or FolderPath has_any (@"\Temp\",@"\AppData\")
```

## Triage guidance

- **Likely malicious:** a never-before-seen unsigned binary executing from `%TEMP%`/`%APPDATA%` on a handful of hosts; AnyDesk (or other RMM) installed on a host where it is not the sanctioned tool and beaconing out; AzureHound/Roadtools/roadrecon enumeration from a recently-authenticated identity in a tenant that has no red-team engagement; a known-RAT family name or hash landing in a user-writable path; tooling appearing right after a suspicious sign-in (HUNT-01) or delivery event.
- **Likely benign / expected:** sanctioned RMM on its approved hosts, authorized red-team/pentest tooling within a scoped window, developer automation using AutoIt/PowerShell, and legitimately rare-but-signed enterprise apps — allowlist the sanctioned RMM, known admin hosts and any active engagement; a signed, expected tool on its normal host is not a finding. Rarity + unsanctioned location/identity is the discriminator.
- **Pivot next:** on a hit, pull the binary's full process lineage and network egress (HUNT-03), its drop chain (HUNT-05), and — for cloud enumeration tools — the identity's sign-in path (HUNT-01) and Graph activity (detection pack T1087.004/T1526). Confirmed adversary tooling in place is a live incident → escalate to IR; route categorically-unsanctioned tools (AzureHound in prod, unapproved RMM) to detection-engineering / allowlisting.

## References

- https://attack.mitre.org/techniques/T1588/002/
- https://www.mandiant.com/resources/blog/apt33-insights-into-iranian-cyber-espionage
- https://www.microsoft.com/en-us/security/blog/2023/09/14/peach-sandstorm-password-spray-campaigns-enable-intelligence-collection-at-high-value-targets/
- https://attack.mitre.org/groups/G0064
