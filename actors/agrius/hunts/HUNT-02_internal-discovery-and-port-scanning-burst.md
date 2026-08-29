# Hunt: Agrius internal discovery burst — NetBIOS host enumeration and horizontal port-scanning ahead of lateral movement

- **Hypothesis:** If Agrius has established a foothold and is mapping the environment before lateral movement and target selection, then from a single internal host we should observe a *fan-out* of short-lived connections to many peers on a narrow set of ports (port-scan signature) and/or a burst of NetBIOS name-resolution queries across a subnet, often paired with execution of a renamed scanner binary — a pattern that stands apart from the steady, low-volume connection profile of a normal workstation or the scoped sweeps of a sanctioned inventory agent.
- **ATT&CK:**
  - T1046 — Network Service Discovery (discovery) — WinEggDrop / NimScan detailed host/port scans
  - T1018 — Remote System Discovery (discovery) — NBTscan enumeration of accessible hosts
- **Actor procedure:** In Agonizing Serpens intrusions Agrius ran open-source scanners — WinEggDrop and NimScan — to perform detailed port/service scans of hosts of interest, and used NBTscan to enumerate remote reachable hosts across the victim network. This internal reconnaissance selects the database and critical servers that are later read, staged, exfiltrated and wiped, so catching the scan burst is an upstream early-warning opportunity on the wiper kill chain.
- **Why a hunt, not a rule:** internal discovery blends with legitimate activity — vulnerability scanners, asset-inventory tools (SCCM/Tanium/Lansweeper/Nessus), network-monitoring pollers and admins troubleshooting all produce connection fan-out and NetBIOS queries, and the scan tools are trivially renamed (Summiting Level 1 filename — do not anchor here). A fixed "N connections" alert either floods on scanners or misses a slow scan. The hunt value is the *shape* (one source → many destinations → few ports, tightly clustered in time) from a host and account that has no sanctioned scanning role, requiring per-environment baselining of who legitimately scans.

## Data sources required

- Firewall / NetFlow / Zeek `conn.log` — internal east-west flows (src, dst, dport, duration, bytes) for fan-out analysis
- Sysmon EID 3 (network connect) — per-process outbound connection fan-out on the source host
- Windows Security 5156 (WFP connection allowed) where Sysmon absent
- Sysmon EID 1 / 4688 — process create for scanner-binary execution (and PE-metadata / hash for renamed tools)

## Query starting point

Platform: `Splunk SPL`

```
index=netflow OR sourcetype=zeek:conn
| eval src=src_ip, dst=dst_ip, dport=dest_port
| where cidrmatch("10.0.0.0/8",src) OR cidrmatch("172.16.0.0/12",src) OR cidrmatch("192.168.0.0/16",src)
| bin _time span=10m
| stats dc(dst) as hosts_touched dc(dport) as distinct_ports
        values(dport) as ports count as flows by _time, src
| eval fanout_ratio=round(hosts_touched/ (distinct_ports+1),1)
| where hosts_touched >= 40 AND flows >= 100
| sort - hosts_touched
```
Companion (NetBIOS / EID 3 fan-out by process): pivot on the flagged `src` into `EventCode=3`
grouped by `Image` to find the scanner process; check UDP/137 and TCP/139/445 query volume for NBTscan.

## Triage guidance

- **Likely malicious:** one internal host touching dozens–hundreds of peers on a small port set (e.g. 445/135/3389/22 or a wide TCP sweep) inside a few minutes from a workstation/server with no scanning role; the source process running from `%temp%`/`%public%`/a single-letter folder or carrying scanner PE metadata (WinEggDrop/NimScan/NBTscan) under a renamed on-disk name; scan burst on a host that also shows web-shell or credential-dumping activity.
- **Likely benign / expected:** authorized vulnerability scanners and inventory agents (baseline their source IPs/accounts and schedules); network-monitoring pollers; a new host-discovery run by IT with a matching change ticket. Suppress sanctioned scanner sources by IP/account, not by tool name.
- **Pivot next:** enumerate the destinations the scan prioritized (DB/critical servers?) and watch those for the theft-and-staging chain (HUNT-01); check the scanning host for the entry vector — web shell or valid-account RDP (HUNT-05) — and for credential dumping (detection lane, LSASS/SAM); if the scan feeds directly into lateral tool transfer, jump to HUNT-03. A scan burst co-located with staging or cred theft is a live-intrusion indicator — escalate.

## References

- https://unit42.paloaltonetworks.com/agonizing-serpens-targets-israeli-tech-higher-ed-sectors/
- https://attack.mitre.org/groups/G1030/
