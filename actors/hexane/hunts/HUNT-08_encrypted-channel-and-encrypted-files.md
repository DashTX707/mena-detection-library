# Hunt: HEXANE custom-encrypted C2 beacons & encrypted/encoded payloads on disk

- **Hypothesis:** If DanBot (or a related HEXANE implant) is beaconing over its symmetric-encrypted C2 and stores its payload components encrypted on disk to defeat static analysis, then content inspection is useless and we must hunt the *shape* instead: (a) outbound sessions to a small set of destinations on a machine-regular cadence carrying high-entropy, uniformly-sized payloads that resist TLS/protocol fingerprinting or ride non-standard ports, and (b) high-entropy encrypted/encoded blobs on disk in temp/AppData that are later read and decoded at runtime by a loader. The finding is beacon-regularity + high-entropy traffic tied to a process that also drops/reads a high-entropy file, not entropy alone.
- **ATT&CK:**
  - T1573.001 — Encrypted Channel: Symmetric Cryptography (command-and-control)
  - T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File (stealth)

- **Actor procedure:** HEXANE encrypts its C2 traffic with symmetric cryptography to protect command and exfiltration content, and stores payload components in encrypted/encoded form on disk, decoding them at runtime prior to execution. Together these defeat network content inspection and static file detection, leaving traffic-shape and file-entropy behavior as the residual signal.
- **Why a hunt, not a rule:** Encryption is everywhere — the vast majority of legitimate traffic is encrypted and high-entropy files (archives, media, installers, certs, DB pages) are normal on every host, so entropy or "encrypted channel" alone is unalertable. The discriminating signal is behavioural and correlated: beacon periodicity + uniform payload sizing + destination rarity, joined to a process that drops and later reads a high-entropy blob it then executes from. That multi-signal correlation and per-environment baselining is analyst work, not a precise rule — though a proven beacon-cadence-to-rare-destination selector can be handed to detection-engineering.

## Data sources required

- Netflow / firewall / proxy with per-session byte counts, timestamps, destination, port (beacon cadence + payload-size uniformity)
- TLS metadata / JA3-JA3S (custom or rare fingerprints; TLS-on-non-standard-port; protocol-port mismatch)
- Sysmon EID 3 (network) joined to EID 1 (initiating process) — tie beacon to process
- Sysmon EID 11 (file create) with entropy scoring — high-entropy blobs in temp/AppData/ProgramData
- Sysmon EID 7 / EDR — the same process reading that blob then executing/decoding it (runtime decode)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — regular high-entropy beacon tied to a process that also drops a high-entropy file

```kusto
let lookback = 14d;
// (a) Beacon cadence to a rare external destination by a non-browser process
let beacons = DeviceNetworkEvents
    | where TimeGenerated > ago(lookback)
    | where RemoteIPType == "Public"
    | summarize conns = count(), t = make_list(TimeGenerated, 1000),
              dst = make_set(RemoteIP, 5), ports = make_set(RemotePort, 10)
        by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA1
    | where conns >= 20
    | where InitiatingProcessFileName !in~ ("msedge.exe","chrome.exe","firefox.exe","onedrive.exe","outlook.exe");
// (b) High-entropy file dropped by the SAME process (encrypted payload on disk)
let drops = DeviceFileEvents
    | where TimeGenerated > ago(lookback)
    | where FolderPath has_any (@"\temp\", @"\appdata\", @"\programdata\")
    | where FileName endswith ".dat" or FileName endswith ".bin" or FileName endswith ".tmp" or FileName matches regex @"^[a-f0-9]{8,}$"
    | summarize drops = dcount(FileName) by DeviceName, InitiatingProcessSHA1;
beacons
| join kind=inner drops on DeviceName, InitiatingProcessSHA1
| project DeviceName, InitiatingProcessFileName, conns, dst, ports, drops
| order by conns desc
// Pivot on low-jitter inter-arrival (machine cadence), uniform payload sizes, non-standard ports,
// and confirm the dropped blob is high-entropy and read/decoded at runtime by the same process.
```

## Triage guidance

- **Likely malicious:** an unsigned/LOLBin process beaconing to a rare destination on a fixed low-jitter interval with uniformly-sized high-entropy payloads (custom symmetric C2), especially on a non-standard port or protocol-port mismatch, that also drops and later reads/decodes a high-entropy blob from temp/AppData; entropy + cadence stacked on one process.
- **Likely benign / expected:** normal TLS, software-update checks, telemetry, sync clients and legitimate archives/media/installers are high-entropy and sometimes periodic. Baseline signed updaters/sync agents and known-good destinations; entropy or regularity alone from a signed vendor process is expected.
- **Pivot next:** confirmed encrypted C2 → capture the process + on-disk blob for keying/decryption, block the destination, correlate to collection/exfil (HUNT-05/07) and the DNS-tunneling detection lane (T1071.004) since DanBot alternates DNS/HTTP, and escalate to IR — an active encrypted beacon is a live C2 channel.

## References

- https://www.secureworks.com/research/lyceum-takes-center-stage-in-middle-east-campaign
- https://attack.mitre.org/techniques/T1573/001/
- https://attack.mitre.org/techniques/T1027/013/
