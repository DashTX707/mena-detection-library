# Hunt: POLONIUM — off-victim VPS infrastructure & capability-development tracking

- **Hypothesis:** POLONIUM builds its own tooling and stands up its own infrastructure off-victim, so most of this activity is invisible on our endpoints — but if the group has selected us, the on-victim tell is *outbound contact with the infrastructure they acquired* and *execution of the capabilities they developed or obtained*. If we track HostGW IP-only VPS clusters and Creepy-family/Plink/AirVPN indicators as intel, then any internal host beaconing to those ranges — or running a newly-seen Creepy-family variant or acquired library (AForge.NET, MegaApiClient, Plink) — is the downstream landing point of that off-victim prep. The finding is an internal asset that touches curated POLONIUM infrastructure OR runs a capability matching the Creepy-family development signature.
- **ATT&CK:**
  - T1583.003 — Acquire Infrastructure: Virtual Private Server (resource-development) — dedicated HostGW VPS, IP-only; hunt egress to tracked VPS ranges (45.80.148.0/22, 185.244.129.0/24).
  - T1587.001 — Develop Capabilities: Malware (resource-development) — seven bespoke Creepy backdoors; hunt for new/unsigned .NET+PowerShell implants matching the family's development signature.
  - T1588.001 — Obtain Capabilities: Malware (resource-development) — public keylogger code and libraries (AForge.NET, MegaApiClient) folded into modules; hunt image-loads of those libraries by non-standard processes.
  - T1588.002 — Obtain Capabilities: Tool (resource-development) — Plink and AirVPN operationalized; hunt downstream Plink execution and AirVPN egress as the on-victim landing of the acquisition.

- **Actor procedure:** POLONIUM acquired **dedicated VPS via HostGW**, entirely **IP-only with no domains** (defeats DNS pivots), and developed **at least seven custom backdoors** (CreepyDrive/CreepySnail, DeepCreep, MegaCreep, FlipCreep, TechnoCreep, PapaCreep) plus modular keylogger/screenshot/webcam/reverse-shell/exfil components. It reused **public code and libraries** rather than writing everything from scratch — AForge.NET for webcam capture, MegaApiClient for Mega — and **operationalized public tooling** (Plink SSH tunneling, AirVPN). These off-victim acts land on-victim as: outbound sessions to HostGW ranges, execution of Creepy-family binaries, and image-loads of the borrowed libraries.
- **Why a hunt, not a rule:** Infrastructure acquisition and malware development happen entirely off our network — there is nothing on-endpoint to alert on for the resource-development act itself. What is on-victim (egress to an IP-only range, a new unsigned .NET binary, an AForge.NET load) is individually low-fidelity and shifts as the actor rotates VPS and recompiles implants — brittle IOCs, not durable signals. The value is intel-fusion: maintaining the tracked-infrastructure watchlist and judging whether an internal touch of it, combined with a matching capability, indicates targeting. If a stable observable emerges (e.g., egress to a confirmed still-live HostGW C2 /24 — a Level-2/3 observable), hand it to detection-engineering while noting IOC decay.

## Data sources required

- Curated POLONIUM infrastructure watchlist: pack VPS IPs + HostGW ranges (45.80.148.0/22, 185.244.129.0/24), refreshed against current intel
- NetFlow / firewall / proxy egress logs (to match internal hosts against the watchlist)
- EDR image-load telemetry (Sysmon EID 7) for AForge.NET / MegaApiClient / PuTTY-Plink modules; process-creation for Plink and Creepy-family SHA-1s
- Threat-intel feed of new Creepy-family variant hashes (ESET malware-ioc/polonium repo)

## Query starting point

Platform: `Splunk SPL (NetFlow + EDR)`

```spl
(index=netflow OR index=firewall)
| eval dst_track=case(
    cidrmatch("45.80.148.0/22", dest_ip), "HostGW-45.80",
    cidrmatch("185.244.129.0/24", dest_ip), "HostGW-185.244",
    match(dest_ip, "^(37\.120\.233\.89|172\.96\.188\.51|212\.73\.150\.174|94\.156\.189\.103|51\.83\.246\.73)$"), "known-VPS",
    1==1, null())
| where isnotnull(dst_track)
| stats count sum(bytes_out) as bytes_out values(dest_port) as ports
        min(_time) as first max(_time) as last by src_ip dst_track dest_ip
| join type=left src_ip
    [ search index=edr (Image="*plink*" OR ImageLoaded="*AForge*" OR ImageLoaded="*MegaApiClient*"
        OR file_hash IN (creepy_family_hashes.csv))
      | stats values(Image) as procs values(ImageLoaded) as libs by src_ip ]
| eval score = if(isnotnull(procs),2,0) + 1
| sort - score, - bytes_out
```

## Triage guidance

- **Likely malicious:** an internal workstation (not a scanner) with sustained egress to a HostGW /24, low byte volume consistent with beaconing, that *also* runs Plink or loads AForge.NET/MegaApiClient; a newly-appeared unsigned .NET binary whose hash matches a Creepy-family variant; a non-admin host initiating SSH to an IP-only VPS.
- **Likely benign / expected:** security scanners, threat-intel sandboxes, and researchers that deliberately touch tracked ranges (exclude by asset role); developers legitimately using PuTTY/Plink to known internal jump hosts; AForge.NET present in a real machine-vision app. A watchlist hit alone is thin — the capability overlay on the same host is what elevates it.
- **Pivot next:** on a stacked hit, pull the full process tree and file-writes on that host (HUNT-06 staging, detection pack T1105 ingress), confirm whether the egress is cloud-C2 (HUNT-03) or raw-port C2, and if a live Creepy implant is confirmed, escalate to incident-response-coordinator. Feed any newly-confirmed live C2 IP back into the watchlist and to detection-engineering.

## References

- https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/
- https://github.com/eset/malware-ioc/tree/master/polonium
- https://attack.mitre.org/techniques/T1583/003/
- https://attack.mitre.org/techniques/T1587/001/
- https://attack.mitre.org/techniques/T1588/001/
- https://attack.mitre.org/techniques/T1588/002/
