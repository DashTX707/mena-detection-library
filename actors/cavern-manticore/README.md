# Cavern Manticore — Detection & Hunt Pack

> **Attribution:** Iran-nexus — high-medium confidence  
> **MENA targeting:** Israel, Gulf / Arabian Peninsula organizations  
> **Sectors:** Technology, Government / local government, Defense, Healthcare, Education, Manufacturing  
> **Aliases:** DEV-0270, Nemesis Kitten, Cobalt Mirage, TunnelVision, UNC2448, PHOSPHORUS (parent cluster), Secnerd (cover company), Lifeweb (cover company)

## Summary

Iran-nexus, assessed as a sub-cluster of the Iranian state-aligned actor PHOSPHORUS (Mint Sandstorm), operated by a company running under the public aliases Secnerd and Lifeweb and linked to MOIS-affiliated contractors Najee Technology and Afkar System. Activity blends financially motivated ransomware/extortion (opportunistic, likely not fully state-sanctioned) with espionage-aligned intrusion in support of Iranian state interest. Secureworks tracks two behavioral clusters: Cluster A opportunistically encrypts (BitLocker/DiskCryptor) for low ransom demands, while Cluster B conducts more targeted intrusion using Fast Reverse Proxy (FRPC).

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| DEV-0270 BitLocker/DiskCryptor full-disk-encryption extortion | 2021 to 2022 | Opportunistic ransomware operations that gain access by early exploitation of high-severity vulnerabilities (Exchange ProxyShell/ProxyLogon, Fortinet CVE-2018-13379, Log4Shell), then abuse the native Windows BitLocker feature on servers… | [source](https://www.microsoft.com/en-us/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/) |
| COBALT MIRAGE ransomware operations in U.S. (FRPC intrusions) | 2020 to 2022 | Intrusions into U.S. and other organizations by exploiting internet-facing applications (Log4Shell on VMware Horizon, ProxyShell on Exchange, Fortinet FortiOS). Actors deploy Fast Reverse Proxy Client (FRPC, masqueraded as audio.exe)… | [source](https://www.secureworks.com/blog/cobalt-mirage-conducts-ransomware-operations-in-us) |
| TunnelVision Log4Shell exploitation of VMware Horizon | 2021 to 2022 | Wide exploitation of Log4Shell (CVE-2021-44228 / CVE-2021-45046) against internet-facing VMware Horizon (Tomcat ws_TomcatService.exe) to run PowerShell, deploy backdoors, create backdoor admin users, harvest credentials (Procdump, SAM… | [source](https://www.sentinelone.com/labs/log4j2-in-the-wild-iranian-aligned-threat-actor-tunnelvision-actively-exploiting-vmware-horizon/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**34 techniques** across 13 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 29 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 5 hunt-lane techniques
- [`iocs/`](iocs/) — **57 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **34** across 13 tactics
- Lane split: **29 detection / 5 hunt**
- IOCs: **57**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
