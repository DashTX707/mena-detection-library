# Dark Caracal — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Lebanon, Turkey, Cyprus, United Arab Emirates (Dubai/JAFZA-themed lures), Middle East (broad)  
> **Sectors:** Activists and dissidents, Journalists, Lawyers / legal institutions, Military and defense personnel, Government, Financial institutions  
> **Aliases:** Dark Caracal, MITRE ATT&CK G0070, GDGS (Lebanese General Directorate of General Security) cyber cluster, associated infrastructure overlaps: Operation Manul

## Summary

Lebanon-nexus. Lookout and EFF assess (medium-high confidence) that Dark Caracal operates from a building belonging to the Lebanese General Directorate of General Security (GDGS) in Beirut, based on test devices, exfiltrated data and infrastructure clustering. The operation has the hallmarks of a mercenary/offensive-capability-as-a-service actor: the same Bandook infrastructure and tooling has served multiple, unrelated campaigns (including 'Operation Manul' against Kazakh dissidents), so the operator is best understood as shared infrastructure serving several nation-state and private customers rather than a single monolithic APT.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Dark Caracal — Cyber-espionage at a Global Scale (2018 disclosure) | 2012 to 2018 (disclosed January 2018) | Multi-year global espionage operation attributed to the Lebanese GDGS. Delivered the Pallas Android surveillanceware via trojanized copies of popular secure-messaging and utility apps (WhatsApp/Signal/Telegram/Primo look-alikes)… | [source](https://www.lookout.com/documents/reports/lookout-dark-caracal-20180118-us.pdf) |
| Bandook: Signed & Delivered (2020 resurgence) | 2019 to 2020 | Resurgence of the Bandook Windows RAT with Certum-signed, digitally trusted samples. Infection chain: phishing email delivers a ZIP containing a malicious Word document that abuses the Office 'external template' feature to pull VBA… | [source](https://research.checkpoint.com/2020/bandook-signed-delivered/) |
| Dark Caracal: You Missed a Spot (EFF follow-on) | 2020-12 | EFF follow-on linking the 2020 Bandook activity back to the original Dark Caracal cluster and highlighting continued operational-security failures and infrastructure reuse consistent with a mercenary offensive-capability operation. | [source](https://www.eff.org/deeplinks/2020/12/dark-caracal-you-missed-spot) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**41 techniques** across 9 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 32 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 9 hunt-lane techniques
- [`iocs/`](iocs/) — **38 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **41** across 9 tactics
- Lane split: **32 detection / 9 hunt**
- IOCs: **38**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
