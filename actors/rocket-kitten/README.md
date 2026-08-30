# Rocket Kitten — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium-high confidence  
> **MENA targeting:** Israel, Saudi Arabia, Iran (domestic dissidents, academics, journalists), United Arab Emirates, Yemen, Iraq  
> **Sectors:** Defense / defense-industrial base, Academia / scientists / scholars / research institutes, Government / ministry officials, Media / journalists, Human-rights activists and dissidents, Nuclear / missile / policy experts  
> **Aliases:** Rocket Kitten, Group 41, Operation Woolen-Goldfish, Woolen-GoldFish, Thamar Reservoir (campaign), TEMP.Beanie, Wool3n.H4t / Woole3n.H4t (operator handle), Ajax Security Team (MITRE G0130 cluster alias)

## Summary

Iran-nexus cyber-espionage group, assessed as aligned with / operating on behalf of the Islamic Revolutionary Guard Corps (IRGC). Attribution rests on convergence of: Farsi-language artifacts and operator handles (Wool3n.H4t / 'Masoud_pk', 'Yaser'), targeting sets of clear Iranian state interest (Israeli defense and academia, Saudi Arabia, and Iranian dissidents/journalists/human-rights activists at home and in diaspora), Iranian hosting/registration pivots (an inactive Iran-hosted blog for Wool3n.H4t; use of the free Iranian AV-scanning service av.zerodays.ir to pre-test samples), and re-use of the same custom GHOLE/CWoolger tooling and personas across campaigns. MITRE tracks the cluster under Ajax Security Team (G0130).

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Operation Woolen-GoldFish / The GHOLE Campaign | 2014 to early 2015 | Spear-phishing of Israeli and European targets with malicious Microsoft Office (Excel/PowerPoint) attachments and OneDrive-hosted decoys. Opening the Office file and enabling a VBA macro drops and executes a GHOLE backdoor DLL (a… | [source](https://documents.trendmicro.com/assets/wp/wp-operation-woolen-goldfish.pdf) |
| The Spy Kittens Are Back (Rocket Kitten 2) | May to September 2015 | Continued Middle East espionage. New TSPY_WOOLERG keylogger variants (debug strings 'D:\Yaser Logers\...') add a basic encryption layer over the previously plaintext hard-coded FTP credentials and exfiltrate keystroke logs via FTP to… | [source](https://documents.trendmicro.com/assets/wp/wp-the-spy-kittens-are-back.pdf) |
| Thamar Reservoir | 2014 to 2015 (activity as recent as Oct 2015) | ClearSky-tracked campaign (named for target Thamar E. Gindin) using coordinated spear-phishing, fake-login credential-harvesting pages spoofing webmail/portal logins, and phone/email social-engineering with tailored fake identities… | [source](https://www.clearskysec.com/thamar-reservoir/) |
| Rocket Kitten: A Campaign With 9 Lives (operational database exposure) | 2015 (activity through Oct 2015) | Check Point/ClearSky obtained the group's target-management database, revealing ~1,600 targets: scholars, scientists, CEOs, ministry officials, education institutes, media/journalists and human-rights activists across the Middle East,… | [source](https://blog.checkpoint.com/research/rocket-kitten-a-campaign-with-9-lives/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**34 techniques** across 11 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 20 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 14 hunt-lane techniques
- [`iocs/`](iocs/) — **67 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **34** across 11 tactics
- Lane split: **20 detection / 14 hunt**
- IOCs: **67**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
