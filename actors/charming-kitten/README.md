# Charming Kitten (APT35 / Magic Hound, G0059) — Detection & Hunt Pack

> **Attribution:** Iran-nexus, assessed to the Islamic Revolutionary Guard Corps (IRGC) — **high confidence**
> **MENA targeting:** Israel, Gulf states, broader Middle East
> **Sectors:** Government, media, NGOs, academia, dissidents/activists/journalists
> **Aliases:** Magic Hound, APT35, TA453, Phosphorus, Mint Sandstorm, COBALT ILLUSION, ITG18, NewsBeef, Charming Kitten

## Summary

Charming Kitten is a long-running Iran-nexus (IRGC) actor defined by **credential harvesting through elaborate social engineering** rather than mass malware: convincing fake login pages, long-con impersonation personas (journalists, academics, think-tank staff), and multi-message rapport-building before a malicious link or attachment. Where it does deploy tooling it favors lightweight backdoors, PowerShell, and abuse of legitimate services. Its heavy reliance on phishing, valid-account abuse, and cloud/webmail access (including 2FA-phishing and mailbox rules) makes this pack lean on **identity, email, and authentication telemetry** for detection and on **impersonation-infrastructure and account-abuse hunts** for the tradecraft that lives outside endpoint logs.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| "Uncharmed" — APT42 operations | pub. May 2024 | Tooling/operations vs. Israeli military, defense, diplomats | [Google Cloud – Uncharmed: Untangling Iran's APT42](https://cloud.google.com/blog/topics/threat-intelligence/untangling-iran-apt42-operations) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes (note: vendors variously split APT35/Charming Kitten and APT42; this pack maps to MITRE G0059)._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**84 techniques** across 14 tactics — the library's most complete actor map)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (lane-colored)
- [`detections/`](detections/) — **26 Sigma rules** covering all 58 detection-lane techniques (aggressively merged), all validated clean
- [`hunts/`](hunts/) — **8 consolidated hunt hypotheses** covering the 26 hunt-lane techniques (impersonation-persona flagship)
- [`iocs/`](iocs/) — **30 publicly-sourced indicators** (19 domains + 11 MD5) plus the verbatim Mandiant NICECURL YARA rule in the intel
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **84** across 14 tactics (the widest kill-chain spread in the library — heavy Reconnaissance & Resource-Development)
- Lane split: **58 detection / 26 hunt** — the detectable seam is the **identity/email/cloud-log surface** (M365/Entra/Google): MFA fatigue, app-password abuse, session-cookie reuse, inbox/hiding rules, mailbox delegation, impossible travel
- Detections: **26 Sigma files** (merged from 58 techniques) · Hunts: **8** · IOCs: **30**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs enriched from MITRE G0059 + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> **Notes:** all 84 IDs verified against the CI's bundled ATT&CK dataset on the first pass (Impair-Defenses family uses this env's `T1685`/`T1685.001`/`T1686.003` under the `defense-impairment` tactic; defense-evasion tagged `attack.stealth`). The 58 detection techniques are consolidated into 26 multi-tag rules — the identity-log rules (rules 2–6: MFA, sign-in, mailbox) are the durable, evasion-resistant core; domain/hash IOCs are treated as fast-decaying supplements.
