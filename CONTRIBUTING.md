# Contributing an actor pack

Thanks for helping MENA defenders. Contributions follow the same pipeline the maintained packs use, so quality and provenance stay consistent.

## What makes a good pack

1. **The actor has documented MENA targeting** with a real public source (vendor report, government advisory, or reputable journalism). If it isn't sourced, it doesn't ship.
2. **Every detection traces to a TTP, and every TTP traces to a source.** No orphan rules.
3. **Detectable behaviors become Sigma; the rest become hunts.** Don't force a fragile rule where a hunt is the honest answer.

## Steps

1. Copy `templates/actor-pack-template/` to `actors/<actor-slug>/`.
2. **Stage 1 — intel.** Fill `intel/cti-pipeline.json`: actor metadata, `ttps[]` (technique_id, tactic, procedure, observed_tooling, `detection_feasibility`, sources), `iocs[]` (publicly sourced only). Map techniques to [ATT&CK](https://attack.mitre.org/).
3. **Stage 2 — routing.** For each TTP decide **detection** vs **hunt** based on *feasibility*, not severity. Record it in `intel/routing.json`. (If you drive this with the read-only `decision-agent`, note it cannot write files — capture its output and persist `routing.json` yourself.)
4. **Stage 3a — detections.** Write one Sigma rule per detectable TTP in `detections/`. Follow the [Sigma spec](https://github.com/SigmaHQ/sigma-specification). Required fields: `title`, `id` (UUID), `status`, `description`, `references`, `author`, `date`, `tags` (incl. `attack.tXXXX`), `logsource`, `detection`, `falsepositives`, `level`.
5. **Stage 3b — hunts.** Write one hunt per hunt-routed TTP in `hunts/` using the template: hypothesis, ATT&CK ref, data sources, query starting point, triage / expected FP.
6. **Regenerate** `ttps.md` and `navigator-layer.json`.
7. Update the coverage table in the root `README.md`.

## Quality bar for Sigma

- Validates against `sigma-cli` (`sigma check`) — CI runs this on every PR.
- Has realistic `falsepositives`.
- `level` reflects fidelity, not how scary the actor is.
- Prefer behavior-based logic (command-line, parent/child, LOLBAS) over brittle IOCs; put atomic IOCs in `iocs/` instead.

## Provenance

Note in the pack README how the content was produced (which pipeline stages / analysts / sources). Auditable derivation is a feature of this project, not an afterthought.
