# Hunt: Gaza Cybergang victim-gating & sandbox evasion (Arabic-language check + user-activity checks)

- **Hypothesis:** If a Gaza Cybergang payload (Spark, DropBook, SharpStage, NimbleMamba) executed but the host was not an intended Arabic-language target — or was an analysis sandbox — then the sample will have run a keyboard-layout/locale check and/or a user-activity check and *exited without follow-on*, so the delta between hosts that show the check-then-nothing and hosts that show the check-then-payload is itself the signal; the gating logic is best surfaced by static/sandbox analysis of collected samples rather than host logs.
- **ATT&CK:**
  - T1614.001 — System Location Discovery: System Language Discovery (discovery) — Spark/DropBook/SharpStage/NimbleMamba gate execution to Arabic-language systems
  - T1497.002 — Virtualization/Sandbox Evasion: User Activity Based Checks (defense-evasion) — Spark performs anti-analysis/user-activity checks before executing
- **Actor procedure:** A *signature* Gaza Cybergang victim-gating behavior: Spark, DropBook and SharpStage check the system keyboard/language settings and run only on Arabic-language systems; NimbleMamba similarly geofences delivery. Spark additionally performs user-activity/anti-analysis checks so it does not detonate in automated sandboxes. This keeps the malware dark on Western analyst machines and evades detonation coverage.
- **Why a hunt, not a rule:** a single `GetKeyboardLayout`/`GetLocaleInfo`/`GetUserDefaultUILanguage` call or a mouse/idle-time check is near-invisible in host logs and has a massive benign base rate (every localized app does it) — there is nothing reliable to alert on at the endpoint. The value is in (a) static/sandbox analysis of collected Gaza Cybergang samples to confirm the gate, and (b) *comparing detonation outcomes*: the same lure that ran inertly in the sandbox now spawning a payload on a real Arabic-locale workstation is the finding. That is analyst comparison, not a threshold.

## Data sources required

- Mail-gateway / sandbox detonation output and Office VBA macro extraction (look for locale/keyboard-layout and mouse/idle/user-activity API calls)
- Sample static-analysis pipeline (import table: `GetKeyboardLayout`, `GetKeyboardLayoutList`, `GetLocaleInfo`, `GetUserDefaultUILanguage`, `GetSystemDefaultLangID`; `GetCursorPos`, `GetLastInputInfo`, `Sleep`-loops)
- Sysmon EID 1 / 4688 process lineage (to establish check-then-payload vs. check-then-exit)
- Host locale inventory (which endpoints are Arabic-locale — the intended-victim population)

## Query starting point

Platform: `Splunk SPL`

```
* Stage 1 — from sandbox/static analysis, list samples that queried locale/keyboard or user-activity APIs:
index=sandbox sourcetype=detonation
| eval apis=lower(api_calls)
| eval lang_gate=if(match(apis,"(getkeyboardlayout|getlocaleinfo|getuserdefaultuilanguage|getsystemdefaultlangid)"),1,0)
| eval activity_gate=if(match(apis,"(getcursorpos|getlastinputinfo)"),1,0)
| where lang_gate=1 OR activity_gate=1
| table sample_hash file_name lang_gate activity_gate verdict
```
```
* Stage 2 — did that same lure hash spawn a payload on a real (Arabic-locale) endpoint?
index=endpoint source=*Sysmon* EventCode=1 Hashes="*<sample_hash>*"
| lookup host_locale host OUTPUT locale
| stats values(Image) as children values(locale) as host_locale count by host, ParentImage
```

## Triage guidance

- **Likely malicious:** a delivered sample whose import table / sandbox trace shows a locale/keyboard check followed by early exit in the sandbox, that then executes fully on an Arabic-locale endpoint (the gate passed); mouse-present/idle-time checks bundled into an Office macro before a script-host handoff.
- **Likely benign / expected:** localized/regional software legitimately reading locale; anti-cheat/DRM idle checks. These are the noise the endpoint can't separate — which is exactly why this stays a sample-analysis hunt.
- **Pivot next:** confirm the gate statically, then treat every host in the intended-locale population that received the lure as in-scope for the discovery-burst (HUNT-02) and cloud-C2 (HUNT-01) hunts; feed the confirmed macro/interpreter lineage to detection-engineering. If a gated payload detonated on a real victim, escalate.

## References

- https://attack.mitre.org/software/S0543/
- https://attack.mitre.org/software/S0547/
- https://www.proofpoint.com/us/blog/threat-insight/nimblemamba-investigating-ta402-molerats-espionage-trojan
- https://unit42.paloaltonetworks.com/molerats-delivers-spark-backdoor/
