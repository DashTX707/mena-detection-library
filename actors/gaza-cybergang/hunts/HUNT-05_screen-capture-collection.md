# Hunt: Gaza Cybergang desktop screen capture (SharpStage / Pierogi espionage collection)

- **Hypothesis:** If a SharpStage or Pierogi backdoor is collecting on a host, then endpoint telemetry will show a *non-interactive, backdoor-lineage* process (a .NET binary in `%AppData%`, a PyInstaller `_MEI` process, or a scheduled-task-launched executable) invoking screen-capture APIs on a recurring cadence and writing image files (`.jpg`/`.png`/`.bmp`) into a staging folder, without any foreground screenshot/screen-share application in the user's session.
- **ATT&CK:**
  - T1113 — Screen Capture (collection) — SharpStage and Pierogi capture screenshots of the victim's desktop for espionage
- **Actor procedure:** SharpStage and the Pierogi backdoor periodically grab screenshots of the victim's desktop and stage them for exfiltration to the cloud C2 (Operation Bearded Barbie / cloud-arsenal campaigns). The capture runs headless from the implant, not from a user opening the Snipping Tool.
- **Why a hunt, not a rule:** the Win32 capture path (`BitBlt`/`GetDC`/`CopyFromScreen`/`PrintWindow`) is used constantly by legitimate software — remote-support, conferencing, screenshot utilities, DLP and even the OS — so the API call alone is not alertable and often leaves little discrete log signal. The value is behavioral: a process with *no visible window and backdoor lineage* capturing on a timer and dropping a growing set of images into one folder, judged against a baseline of which processes legitimately capture on that host role. That is correlation and baselining, not a fixed rule.

## Data sources required

- EDR API/behavioral telemetry (screen-capture API invocation with owning process and window state) — the primary source
- Sysmon EID 11 (image files written to a staging dir by a non-graphics process) and EID 1 (process lineage)
- Sysmon EID 7 (image loads of `gdi32.dll`/`user32.dll` by an otherwise console/service process — weak corroborator)
- Host inventory of sanctioned screenshot/conferencing/remote-support tools (the allowlist)

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint source=*Sysmon* EventCode=11
| eval f=lower(TargetFilename), creator=lower(Image)
| where match(f,"\.(jpg|jpeg|png|bmp|gif)$")
| where match(f,"(appdata|\\\\temp\\\\|\\\\programdata\\\\|\\\\_mei)")
| where NOT match(creator,"\\\\(chrome|msedge|firefox|snippingtool|screenclippinghost|teams|zoom|slack|onedrive|explorer)\.exe$")
| bin _time span=10m
| stats count dc(f) as images values(creator) as creators values(f) as sample_files by _time, host, User
| where count >= 5
| sort - count
```

## Triage guidance

- **Likely malicious:** a process with no interactive window, running from `%AppData%`/`%TEMP%`/`_MEI` or launched by a scheduled task, writing a steady stream of timestamped images into one staging folder on a timer; the same process later seen calling a cloud-storage/social API (join to HUNT-01); capture activity on a targeted-role host (diplomat, journalist, official) outside working hours.
- **Likely benign / expected:** conferencing/screen-share, remote-support tools, DLP screenshotting, and user-driven screenshot utilities. Baseline and allowlist these by process + signer + host role.
- **Pivot next:** confirm the owning process and lineage in EDR; look for the staged images leaving over cloud C2/exfil (HUNT-01); correlate with the discovery burst (HUNT-02) and screen-capture-adjacent collection. Recurring headless capture staged for cloud upload is a live espionage compromise — escalate to incident-response-coordinator.

## References

- https://attack.mitre.org/software/S0546/
- https://www.cybereason.com/blog/operation-bearded-barbie-apt-c-23-campaign-targeting-israeli-officials
- https://attack.mitre.org/groups/G0021/
