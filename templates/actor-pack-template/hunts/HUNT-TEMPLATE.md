# Hunt: <short title>

- **Hypothesis:** <If actor uses technique X, then we should observe Y in Z telemetry.>
- **ATT&CK:** <TXXXX.XXX — Name> (<tactic>)
- **Actor procedure:** <what the actor specifically does, from reporting + source>
- **Why a hunt, not a rule:** <why this isn't a reliable alert — high base rate, needs baselining, context-dependent>

## Data sources required

- <e.g. Sysmon EID 1/3/11, Windows Security 4688, PowerShell 4104, proxy logs, EDR process/network telemetry>

## Query starting point

Platform: `<Splunk SPL | KQL/Sentinel | Elastic EQL | osquery>`

```
<query>
```

## Triage guidance

- **Likely malicious:** <indicators that raise suspicion>
- **Likely benign / expected:** <normal activity that matches>
- **Pivot next:** <what to look at if a hit is found>

## References

- <source URL(s)>
