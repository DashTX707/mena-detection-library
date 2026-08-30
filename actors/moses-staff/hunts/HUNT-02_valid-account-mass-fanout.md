# Hunt: Moses Staff / valid-account credential-reuse mass fan-out (PyDCrypt spread precursor)

- **Hypothesis:** If Moses Staff has harvested domain-administrator credentials and is about to spread DCSrv, then we should observe a single privileged account authenticating to an abnormally large number of hosts in a short window — many more than it touches on a normal day — with those logons (Type 3 network / Type 2 or 10 where PsExec/WMIC land) immediately followed by service-creation (7045) or remote process-create events on the same destination hosts. The hunt keys on the *unexpected relationship* between one account and a fan-out set of hosts it has never collectively touched, paired with the service-install tail that distinguishes malicious deployment from routine admin sweeps.
- **ATT&CK:**
  - T1078 — Valid Accounts (lateral-movement) — credential reuse for mass payload deployment

- **Actor procedure:** Per Check Point, PyDCrypt collects domain and machine names plus administrator credentials during the earlier intrusion stages, then reuses those legitimate admin credentials to authenticate to and push the DCSrv payload across the network via PsExec, WMIC and PowerShell. Because the credentials are valid, each individual logon looks normal — the abnormality is only visible in the *shape*: one account, many destinations, compressed in time, each destination gaining a new service moments later.
- **Why a hunt, not a rule:** Valid-account logons are the single noisiest authentication signal in any enterprise; admins legitimately touch many hosts, and vulnerability scanners, patch tools and monitoring service accounts fan out by design. A raw "account authenticated to N hosts" rule drowns in that base rate. What makes this huntable rather than alertable is the *deviation from each account's own baseline* combined with the service-creation tail and the compressed timing — a per-account behavioral model that needs analyst tuning, not a static threshold. If a specific enclave has a stable, small admin-to-host baseline, the deviation-plus-service-install correlation can be handed to detection-engineering as a scoped alert.

## Data sources required

- Windows Security 4624 (logon, with LogonType, TargetUserName, source host) + 4648 (explicit-credential logon)
- Windows Security 4672 (special privileges assigned) — admin-context logons
- Windows System 7045 / Security 4697 (service install) on the destination hosts
- Per-account historical baseline of distinct destination hosts per day (28-60d)
- Domain Controller authentication logs (Kerberos TGS 4769 for destination-host coverage)

## Query starting point

Platform: `KQL / Microsoft Sentinel` — single account fan-out vs its own baseline, joined to downstream service installs

```kusto
let lookback = 14d;
let baseline = SecurityEvent
    | where TimeGenerated between (ago(60d)..ago(lookback))
    | where EventID == 4624 and LogonType in (2,3,10)
    | summarize base_hosts = dcountif(Computer, true) by Account
    | project Account, base_hosts;
let fanout = SecurityEvent
    | where TimeGenerated > ago(lookback)
    | where EventID == 4624 and LogonType in (2,3,10)
    | summarize win_hosts = dcount(Computer), hostset = make_set(Computer, 40),
                firstSeen = min(TimeGenerated), lastSeen = max(TimeGenerated)
              by Account, bin(TimeGenerated, 1h)          // 1-hour burst window
    | where win_hosts >= 10;                              // tune per enclave
fanout
| join kind=leftouter baseline on Account
| extend ratio = todouble(win_hosts) / todouble(max_of(base_hosts, 1))
| where ratio >= 3.0 or isempty(base_hosts)              // >=3x own baseline, or brand-new spread
// tail: destination hosts gaining a new service within ~30 min of the logon burst
| join kind=inner (
    SecurityEvent | where TimeGenerated > ago(lookback) and EventID in (7045,4697)
    | project SvcTime = TimeGenerated, Computer, ServiceName = Service
  ) on $left.Account == $right.Account
| order by ratio desc
```

## Triage guidance

- **Likely malicious:** one domain-admin account authenticating to 10+ hosts it has never collectively touched, compressed into minutes, each destination gaining a new service (especially DCUMSrv/DCDrv/PSEXESVC or random-named) shortly after; the account's source host is a web server / non-admin workstation rather than a jump box; the fan-out set overlaps the destructive precursors from HUNT-01.
- **Likely benign / expected:** sanctioned patch/config-management service accounts (SCCM, Ansible, Tanium), vulnerability scanners, and admin jump-box sweeps fan out to many hosts by design and on a stable cadence — baseline and allowlist those accounts and their known service names. A known tooling account hitting its usual host set is expected; a *human* admin account suddenly spraying from an unusual source is not.
- **Pivot next:** confirm which credential was used and whether it maps to a real admin; pivot to the source host to find the credential-theft/web-shell origin, and downstream to the destination service installs (→ HUNT-01 destructive precursors). If the fan-out is delivering an unknown service to many hosts, treat as active pre-detonation spread → escalate to incident-response-coordinator and force-reset the implicated credential.

## References

- https://research.checkpoint.com/2021/mosesstaff-targeting-israeli-companies/
- https://attack.mitre.org/techniques/T1078/
- https://www.cybereason.com/blog/research/strifewater-rat-iranian-apt-moses-staff-adds-new-trojan-to-ransomware-operations
