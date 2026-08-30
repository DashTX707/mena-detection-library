# Hunt: Tortoiseshell IT-provider supply-chain compromise — unexpected provider-pushed binaries

- **Hypothesis:** If a trusted IT/managed-service provider that reaches our environment has been compromised (the defining Tortoiseshell tradecraft), then the provider's legitimate software-distribution / remote-management channel will push a binary or script that is *unexpected* — a never-before-seen executable, an off-schedule deployment, or a payload whose name/path/signature does not match that provider's normal catalog — landing on endpoints via the RMM/patch agent rather than user action. The evidence stacks a never-before-seen anomaly (a binary the provider has never distributed before) with a path/property mismatch (unsigned or mismatched-publisher payload dropped by a signed RMM agent) and a timing anomaly (deployment outside the provider's normal maintenance window).
- **ATT&CK:**
  - T1195 — Supply Chain Compromise (initial-access)
  - T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain (initial-access)

- **Actor procedure:** Tortoiseshell compromised at least 11 organisations — the majority IT/managed-service providers in Saudi Arabia — to use their trusted access as a stepping stone to downstream customers. Once inside a provider, they abused its software/administration and distribution channels to deliver malware (Backdoor.Syskit and info-gathering tools) into customer estates, reaching several hundred hosts in some environments. From a downstream victim's seat the malware arrives through a channel the environment already trusts, so the tell is *what* the trusted channel delivered, not that it delivered anything.
- **Why a hunt, not a rule:** RMM and patch agents legitimately push new binaries constantly; alerting on "provider agent wrote a new EXE" would fire on every genuine deployment. The upstream compromise is invisible from the victim endpoint, so the only observable is a deviation in the *content and cadence* of provider-pushed software — which requires knowing that provider's normal catalog, publisher certs, and maintenance windows, a per-relationship baseline that is judgement-heavy. That is a hunt. A durable finding (RMM agent dropping an unsigned/mismatched-publisher binary outside the maintenance window — Summiting Level 3–4, parent-process + signing property) can be handed to detection-engineering once each provider's baseline is codified.

## Data sources required

- EDR/Sysmon EID 1 (process create) + EID 11 (file create) — filter to children/writes of known RMM/patch agents (e.g. the provider's agent, `ScreenConnect`, `AnyDesk`, `TacticalRMM`, WSUS/SCCM clients)
- Code-signing metadata on dropped binaries (publisher, thumbprint, signed vs unsigned)
- Provider remote-management logon telemetry (Security 4624/4648 for provider service accounts; VPN/jump-host logs)
- Software-deployment inventory / change-management records to establish the "normal catalog" and maintenance windows

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — RMM/provider agent dropping a never-before-seen or unsigned binary, fanning across hosts

```kusto
let rmmAgents = dynamic(["screenconnect.clientservice.exe","tacticalrmm.exe","anydesk.exe",
    "ccmexec.exe","wuauclt.exe","provider_agent.exe"]);   // ← replace with YOUR providers' agents
let baseline = DeviceFileEvents
    | where TimeGenerated between (ago(60d)..ago(2d))
    | where tolower(InitiatingProcessFileName) in (rmmAgents)
    | summarize by SHA256;
DeviceFileEvents
| where TimeGenerated > ago(14d)
| where tolower(InitiatingProcessFileName) in (rmmAgents)
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1"
| where SHA256 !in (baseline)                              // never-before-pushed payload
| summarize hosts = dcount(DeviceName), hostset = make_set(DeviceName, 30),
            first = min(TimeGenerated), paths = make_set(FolderPath, 10)
        by InitiatingProcessFileName, FileName, SHA256
| where hosts >= 3                                          // fan-out via the trusted channel
| order by hosts desc
// Pivot: join SHA256 to DeviceFileCertificateInfo — unsigned or publisher != provider = strong signal
// Pivot: was `first` outside the provider's documented maintenance window?
```

Platform: `SPL / Splunk` — provider account pushing off-catalog software off-hours

```spl
index=edr sourcetype=sysmon EventCode IN (1,11)
| eval agent=lower(parent_process_name)
| search agent IN ("screenconnect.clientservice.exe","tacticalrmm.exe","ccmexec.exe","provider_agent.exe")
| stats dc(host) as hosts values(host) as hostset min(_time) as first
        values(file_path) as paths by agent,file_name,sha256,signature,signature_verified
| where hosts>=3 AND (signature_verified!="Signed" OR signature!="<ExpectedProviderPublisher>")
| eval hour=strftime(first,"%H") | where hour<6 OR hour>20   `# outside maintenance window`
| sort - hosts
```

## Triage guidance

- **Likely malicious:** the provider's RMM/patch agent dropping a never-before-distributed, unsigned or mismatched-publisher binary/script to many hosts at once, outside the documented maintenance window; a payload landing in a temp/user-writable path rather than the agent's normal install location; the drop immediately followed by service creation (NSSM/`sc`), scheduled tasks, or `mshta` (pivot to detection pack); provider service-account logons from an unusual source IP/geo preceding the push.
- **Likely benign / expected:** genuine patch cycles, agent self-updates, and catalogued software rollouts — reconcile every hit against change-management tickets and the provider's known publisher certs and cadence; a signed, catalogued binary pushed in-window is expected. New software after an approved change request is not this actor.
- **Pivot next:** validate the deployment with the provider out-of-band (do not trust the same channel), hash-reputation the payload, and pivot to whether affected hosts show follow-on Tortoiseshell behavior (Syskit registry keys `Enablevmd`/`Sendvmd`, LSASS dump, PsExec fan-out — detection pack). A confirmed malicious provider-pushed binary is a supply-chain incident affecting potentially the whole estate → escalate to incident-response-coordinator immediately and notify the provider.

## References

- https://www.security.com/threat-intelligence/tortoiseshell-apt-supply-chain
- https://attack.mitre.org/techniques/T1195/
- https://attack.mitre.org/techniques/T1195/002/
