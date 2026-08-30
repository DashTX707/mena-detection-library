# Hunt: Web-shell-parented network configuration discovery (ping connectivity checks)

- **Hypothesis:** If Void Manticore has an operational web shell on one of our servers, then before moving deeper it runs quick **connectivity/reachability checks** — `ping.exe` to an external resolver (`4.2.2.4`) and `microsoft.com` — to confirm the compromised host's outbound reachability and orient in the environment. `ping` is ubiquitous and meaningless on its own, so the hunt keys on the **unexpected relationship**: `ping.exe` (and other discovery utilities) whose **parent process is a web-server worker** (`w3wp.exe`, `httpd.exe`) or `cmd.exe /c` spawned by one — a web application has no legitimate reason to shell out to `ping`.
- **ATT&CK:**
  - T1016 — System Network Configuration Discovery (discovery) — `ping` to `4.2.2.4` / `microsoft.com` via Karma Shell to confirm outbound connectivity and environment

- **Actor procedure:** Through the Karma Shell, Void Manticore issued `cmd.exe /c` connectivity checks — `ping` against the external resolver `4.2.2.4` and `microsoft.com` — to verify the compromised host could reach the internet and to fingerprint the environment before staging tooling and moving laterally.
- **Why a hunt, not a rule:** `ping.exe` executes thousands of times a day across an enterprise for entirely legitimate reasons (monitoring, scripts, admin troubleshooting), so a rule on `ping` — even to a specific target — is pure noise. The malicious discriminator is the *process lineage*: the parent being a web-worker process. That lineage pivot is a strong, low-base-rate signal, but it needs to be scoped against the small set of apps that legitimately shell out (health-check scripts, monitoring agents) — that scoping is a baselining/judgement task → hunt. The durable core: **a web-worker process (or its `cmd.exe` child) spawning `ping`/`net`/`ipconfig`/`nslookup`** (Summiting Level-4 relationship observable — the adversary using a web shell to run recon *must* create this parent-child edge) is a candidate to hand to detection-engineering once the legitimate-app allowlist is built; here it also overlaps with the detection pack's web-shell-command-execution coverage (T1059.003).

## Data sources required

- Sysmon EID 1 / Windows Security 4688 (process create with ParentImage + full command line)
- Web-worker process inventory (`w3wp.exe`, `httpd.exe`, `php-cgi.exe`, `tomcat.exe`, `java.exe` under app-pool identities) — to define the "web parent" set
- Baseline of applications/scripts that legitimately spawn shells/network tools from web context (allowlist)
- Egress/DNS logs (secondary) — to corroborate the outbound checks to `4.2.2.4` / `microsoft.com`

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — network-discovery utilities parented by a web-worker process

```kusto
let webParents = dynamic(["w3wp.exe","httpd.exe","php-cgi.exe","tomcat.exe","java.exe","nginx.exe"]);
let reconTools = dynamic(["ping.exe","net.exe","net1.exe","ipconfig.exe","nslookup.exe","whoami.exe","arp.exe","tracert.exe"]);
DeviceProcessEvents
| where TimeGenerated > ago(21d)
| where FileName in~ (reconTools)
| where InitiatingProcessFileName in~ (webParents)
     or (InitiatingProcessFileName =~ "cmd.exe"
         and InitiatingProcessParentFileName in~ (webParents))   // cmd.exe /c wrapper
// scope out known-good apps that legitimately shell out from web context
| where InitiatingProcessAccountName !in~ ("svc_healthcheck")     // suppress baselined monitoring identity
| extend voidPing = ProcessCommandLine has_any ("4.2.2.4","microsoft.com")  // actor-specific pivot, not the filter
| project TimeGenerated, DeviceName, InitiatingProcessAccountName,
          ParentChain = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName, " > ", FileName),
          ProcessCommandLine, voidPing
| order by TimeGenerated asc
```

## Triage guidance

- **Likely malicious:** `ping.exe` (or `net`/`ipconfig`/`nslookup`/`whoami`) whose parent is `w3wp.exe`/`httpd.exe`, or a `cmd.exe /c` recon one-liner spawned by a web worker — especially `ping 4.2.2.4` / `ping microsoft.com` on an internet-facing server, clustered with other discovery, web-shell file drops (HUNT-03), or `do.exe`/WinRAR staging. A web application shelling out to network-recon tools is not normal behavior.
- **Likely benign / expected:** application health-checks and monitoring agents that legitimately invoke `ping`/`nslookup` from an app context on a known cadence and identity (baseline and suppress these — note the suppression, e.g. `svc_healthcheck`); admin troubleshooting from an interactive session (parent is a real shell/console, not a web worker). A single recon tool under a baselined health-check identity is expected.
- **Pivot next:** confirmed web-worker-parented recon → treat the host's web shell as live; pivot to HUNT-03 (identify the shell file), HUNT-01 (handoff/DA use + destruction), and the tunnel/lateral-movement detection coverage. Hand the web-parent→recon lineage to detection-engineering once the app allowlist is set. Web-shell-driven discovery on an internet-facing server is active intrusion → escalate to IR.

## References

- https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/
- https://blog.checkpoint.com/research/unveiling-void-manticore-structured-collaboration-between-espionage-and-destruction-in-mois/
- https://attack.mitre.org/techniques/T1016/
