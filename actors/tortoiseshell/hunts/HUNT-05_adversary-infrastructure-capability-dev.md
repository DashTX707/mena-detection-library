# Hunt: Tortoiseshell adversary infrastructure & capability development (intel-led external hunt)

- **Hypothesis:** If Tortoiseshell is preparing or running an operation against us, then the off-victim scaffolding will be observable in external telemetry *before or during* endpoint impact — newly-registered lookalike domains, attacker web services staging malicious installers on fake recruiting/job sites, and custom-implant tradecraft (Backdoor.Syskit / IMAPLoader) or acquired public tools (ProcDump, NSSM, PAExec, Mimikatz) whose known artifacts can be pre-positioned in hunts. The evidence stacks a never-before-seen anomaly (domain/host registered days ago) with a masquerading anomaly (brand/sector lookalike naming) and a property-mismatch anomaly (staged binary whose signing/build metadata matches known Tortoiseshell tooling rather than the impersonated brand).
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development)
  - T1583.006 — Acquire Infrastructure: Web Services (resource-development)
  - T1587.001 — Develop Capabilities: Malware (resource-development)
  - T1588.002 — Obtain Capabilities: Tool (resource-development)
  - T1608.001 — Stage Capabilities: Upload Malware (resource-development)

- **Actor procedure:** Tortoiseshell / Imperial Kitten registers domains and stands up web services for fake recruiting sites, persona infrastructure, watering-hole exfil endpoints and C2; develops custom malware (Backdoor.Syskit in Delphi and .NET; the .NET IMAPLoader); obtains and repurposes public tooling (ProcDump, NSSM, PAExec/PsExec, Mimikatz); and hosts weaponized installers/payloads on fake job-application websites staged for targeted delivery. All of this is off the victim endpoint, so it is an intel-led external hunt whose product is pre-positioned indicators and hunt inputs for the endpoint hunts (HUNT-01/02/04).
- **Why a hunt, not a rule:** None of this is endpoint-observable — there is nothing in victim telemetry to alert on, so a rule cannot be written here at all. The value is proactive external discovery: enumerating lookalike domains, watching certificate-transparency and passive-DNS for staging hosts, and pre-loading known tool/implant artifacts into the endpoint hunts. This is investigative, intel-fusion work requiring analyst judgement over noisy registration/hosting data → hunt. Findings feed forward: a confirmed staging domain or implant hash becomes a Level-1/2 pivot (not a durable detection base) handed into HUNT-01/02/04 and the detection pack's IOC set.

## Data sources required

- Certificate Transparency logs + passive DNS + WHOIS/registration feeds (newly-registered / lookalike domains for target brands and sectors)
- Domain/brand-monitoring and typosquat services (recruiting/careers/maritime/logistics lures)
- Malware-repository / sandbox intel (VirusTotal, Hybrid-Analysis) pivoting on Backdoor.Syskit / IMAPLoader hashes and imphash/build metadata
- Public tool baselines (ProcDump/NSSM/PAExec/Mimikatz hashes, signer, default artifacts) for endpoint-hunt seeding
- Internal proxy/DNS logs — to check whether any enumerated adversary domain has already been contacted (crossover into endpoint reality)

## Query starting point

Platform: `Threat-intel workflow + internal DNS crossover (KQL / Sentinel)` — check whether externally-enumerated infra was touched internally

```kusto
// externally enumerated Tortoiseshell staging/lookalike domains + known tool/implant hashes,
// curated from CT logs, passive DNS, WHOIS and malware-repo pivots on Syskit/IMAPLoader.
let adversaryDomains = dynamic([
    "example-careers-lookalike[.]com","maritime-jobs-staging[.]net"]);   // ← intel-curated
let adversaryHashes = dynamic([
    "f71732f997c53fa45eef5c988697eb4aa62c8655d8f0be3268636fc23addd193",  // Symantec-reported
    "02a3296238a3d127a2e517f4949d31914c15d96726fb4902322c065153b364b2",
    "07d123364d8d04e3fe0bfa4e0e23ddc7050ef039602ecd72baed70e6553c3ae4",
    "d9ac9c950e5495c9005b04843a40f01fa49d5fd49226cb5b03a055232ffc36f3"]);
union
 (DeviceNetworkEvents | where TimeGenerated > ago(30d)
    | extend dom = tostring(parse_url(RemoteUrl).Host)
    | where dom in (adversaryDomains) | project TimeGenerated, DeviceName, kind="domain-contact", ioc=dom),
 (DeviceFileEvents | where TimeGenerated > ago(30d)
    | where SHA256 in (adversaryHashes) | project TimeGenerated, DeviceName, kind="known-hash", ioc=SHA256)
| order by TimeGenerated asc
// Any hit = the external scaffolding has touched reality → pivot immediately to HUNT-01/02/04 on that host.
```

Platform: `External enumeration (analyst method, no SIEM)` — lookalike/staging discovery

```text
1. CT logs (crt.sh / Censys): certificates issued in last 90d for <brand>/careers/apply/maritime/logistics
   permutations; note registrar, hosting ASN, first-seen.
2. Passive DNS: resolve each candidate; cluster by shared IP/ASN/NS with the Symantec C2 IPs
   64.235.60.123 / 64.235.39.45 and any IMAPLoader mailbox infra from CrowdStrike/PwC reports.
3. Malware repos: pivot on Syskit/IMAPLoader hashes → imphash, PDB path, signer → surface siblings.
4. Feed confirmed domains/hashes into the adversaryDomains/adversaryHashes lists above and the detection-pack IOC set.
```

## Triage guidance

- **Likely malicious:** a freshly-registered domain imitating your brand/sector on a registrar/ASN clustering with known Tortoiseshell infra; a staging host serving a "job application" installer whose build/signing metadata or imphash matches Syskit/IMAPLoader; any internal DNS/proxy hit on an enumerated staging domain, or any endpoint hash matching the reported Syskit hashes — the external and internal worlds have connected.
- **Likely benign / expected:** the vast majority of newly-registered domains and public-tool downloads are unrelated; ProcDump/NSSM/PsExec have heavy legitimate admin use, so their mere presence in a repo or on a host is not this actor — only the *combination* with target-specific lures or clustering with known infra matters. Treat isolated registrations as watch-list, not findings.
- **Pivot next:** submit confirmed lookalike/staging domains for takedown and add them plus any implant hashes to the endpoint hunts (HUNT-01/02/04) and detection-pack IOCs; if an internal crossover hit fires, the operation is live in your estate → pivot that host through the endpoint hunts and escalate to IR. Park unconfirmed-but-suspicious registrations as unsolved mysteries for the next hunt cycle.

## References

- https://www.security.com/threat-intelligence/tortoiseshell-apt-supply-chain
- https://www.crowdstrike.com/en-us/adversaries/imperial-kitten/
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1583/006/
- https://attack.mitre.org/techniques/T1587/001/
- https://attack.mitre.org/techniques/T1588/002/
- https://attack.mitre.org/techniques/T1608/001/
