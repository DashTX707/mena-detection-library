# Hunt: OilRig capability development, tooling & certificate acquisition (downstream-use tracking)

- **Hypothesis:** OilRig's off-victim capability work — developing custom downloaders, obtaining public tools (Plink/Mimikatz), acquiring code-signing certificates, and tuning malware to evade AV — is not directly observable, but its *downstream use* leaves traces: freshly-compiled/low-prevalence downloaders, LOLBin-tunnel/credential tooling, and signed-but-anomalous binaries appearing on hosts. This is an intel-led hunt that tracks the adversary's toolchain by its footprint on our estate and in threat intel.
- **ATT&CK:**
  - T1587.001 — Develop Capabilities: Malware (resource-development)
  - T1588.002 — Obtain Capabilities: Tool (resource-development)
  - T1588.003 — Obtain Capabilities: Code Signing Certificates (resource-development)
  - T1027.005 — Obfuscated Files or Information: Indicator Removal from Tools (defense-evasion)
- **Actor procedure:** OilRig **actively developed a series of custom downloaders** (ODAgent, OilCheck, OilBooster, SampleCheck5000 during 2022's Juicy Mix), **uses publicly available tools including Plink and Mimikatz**, **obtains stolen code-signing certificates to sign malware**, and **tests samples against AV and modifies them** to strip detectable indicators before deployment.
- **Why a hunt, not a rule:** development, tool acquisition, cert theft and AV-evasion tuning all happen on adversary infrastructure — none is endpoint-observable at the moment it occurs. The hunt is enrichment: correlate our low-prevalence-binary and signer telemetry with external intel on OilRig tooling/certificates and low-detection samples, and watch for the *downstream* execution of acquired tools. Analyst judgement, not alerting.

## Data sources required

- EDR binary-prevalence / first-seen telemetry (rare hashes, first-seen-in-org executables, compile timestamps)
- Sysmon EID 1/7 (Image, Hashes, Signature, signer thumbprint) for tool execution and signed-binary loads
- CTI platform: OilRig malware family hashes, known-abused code-signing thumbprints, low-AV-detection sample feeds
- Multi-AV / sandbox verdict telemetry (samples with suspiciously low detection ratios)

## Query starting point

Platform: `KQL/Sentinel`

```
DeviceProcessEvents
| where Timestamp > ago(30d)
| summarize hosts=dcount(DeviceId), first=min(Timestamp), signers=make_set(tostring(parse_json(AdditionalFields).Signer))
    by SHA256, FileName
| where hosts <= 3                                  // low-prevalence, rare in the estate
| join kind=leftouter (
    ThreatIntelligenceIndicator
    | where isnotempty(FileHashValue)
    | project SHA256 = FileHashValue, ti_desc = Description
  ) on SHA256
| extend known_tool = FileName has_any ("plink","adobe.exe","mimikatz","lazagne","ngrok")
| where isnotempty(ti_desc) or known_tool
| project first, FileName, SHA256, hosts, signers, ti_desc
| order by first asc
```

## Triage guidance

- **Likely malicious:** a low-prevalence binary matching OilRig downloader-family intel (ODAgent/OilBooster/etc.) or a known-abused signer thumbprint; Plink/Mimikatz/LaZagne/ngrok execution (or renamed copies) on hosts with no admin justification; a binary with a suspiciously low multi-AV detection ratio and a very recent compile timestamp.
- **Likely benign / expected:** in-house or vendor tools that are legitimately rare in the estate; sanctioned use of Plink/PuTTY/ngrok by network engineers (enumerate and allowlist); newly-deployed signed software from known publishers.
- **Pivot next:** any hit → downstream-use hunts (HUNT-01 tunneling, HUNT-07 masquerading/signing, detection-lane credential dumping); confirmed OilRig-family hash or stolen cert → hand to detection-engineering as an IOC block and to intel for infrastructure tracking (HUNT-02).

## References

- https://attack.mitre.org/groups/G0049/
- https://www.trendmicro.com/en_us/research/24/j/earth-simnavaz-cyberattacks.html
