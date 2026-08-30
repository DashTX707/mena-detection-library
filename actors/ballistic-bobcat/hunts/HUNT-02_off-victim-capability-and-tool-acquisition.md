# Hunt: Ballistic Bobcat — off-victim capability development & tool acquisition (sample/YARA tracking)

- **Hypothesis:** If Ballistic Bobcat is actively iterating its toolset against targets in our region, then — because both the malware development (Sponsor v1-v5 / Alumina) and the dual-use tool acquisition happen *off* our victim network — the observable is not on our endpoints at all but in **sample space**: new Sponsor-family builds or the actor's characteristic staged-tool bundle (Mimikatz `mi.exe`, ProcDump `procdump64.exe`, WebBrowserPassView, Host2IP, SharpTShipper, SQLExtractor, Plink, RevSocks-as-`CSRSS.EXE`, GOST, Chisel) will surface in malware repositories, our sandbox detonation queue, or third-party sample feeds carrying the family's structural traits (Windows-service backdoor named SystemNetwork/Update, config.txt/node.txt/error.txt on-disk config triad, Base64+RC4 HTTP/80 C2 to the known infrastructure ranges). The finding is a *durable-trait* match — service-name + config-triad + C2-shape stacked together — not a single lookalike filename, and its value is early warning: a fresh Sponsor build seen in the wild before it lands on us.
- **ATT&CK:**
  - T1587.001 — Develop Capabilities: Malware (resource-development) — the actor develops and iterates the Sponsor backdoor across ≥5 versions; hunt tracks new builds by family traits and YARA rather than by hash.
  - T1588.002 — Obtain Capabilities: Tool (resource-development) — the actor operationalizes public/dual-use tools (Mimikatz, ProcDump, WebBrowserPassView, Host2IP, SharpTShipper, SQLExtractor, Plink, RevSocks, GOST, Chisel); hunt tracks acquisition of this specific bundle and its staging infrastructure.

- **Actor procedure:** ESET documents Ballistic Bobcat evolving the Sponsor backdoor across at least five versions (v1-v5, v5 aka Alumina), changing configuration handling, service naming (SystemNetwork → Update), and evasion between builds. In parallel the actor obtains and operationalizes a consistent bundle of publicly available offensive/dual-use tooling, staging it on dedicated delivery servers (5.255.97.172, 198.144.189.74) for download-and-execute onto victims. Both activities occur off-victim; the resulting binaries and delivery infrastructure are where visibility exists.
- **Why a hunt, not a rule:** Neither malware authorship nor tool acquisition touches our telemetry — there is nothing on our endpoints to alert on until a binary is already delivered, at which point the *downstream execution* is covered by the detection pack (T1105 downloader, T1090/T1572 tunneling, T1003.001 dumping, etc.). This hunt lives in sample-tracking and hunting-YARA space: authoring and running family-trait YARA over repositories and our own detonation queue to catch new Sponsor builds and the actor's tool bundle *early*, and to enrich attribution. That is intel/hunt work by design (low endpoint feasibility), and hunting-YARA is explicitly a hunting instrument here, not a production detection control — if a build yields a stable host-observable, route it to detection-engineering.

## Data sources required

- Malware sample feeds / repositories: VirusTotal Intelligence, MalwareBazaar, internal sandbox detonation queue and quarantine store (retro-hunt targets)
- Family-trait hunting-YARA over PE metadata, embedded strings (service names `SystemNetwork`/`Update`, config filenames `config.txt`/`node.txt`/`error.txt`, install/uninstall batch strings), and the Base64+RC4 HTTP/80 C2 routine
- Threat-infra intel on the tool-delivery / C2 IP ranges (37.120.222.168, 5.255.97.172, 198.144.189.74, 162.55.137.20) — passive DNS, hosting-provider and reuse tracking
- Known-good hash allowlist for legitimate signed ProcDump / Plink / PuTTY / GOST releases (to separate the tool from its abuse)

## Query starting point

Platform: `EDR / hunting-YARA (retro-hunt over sample store + detonation queue)` — trait-stacked Sponsor-family rule; a single trait is thin, the stack is the finding

```yara
rule BallisticBobcat_Sponsor_family_hunt
{
    meta:
        author = "threat-hunter (MENA Detection Library)"
        purpose = "HUNTING ONLY — retro-hunt Sponsor family + tool bundle; not a production detection control"
        actor = "Ballistic Bobcat / Sponsor (overlaps APT35/Charming Kitten)"
        reference = "https://www.welivesecurity.com/en/eset-research/sponsor-batch-filed-whiskers-ballistic-bobcats-scan-strike-backdoor/"
    strings:
        $svc1 = "SystemNetwork" ascii wide
        $svc2 = "Update" ascii wide
        $cfg1 = "config.txt" ascii wide
        $cfg2 = "node.txt"   ascii wide
        $cfg3 = "error.txt"  ascii wide
        $inst = "install"    ascii wide
        $bat1 = "Uninstall.bat" ascii wide
        $api1 = "URLDownloadToFileW" ascii wide
        // C2 / delivery infra (pivot strings, weak alone)
        $ip1 = "37.120.222.168" ascii wide
        $ip2 = "5.255.97.172"   ascii wide
        $ip3 = "198.144.189.74" ascii wide
    condition:
        uint16(0) == 0x5A4D and                       // PE
        (1 of ($svc*)) and (2 of ($cfg*)) and          // service-name + config-triad stack
        ($inst and ($bat1 or $api1) or (any of ($ip*))) // install chain OR infra pivot
}
```

Pair the retro-hunt with an infra pivot (Splunk/SIEM): `index=proxy OR index=netflow dest_ip IN (37.120.222.168,5.255.97.172,198.144.189.74,162.55.137.20) | stats count dc(src_ip) values(dest_port) by dest_ip` to catch any of our hosts already reaching the delivery/C2 infrastructure.

## Triage guidance

- **Likely malicious:** a fresh sample matching the trait stack (service-name + config-triad + install/downloader or infra pivot) that is *not* a known Sponsor hash — likely a new build (v-next / Alumina variant); any PE embedding the delivery/C2 IPs; the actor's tool bundle appearing together (Host2IP + SQLExtractor + RevSocks-as-CSRSS.EXE is a very specific co-occurrence). An internal host beaconing to the delivery/C2 ranges is not a sample-tracking finding at all — it is a live intrusion, jump to escalation.
- **Likely benign / expected:** the individual dual-use tools are legitimate — signed Sysinternals ProcDump, official PuTTY/Plink, upstream GOST/Chisel releases are used by real admins and pentesters; allowlist their known-good hashes and signatures. The string `Update` alone is in countless benign binaries — that is why the rule *requires* the config-triad stack, not any single string. A VirusTotal hit on a public red-team tool is not attribution to this actor.
- **Pivot next:** a new-build match feeds two directions — (1) extract its embedded C2/config and hand the *durable* host-observable (SystemNetwork/Update service pointing at unsigned binary + config-triad on disk) to detection-engineering to strengthen the existing T1543.003 rule; (2) sweep our estate with the extracted network indicators. If the infra-pivot query shows any internal host contacting the delivery/C2 ranges, treat as active compromise and escalate to incident-response-coordinator.

## References

- https://www.welivesecurity.com/en/eset-research/sponsor-batch-filed-whiskers-ballistic-bobcats-scan-strike-backdoor/
- https://github.com/eset/malware-ioc
- https://attack.mitre.org/techniques/T1587/001/
- https://attack.mitre.org/techniques/T1588/002/
